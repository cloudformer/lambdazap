"""The Lambda: sign-in, scanners (start with a lease, extend, stop), the allowlist, the task queue, logs, report links."""
import json

import pytest

import datetime

from conftest import SCANNER_ID, STARTED, FakeCodeBuild, FakeLogs, FakeS3, basic
from lambdazap.server import lambda_function as lf


@pytest.fixture(autouse=True)
def aws(monkeypatch):
    fakes = FakeCodeBuild(), FakeLogs(), FakeS3()
    monkeypatch.setattr(lf, "codebuild", fakes[0])
    monkeypatch.setattr(lf, "logs", fakes[1])
    monkeypatch.setattr(lf, "s3", fakes[2])
    lf._CACHE.clear()
    return fakes


def call(method, path, body=None, auth=True, query=None):
    event = {"requestContext": {"http": {"method": method}}, "rawPath": path,
             "headers": {"authorization": basic()} if auth else {}, "queryStringParameters": query}
    if body is not None:
        event["body"] = json.dumps(body)
    r = lf.lambda_handler(event, None)
    if r["headers"]["content-type"] != "application/json":
        return r["statusCode"], r
    data = json.loads(r["body"])
    data.pop("ms", None)   # the server's timing
    return r["statusCode"], data


def start(compute_type="BUILD_GENERAL1_SMALL", minutes=240):
    return call("POST", "/api/scanners", {"compute_type": compute_type, "minutes": minutes})


def add(targets, mode="baseline"):
    return call("POST", "/api/tasks", {"targets": targets, "mode": mode})


def queued(aws):
    return [json.loads(v) for k, v in sorted(aws[2].objects.items()) if k.startswith("tasks/")]


def test_page_is_public_and_carries_the_version():
    status, r = call("GET", "/", auth=False)
    assert status == 200 and lf.VERSION in r["body"] and "script-src 'sha256-" in r["headers"]["content-security-policy"]


def test_api_needs_sign_in():
    assert call("GET", "/api/scanners", auth=False)[0] == 401


def test_config():
    status, r = call("GET", "/api/config")
    assert status == 200 and r["allowed_targets"][0] == "example.com" and set(r["modes"]) == {"baseline", "full", "api"}
    assert r["durations"] == [60, 120, 240, 480] and r["default_minutes"] == 240 and r["max_scanners"] == 2
    assert r["default_instance"] == "BUILD_GENERAL1_SMALL" and "BUILD_GENERAL1_LARGE" in r["instances"]


def test_start_with_instance_and_lease(aws):
    status, r = start("BUILD_GENERAL1_MEDIUM", 60)
    assert status == 201 and r["id"] == SCANNER_ID and r["status"] == "IN_PROGRESS" and r["compute_type"] == "BUILD_GENERAL1_MEDIUM"
    assert aws[0].started[0]["compute_type"] == "BUILD_GENERAL1_MEDIUM"
    lease = json.loads(aws[2].objects[f"leases/{SCANNER_ID}.json"])
    assert lease["until"] == r["until"] and lease["by"] == "admin"
    status, r = call("GET", "/api/scanners")
    assert r["scanners"][0]["until"] == lease["until"]


@pytest.mark.parametrize("body", [{"compute_type": "BUILD_GENERAL1_2XLARGE"}, {"minutes": 90}])
def test_bad_start_is_rejected(body, aws):
    assert call("POST", "/api/scanners", body)[0] == 400 and not aws[0].started


def test_at_most_max_scanners(aws):
    assert start()[0] == 201 and start()[0] == 201
    status, r = start()
    assert status == 409 and "max_scanners" in r["error"] and len(aws[0].builds) == 2


def test_extend_moves_the_lease_up_to_the_limit(aws):
    start(minutes=60)
    before = json.loads(aws[2].objects[f"leases/{SCANNER_ID}.json"])["until"]
    status, r = call("POST", f"/api/scanners/{SCANNER_ID}/extend")
    assert status == 200 and r["until"] > before
    for _ in range(10):
        status, r = call("POST", f"/api/scanners/{SCANNER_ID}/extend")
    assert status == 400 and "max_session_minutes" in r["error"]
    limit = (STARTED + datetime.timedelta(minutes=480)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert json.loads(aws[2].objects[f"leases/{SCANNER_ID}.json"])["until"] == limit   # start + max_session_minutes


def test_extend_off_scanner_is_rejected():
    start()
    call("POST", f"/api/scanners/{SCANNER_ID}/stop")
    assert call("POST", f"/api/scanners/{SCANNER_ID}/extend")[0] == 400


def test_stop_and_list():
    start()
    status, r = call("POST", f"/api/scanners/{SCANNER_ID}/stop")
    assert status == 200 and r["status"] == "STOPPED"
    status, r = call("GET", "/api/scanners")
    assert [s["id"] for s in r["scanners"]] == [SCANNER_ID] and "until" not in r["scanners"][0]


def test_scanner_log_is_read_forward(aws):
    start()
    aws[1].streams[SCANNER_ID] = ["provisioning", "::ready"]
    status, r = call("GET", f"/api/scanners/{SCANNER_ID}/log")
    assert status == 200 and r["log"] == ["provisioning", "::ready"] and r["token"] == "f/2"
    aws[1].streams[SCANNER_ID] += ["::shutdown idle"]
    status, r = call("GET", f"/api/scanners/{SCANNER_ID}/log", query={"token": "f/2"})
    assert r["log"] == ["::shutdown idle"] and r["token"] == "f/3"


def test_scanner_log_not_there_yet_is_empty():
    start()
    status, r = call("GET", f"/api/scanners/{SCANNER_ID}/log")
    assert status == 200 and r["log"] == [] and r["token"] is None


@pytest.mark.parametrize("url", ["https://example.com/", "http://example.com:8080/login", "https://a.b.example.net",
                                 "https://app.example.org:8443/api"])
def test_allowed_targets_are_added(url, aws):
    status, r = add([url])
    assert status == 201 and r["targets"] == [url] and r["mode"] == "baseline" and r["by"] == "admin" and r["claim"] is None
    assert [t["id"] for t in queued(aws)] == [r["id"]]


@pytest.mark.parametrize("url", ["https://evil.com/", "https://example.com.evil.com/", "https://example.net/",
                                 "https://app.example.org/", "https://app.example.org:9443/"])
def test_other_hosts_are_forbidden(url, aws):
    status, r = add([url])
    assert status == 403 and "allowlist" in r["error"] and not queued(aws)


@pytest.mark.parametrize("url", ["https://evil.com/", "http://anything.internal:9000/x", "https://example.net/"])
def test_wildcard_allows_any_host(url, aws, monkeypatch):
    monkeypatch.setattr(lf, "ALLOWED_TARGETS", ["*"])
    status, r = add([url])
    assert status == 201 and r["targets"] == [url]


def test_one_bad_target_adds_nothing(aws):
    assert add(["https://example.com/", "https://evil.com/"])[0] == 403 and not queued(aws)


@pytest.mark.parametrize("targets", [[], ["example.com"], ["ftp://example.com/"], ["https://user:pw@example.com/"],
                                     "https://example.com/", [f"https://example.com/{i}" for i in range(21)]])
def test_bad_targets_are_rejected(targets, aws):
    assert add(targets)[0] == 400 and not queued(aws)


def test_bad_mode_is_rejected():
    assert add(["https://example.com/"], mode="attack")[0] == 400


def test_tasks_sort_in_the_order_added_and_list_newest_first(aws):
    ids = [add([f"https://example.com/{i}"])[1]["id"] for i in range(3)]
    assert ids == sorted(ids)
    status, r = call("GET", "/api/tasks")
    assert [t["id"] for t in r["tasks"]] == ids[::-1] and all(t["claim"] is None for t in r["tasks"])


def test_task_with_claim_log_and_reports(aws):
    start()
    t = add(["https://example.com/"])[1]
    aws[2].objects[f"claims/{t['id']}.json"] = json.dumps({"scanner": SCANNER_ID, "started": "2026-11-21T10:01:00Z"}).encode()
    aws[1].streams[SCANNER_ID] = ["::ready", f"::task {t['id']} start", f"::site {t['id']} https://example.com/ start",
                                  f"::out {t['id']} PASS: 10", "other scanner noise"]
    status, r = call("GET", f"/api/tasks/{t['id']}")
    assert status == 200 and r["claim"]["scanner"] == SCANNER_ID
    assert [e["line"] for e in r["log"]] == aws[1].streams[SCANNER_ID][1:4] and r["log"][-1]["t"] == 3
    aws[1].streams[SCANNER_ID] += [f"::task {t['id']} end pass"]
    aws[2].objects[f"reports/{t['id']}/example.com/report.html"] = b"<html>"
    status, r = call("GET", f"/api/tasks/{t['id']}", query={"since": "4"})
    assert [e["line"] for e in r["log"]] == [f"::task {t['id']} end pass"]
    assert r["reports"] == {"example.com": {"report.html": f"https://signed/reports/{t['id']}/example.com/report.html?expires=3600"}}
    status, r = call("GET", "/api/tasks")
    assert r["tasks"][0]["claim"]["scanner"] == SCANNER_ID


def test_task_not_taken_has_no_log():
    t = add(["https://example.com/"])[1]
    status, r = call("GET", f"/api/tasks/{t['id']}")
    assert status == 200 and r["claim"] is None and r["log"] == [] and r["reports"] == {}


def test_cancel_only_before_a_scanner_takes_it(aws):
    t = add(["https://example.com/"])[1]
    status, r = call("POST", f"/api/tasks/{t['id']}/cancel")
    assert status == 200 and r["claim"]["cancelled"] is True
    assert call("GET", "/api/tasks")[1]["tasks"][0]["claim"]["cancelled"] is True
    status, r = call("POST", f"/api/tasks/{t['id']}/cancel")
    assert status == 409


def test_ids_are_checked():
    assert call("GET", "/api/scanners/not-a-uuid/log")[0] == 400
    assert call("GET", "/api/tasks/..%2Fother")[0] in (400, 404)
    assert call("GET", f"/api/scanners/{SCANNER_ID}/log")[0] == 404
    assert call("GET", "/api/tasks/0000000000000000000-abcd")[0] == 404

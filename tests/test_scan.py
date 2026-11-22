"""The scanner in the image: takes queued tasks in order with S3 claims, markers, results, reports, secrets masked,
idle shutdown, the lease."""
import json
import os
import subprocess

import pytest

import scan
from conftest import FakeS3


class FakeSSM:
    def __init__(self, values):
        self.values = values

    def get_parameters(self, Names, WithDecryption):
        return {"Parameters": [{"Name": n, "Value": self.values[n]} for n in Names if n in self.values]}


class FakeZap:
    """Stands in for ZAP's scripts: prints a line (with the secret, to test masking), writes the reports, exits."""

    def __init__(self, exits):
        self.exits, self.calls = exits, []

    def __call__(self, cmd, cwd, env, **kw):
        self.calls.append(cmd)
        code = self.exits[len(self.calls) - 1]
        if code is None:
            raise FileNotFoundError(cmd[0])
        for name in (a for a in cmd if a.startswith("report.")):
            with open(os.path.join(cwd, name), "w") as fh:
                fh.write(name)

        class P:
            stdout = iter([f"scanning {cmd[2]} with {env.get('TOKEN', '-')}\n"])

            def wait(self):
                return code
        return P()


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    """run(tasks, exits, ...) -> (exit code, printed lines, S3 objects, ZAP calls). The tasks are queued before the
    scanner starts; with no more tasks it shuts down at once (idle limit 0)."""
    s3 = FakeS3()
    ssm = FakeSSM({"/test/secrets/TOKEN": "s3cr3t-value"})
    monkeypatch.setattr(scan, "WORK", str(tmp_path))
    monkeypatch.setattr(scan.boto3, "client", lambda name: {"s3": s3, "ssm": ssm}[name])
    monkeypatch.setattr(scan.threading, "Thread", lambda **kw: type("T", (), {"start": lambda self: None})())
    monkeypatch.setenv("BUCKET", "test-reports")
    monkeypatch.setenv("CODEBUILD_BUILD_ID", "test-scanner:abc")
    monkeypatch.setenv("IDLE_SHUTDOWN_MINUTES", "0")
    monkeypatch.delenv("SECRETS", raising=False)

    def go(tasks, exits, secrets=None, value=None, claimed=()):
        if secrets:
            monkeypatch.setenv("SECRETS", secrets)
            monkeypatch.setenv("SECRETS_PATH", "/test/secrets/")
        if value:
            ssm.values["/test/secrets/TOKEN"] = value
        for i, (targets, mode) in enumerate(tasks):
            s3.objects[f"tasks/{i:019d}-0000.json"] = json.dumps({"id": f"{i:019d}-0000", "targets": targets, "mode": mode}).encode()
        for i in claimed:
            s3.objects[f"claims/{i:019d}-0000.json"] = json.dumps({"scanner": "other"}).encode()
        zap = FakeZap(exits)
        monkeypatch.setattr(subprocess, "Popen", zap)
        try:
            scan.Scanner().main()
            code = 0
        except SystemExit as e:
            code = e.code
        return code, capsys.readouterr().out.splitlines(), s3.objects, zap.calls
    return go


def test_tasks_in_order_claimed_marked_and_reported(run):
    code, out, objects, calls = run([(["https://example.com/", "https://app.example.org:8443/"], "baseline"),
                                     (["https://b.example.net/"], "full")], [0, 2, 1])
    t0, t1 = f"{0:019d}-0000", f"{1:019d}-0000"
    assert code == 0 and out[0] == "::ready" and out[-1] == "::shutdown idle"
    assert [l for l in out if l.startswith("::task")] == [f"::task {t0} start", f"::task {t0} end warn", f"::task {t1} start", f"::task {t1} end fail"]
    assert f"::site {t0} https://app.example.org:8443/ end warn" in out and f"::out {t0} scanning https://example.com/ with -" in out
    assert {k for k in objects if k.startswith("reports/")} == {f"reports/{t}/{h}/report.{x}" for t, h in [
        (t0, "example.com"), (t0, "app.example.org_8443"), (t1, "b.example.net")] for x in ("html", "json", "md")}
    claim = json.loads(objects[f"claims/{t0}.json"])
    assert claim["scanner"] == "abc" and claim["result"] == "warn" and claim["sites"]["https://example.com/"] == "pass" and claim["ended"]
    assert [c[0] for c in calls] == ["zap-baseline.py", "zap-baseline.py", "zap-full-scan.py"]


def test_a_task_another_scanner_claimed_is_skipped(run):
    code, out, objects, calls = run([(["https://example.com/"], "baseline"), (["https://b.example.net/"], "baseline")], [0], claimed=[0])
    assert len(calls) == 1 and calls[0][2] == "https://b.example.net/"
    assert json.loads(objects[f"claims/{0:019d}-0000.json"]) == {"scanner": "other"}


def test_error_does_not_stop_the_next(run):
    code, out, objects, calls = run([(["https://example.com/", "https://b.example.net/"], "baseline")], [None, 0])
    t = f"{0:019d}-0000"
    assert code == 0 and len(calls) == 2
    assert f"::site {t} https://example.com/ end error" in out and f"::site {t} https://b.example.net/ end pass" in out
    assert f"::task {t} end error" in out


def test_secrets_reach_zap_and_are_masked(run):
    code, out, objects, calls = run([(["https://example.com/"], "baseline")], [0], secrets="TOKEN")
    assert any("scanning https://example.com/ with ***" in l for l in out) and not any("s3cr3t" in l for l in out)


def test_unset_secret_shuts_down_before_any_scan(run):
    code, out, objects, calls = run([(["https://example.com/"], "baseline")], [0], secrets="TOKEN", value="CHANGE-ME")
    assert code == 1 and out[-1] == "::shutdown secrets" and "/test/secrets/TOKEN" in out[0] and calls == []


def test_api_mode_reads_an_openapi_definition(run):
    code, out, objects, calls = run([(["https://example.com/openapi.json"], "api")], [0])
    assert calls[0][:5] == ["zap-api-scan.py", "-t", "https://example.com/openapi.json", "-f", "openapi"]


def test_idle_with_no_task_shuts_down(run):
    code, out, objects, calls = run([], [])
    assert code == 0 and out == ["::ready", "::shutdown idle"] and calls == []


def test_lease(monkeypatch):
    s3 = FakeS3()
    monkeypatch.setattr(scan.boto3, "client", lambda name: s3)
    monkeypatch.setenv("BUCKET", "b")
    monkeypatch.setenv("CODEBUILD_BUILD_ID", "p:abc")
    s = scan.Scanner()
    assert s.expired() is False   # no lease yet
    s3.objects["leases/abc.json"] = json.dumps({"until": "2000-01-01T00:00:00Z"}).encode()
    assert s.expired() is True
    s3.objects["leases/abc.json"] = json.dumps({"until": "2999-01-01T00:00:00Z"}).encode()
    assert s.expired() is False

#!/usr/bin/env python3
"""lambdazap-scan: one scanner (one CodeBuild build). Takes tasks from the queue all scanners share, one at a time,
until its lease runs out or it has been idle for IDLE_SHUTDOWN_MINUTES; Shut down in the web UI stops the build.

    s3://<BUCKET>/tasks/<task id>.json      the queue, written by the Lambda (targets already on the allowlist)
    s3://<BUCKET>/claims/<task id>.json     a scanner takes a task by creating its claim with If-None-Match: *;
                                            S3 lets one writer win, so no task runs twice. Rewritten at the end
                                            with the result. A cancelled task's claim is the Lambda's.
    s3://<BUCKET>/leases/<scanner id>.json  {"until": ISO time}: when this scanner shuts down; the web UI's +1h
                                            moves it. Checked every LEASE_CHECK_SECONDS, a running scan included.
    s3://<BUCKET>/reports/<task id>/<host>/report.{html,json,md}

Environment (the CodeBuild project sets them; CodeBuild adds CODEBUILD_BUILD_ID = <project>:<scanner id>):
    BUCKET, IDLE_SHUTDOWN_MINUTES
    SECRETS, SECRETS_PATH   comma-separated names: each SSM SecureString <SECRETS_PATH><name> becomes the environment
                            variable <name> of every ZAP run (e.g. ZAP_AUTH_HEADER_VALUE, which ZAP's scans send as
                            a header); their values are replaced by *** in everything printed

Log lines (read by the web UI; a task's lines carry its id, so the UI can follow one task among several scanners):
    ::ready   ::task <id> start|end <result>   ::site <id> <url> start|end <result>   ::out <id> <text>
    ::shutdown <idle|lease|secrets>
result = pass | warn | fail (ZAP's exit 0 / 2 / 1: no alerts / warnings / failures) or error (ZAP could not scan);
a task's result is the worst of its targets'.
"""
import datetime
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse

import boto3
from botocore.exceptions import ClientError

SCRIPTS = {"baseline": "zap-baseline.py", "full": "zap-full-scan.py", "api": "zap-api-scan.py"}
REPORTS = {"report.html": "-r", "report.json": "-J", "report.md": "-w"}   # file -> ZAP's flag for it
TYPES = {"report.html": "text/html; charset=utf-8", "report.json": "application/json", "report.md": "text/markdown; charset=utf-8"}
RESULTS = {0: "pass", 2: "warn", 1: "fail"}  # ZAP's exit status -> result; anything else = error
ORDER = ["pass", "warn", "fail", "error"]    # worst last
WORK = "/zap/wrk"                            # where ZAP's scripts write their reports
PLACEHOLDER = "CHANGE-ME"                    # what Terraform creates a secret with
POLL_SECONDS = 2
LEASE_CHECK_SECONDS = 10


def say(text):
    print(text, flush=True)


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class Scanner:
    def __init__(self):
        self.bucket = os.environ["BUCKET"]
        self.id = os.environ["CODEBUILD_BUILD_ID"].split(":", 1)[1]
        self.idle_limit = int(os.environ.get("IDLE_SHUTDOWN_MINUTES", "15")) * 60
        self.s3 = boto3.client("s3")
        self.values = {}      # secrets: name -> value
        self.taken = set()    # task keys known to be claimed (by anyone)
        self.proc = None      # the running ZAP, killed when the lease runs out

    # ---- secrets ----
    def load_secrets(self):
        """False (after saying why) when a configured secret still holds the placeholder."""
        names = [n for n in os.environ.get("SECRETS", "").split(",") if n]
        if not names:
            return True
        path = os.environ["SECRETS_PATH"]
        r = boto3.client("ssm").get_parameters(Names=[path + n for n in names], WithDecryption=True)
        self.values = {p["Name"][len(path):]: p["Value"] for p in r["Parameters"]}
        unset = [n for n in names if self.values.get(n, PLACEHOLDER) == PLACEHOLDER]
        if unset:
            say("secrets not set yet: " + ", ".join(path + n for n in unset)
                + " — aws ssm put-parameter --name <name> --type SecureString --overwrite --value '...'")
            return False
        return True

    def masked(self, text):
        for v in self.values.values():
            text = text.replace(v, "***")
        return text

    # ---- the lease ----
    def expired(self):
        """True once the lease's time has passed; no lease yet (the Lambda writes it right after Start) = not expired."""
        try:
            lease = json.loads(self.s3.get_object(Bucket=self.bucket, Key=f"leases/{self.id}.json")["Body"].read())
        except self.s3.exceptions.NoSuchKey:
            return False
        return iso(now()) >= lease["until"]

    def watch_lease(self):
        """In the background: when the lease runs out, stop whatever runs and end the build."""
        while True:
            time.sleep(LEASE_CHECK_SECONDS)
            try:
                if self.expired():
                    say("::shutdown lease")
                    if self.proc:
                        self.proc.kill()
                    os._exit(0)
            except Exception as e:  # noqa: BLE001 - a failed check is retried, never fatal
                say(f"lease check failed: {type(e).__name__}: {e}")

    # ---- the queue ----
    def keys(self, prefix):
        out = []
        for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix):
            out += [o["Key"] for o in page.get("Contents", [])]
        return out

    def claim(self, key):
        """Take the task at key; False when another scanner (or a cancel) has it."""
        task_id = key[len("tasks/"):-len(".json")]
        body = json.dumps({"scanner": self.id, "started": iso(now())}).encode()
        try:
            self.s3.put_object(Bucket=self.bucket, Key=f"claims/{task_id}.json", Body=body,
                               ContentType="application/json", IfNoneMatch="*")
            return True
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "PreconditionFailed":
                self.taken.add(key)
                return False
            if code == "ConditionalRequestConflict":   # a write of the same claim in flight: look again next round
                return False
            raise

    def next_task(self):
        """The oldest task nobody has taken, now claimed by this scanner; None when there is none."""
        for key in sorted(k for k in self.keys("tasks/") if k not in self.taken):
            if self.claim(key):
                self.taken.add(key)
                return json.loads(self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read())
        return None

    # ---- one task ----
    def zap(self, task_id, url, mode):
        """Run ZAP on one target, its output streamed (masked, tagged with the task id); returns the result."""
        for name in REPORTS:
            try:
                os.remove(os.path.join(WORK, name))
            except FileNotFoundError:
                pass
        cmd = [SCRIPTS[mode], "-t", url]
        if mode == "api":
            cmd += ["-f", "openapi"]
        for name, flag in REPORTS.items():
            cmd += [flag, name]
        self.proc = subprocess.Popen(cmd, cwd=WORK, env=dict(os.environ, **self.values), stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, errors="replace")
        for line in self.proc.stdout:
            say(f"::out {task_id} {self.masked(line.rstrip(chr(10)))}")
        code, self.proc = self.proc.wait(), None
        return RESULTS.get(code, "error")

    def upload(self, task_id, url):
        host = urllib.parse.urlsplit(url).netloc.lower().replace(":", "_")
        for name in REPORTS:
            path = os.path.join(WORK, name)
            if os.path.isfile(path):
                self.s3.upload_file(path, self.bucket, f"reports/{task_id}/{host}/{name}", ExtraArgs={"ContentType": TYPES[name]})

    def run(self, task):
        """A task's targets one after another; one target's failure never stops the next."""
        tid, started = task["id"], iso(now())
        say(f"::task {tid} start")
        sites = {}
        for url in task["targets"]:
            say(f"::site {tid} {url} start")
            try:
                result = self.zap(tid, url, task["mode"]) if task["mode"] in SCRIPTS else "error"
                self.upload(tid, url)
            except Exception as e:  # noqa: BLE001 - reported in the log, the next target runs
                say(f"::out {tid} {self.masked(f'{type(e).__name__}: {e}')}")
                result = "error"
            sites[url] = result
            say(f"::site {tid} {url} end {result}")
        result = max(sites.values(), key=ORDER.index)
        say(f"::task {tid} end {result}")
        claim = {"scanner": self.id, "started": started, "ended": iso(now()), "result": result, "sites": sites}
        self.s3.put_object(Bucket=self.bucket, Key=f"claims/{tid}.json", Body=json.dumps(claim).encode(),
                           ContentType="application/json")

    def main(self):
        if not self.load_secrets():
            say("::shutdown secrets")
            sys.exit(1)
        self.taken = {"tasks/" + k[len("claims/"):] for k in self.keys("claims/")}   # taken or cancelled before
        threading.Thread(target=self.watch_lease, daemon=True).start()
        say("::ready")
        idle_since = time.monotonic()
        while True:
            task = self.next_task()
            if task:
                self.run(task)
                idle_since = time.monotonic()
            elif time.monotonic() - idle_since >= self.idle_limit:
                say("::shutdown idle")
                return
            else:
                time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    Scanner().main()

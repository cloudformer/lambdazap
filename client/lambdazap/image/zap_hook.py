"""A ZAP packaged-scan hook: add the task's auth headers to every request, so the scan runs signed in.

The scanner (lambdazap-scan) puts the task's headers — a JSON list of {"name","value"} — in the ZAP_EXTRA_HEADERS
environment variable and runs the packaged scan with `--hook`. zap_started adds one Replacer rule per header, so
every request ZAP makes carries it (session cookie, Authorization: Bearer, Cloudflare Access, a raw header, …).
Passing the values this way (not on the command line) keeps spaces and `;` intact and off the process list.
"""
import json
import os


def zap_started(zap, target):
    raw = os.environ.get("ZAP_EXTRA_HEADERS", "")
    if not raw:
        return
    for i, h in enumerate(json.loads(raw)):
        zap.replacer.add_rule(description="auth%d" % i, enabled=True, matchtype="REQ_HEADER",
                              matchregex=False, matchstring=h["name"], replacement=h["value"])

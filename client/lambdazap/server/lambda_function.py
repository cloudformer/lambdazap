"""lambdazap server: one Lambda behind a Function URL — switches scanners on and off, takes tasks, serves the web UI.

A scanner is one CodeBuild build on a fresh instance (the ZAP image, built from lambdazap/image), started from the
page with an instance size and a lease (how long it stays on, extendable from the page up to MAX_SESSION_MINUTES,
the build timeout), and stopped from the page — or by itself when its lease runs out, or after
IDLE_SHUTDOWN_MINUTES without a task. Several may be on (MAX_SCANNERS); each runs one task at a time. Tasks are one queue,
s3://<bucket>/tasks/<task id>.json, apart from the scanners: a free scanner takes the oldest task nobody has taken
by writing its claim, claims/<task id>.json, with If-None-Match: * (S3 lets only one writer win). This Lambda never
scans: it checks targets against the allowlist, starts / stops builds, writes tasks, reads status and logs, and
signs report links.

The first half (JSON, request body, sign-in, routing, error mapping, timing) is the series' shared shell; the
routes are in the second half.

Sign-in: two methods, each on or off; a request passes when any method that is on accepts it.
    HTTP_AUTH=1        HTTP Basic (USER_NAME / PASSWORD). Identity = the user name.
    CLOUDFLARE_AUTH=1  Cloudflare Access: the Cf-Access-Jwt-Assertion header Cloudflare adds in front of this URL,
                       an RS256 JWT checked against the team's public keys (CLOUDFLARE_TEAM), its aud
                       (CLOUDFLARE_AUD), issuer and expiry. Identity = the email in it.
    The page is public while HTTP_AUTH is on (it asks for the user and password); with Cloudflare alone it needs
    the JWT too. Both off, or a method on without its settings: every request is refused (503).

    GET  /                              web UI (index.html), public
    GET  /api/ping                      {"ok": true}
    GET  /api/me                        {"identity", "auth_method": http | cloudflare}: who is signed in
    GET  /api/config                    allowlist, modes, instance sizes, max_scanners, idle shutdown, version
    GET  /api/scanners                  the latest scanners, newest first
    POST /api/scanners                  {"compute_type", "minutes"}: switch one more scanner on for that long (409 at
                                        max_scanners)
    GET  /api/scanners/<id>/log[?token] a scanner's log from token on (the next token comes back)
    POST /api/scanners/<id>/extend      its lease + 1 hour, never past MAX_SESSION_MINUTES after its start
    POST /api/scanners/<id>/stop        switch it off
    GET  /api/tasks                     the latest tasks, newest first, each with its claim
    POST /api/tasks                     {"targets": [url, ...], "mode": baseline | full | api}: add a task; every
                                        target must be on the allowlist (ALLOWED_TARGETS), else nothing is added
    GET  /api/tasks/<id>[?since=ms]     one task: claim, reports (presigned links, 1 hour), its log lines from since
    POST /api/tasks/<id>/cancel         cancel a task no scanner has taken (409 once one has)

Log lines of a task carry its id, so the page can follow one task while several scanners write:
    ::ready                               the scanner takes tasks
    ::task <task id> start | end <result>
    ::site <task id> <url> start | end <result>     result = pass | warn | fail | error
    ::out <task id> <text>                ZAP's output
    ::shutdown <reason>                   idle, or a secret not set

Layout: leases/<scanner id>.json ({"until": ISO time}); tasks/<task id>.json (the id sorts in the order added); claims/<task id>.json ({"scanner", "started"}, then
"ended", "result", "sites" when done; or {"cancelled": true}); reports/<task id>/<host, ':' as '_'>/report.{html,json,md}.
The bucket's lifecycle rule expires them all.
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import time
import urllib.parse
import urllib.request

import boto3
from botocore.exceptions import ClientError

HTTP_AUTH = os.environ.get("HTTP_AUTH", "1") == "1"
USER = os.environ.get("USER_NAME", "")
PASSWORD = os.environ.get("PASSWORD", "")
CLOUDFLARE_AUTH = os.environ.get("CLOUDFLARE_AUTH", "0") == "1"
CLOUDFLARE_TEAM = os.environ.get("CLOUDFLARE_TEAM", "")   # <team>.cloudflareaccess.com
CLOUDFLARE_AUD = os.environ.get("CLOUDFLARE_AUD", "")     # the Access application's AUD tag
ALLOWED_TARGETS = json.loads(os.environ.get("ALLOWED_TARGETS", "[]"))   # example.com, app.example.com:8443, *.example.com
BUCKET = os.environ.get("BUCKET", "")
PROJECT = os.environ.get("PROJECT", "")       # the CodeBuild project: the scanner
LOG_GROUP = os.environ.get("LOG_GROUP", "")   # its CloudWatch log group
TASKS = "tasks/"                              # fixed layout: s3://<bucket>/tasks/<task id>.json
CLAIMS = "claims/"                            #               s3://<bucket>/claims/<task id>.json
LEASES = "leases/"                            #               s3://<bucket>/leases/<scanner id>.json
REPORTS = "reports/"                          #               s3://<bucket>/reports/<task id>/<host>/...
IDLE_SHUTDOWN_MINUTES = int(os.environ.get("IDLE_SHUTDOWN_MINUTES", "15"))   # shown on the page; the image acts on it
MAX_SESSION_MINUTES = int(os.environ.get("MAX_SESSION_MINUTES", "480"))      # a scanner's hard limit: the build timeout
DURATIONS = [m for m in (60, 120, 240, 480) if m <= MAX_SESSION_MINUTES] or [MAX_SESSION_MINUTES]   # Start offers these
DEFAULT_MINUTES = 240 if 240 in DURATIONS else DURATIONS[-1]
EXTEND_MINUTES = 60                           # what +1h adds
MAX_SCANNERS = int(os.environ.get("MAX_SCANNERS", "2"))                      # scanners on at the same time
DEFAULT_INSTANCE = os.environ.get("COMPUTE_TYPE", "BUILD_GENERAL1_SMALL")    # the size the page offers first
INSTANCES = {                                 # CodeBuild compute type -> what the page shows
    "BUILD_GENERAL1_SMALL": "small · 2 vCPU · 3 GB",
    "BUILD_GENERAL1_MEDIUM": "medium · 4 vCPU · 7 GB",
    "BUILD_GENERAL1_LARGE": "large · 8 vCPU · 15 GB",
}
RUNNING = "IN_PROGRESS"                       # CodeBuild's status of a build that is on
MODES = {                                     # mode -> what ZAP runs (the scan image maps it to the script)
    "baseline": "passive, nothing is attacked",
    "full": "active, attacks every page found",
    "api": "active, from an OpenAPI definition URL",
}
MAX_TARGETS = 20                              # per task
LIST_LIMIT = 20                               # scanners shown in the list
TASK_LIMIT = 50                               # tasks shown in the list
LINK_SECONDS = 3600                           # a presigned report link stays valid this long

HERE = os.path.dirname(__file__)
with open(os.path.join(HERE, "..", "__init__.py"), encoding="utf-8") as f:
    VERSION = re.search(r'__version__ = "([^"]+)"', f.read()).group(1)   # this package's release, shown on the page
with open(os.path.join(HERE, "index.html"), encoding="utf-8") as f:
    INDEX_HTML = f.read().replace("__VERSION__", VERSION)

# Content-Security-Policy: only this page's own inline scripts (by hash) run; no request leaves for another origin.
# A line in the scanner's log cannot become script.
_HASHES = " ".join("'sha256-%s'" % base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()
                   for s in re.findall(r"<script>(.*?)</script>", INDEX_HTML, re.S))
CSP = (f"default-src 'none'; script-src {_HASHES}; style-src 'unsafe-inline'; connect-src 'self'; "
       "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
PAGE_HEADERS = {"content-security-policy": CSP, "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer", "x-frame-options": "DENY"}

SCANNER_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")   # the uuid of a build id
TASK_ID = re.compile(r"[0-9]{19}-[0-9a-f]{4}")                                           # <time in ns>-<random>

codebuild = boto3.client("codebuild")
logs = boto3.client("logs")
s3 = boto3.client("s3")


class BadRequest(Exception):
    pass


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


class Busy(Exception):
    """max_scanners are on, or a task to cancel was taken already."""


# ---------------- shared: the same in every project ----------------

def _json(status, data):
    return {"statusCode": status, "headers": {"content-type": "application/json"},
            "body": json.dumps(data, ensure_ascii=False, default=str)}


def _body(event):
    """The JSON request body; 400 when it is not a JSON object."""
    raw = event.get("body") or "{}"
    try:
        if event.get("isBase64Encoded"):
            raw = base64.b64decode(raw)
        data = json.loads(raw)
    except ValueError:
        raise BadRequest("request body is not valid JSON") from None
    if not isinstance(data, dict):
        raise BadRequest("request body must be a JSON object")
    return data


def _auth_problem():
    """Why this deployment's sign-in settings cannot work, or None. Checked on every request: fail closed."""
    if not HTTP_AUTH and not CLOUDFLARE_AUTH:
        return "no sign-in method is on: turn on http_auth or cloudflare_auth"
    if HTTP_AUTH and not (USER and PASSWORD):
        return "http_auth is on without a username and password"
    if CLOUDFLARE_AUTH and not (re.fullmatch(r"[a-z0-9-]+", CLOUDFLARE_TEAM) and CLOUDFLARE_AUD):
        return "cloudflare_auth is on without a team and aud"
    return None


def _authed(event):
    """HTTP Basic, constant-time compare."""
    auth = (event.get("headers") or {}).get("authorization", "")
    if not auth.lower().startswith("basic "):
        return False
    try:
        user, _, password = base64.b64decode(auth.split(None, 1)[1]).decode().partition(":")
    except Exception:
        return False
    return hmac.compare_digest(user.encode(), USER.encode()) & hmac.compare_digest(password.encode(), PASSWORD.encode())


def _b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_CF_KEYS = {}        # kid -> (n, e): the team's RSA public keys, kept while the Lambda is warm
_CF_FETCHED = [0.0]  # when they were last fetched


def _cf_keys(kid):
    """The team's key for kid; an unknown kid fetches the keys again (Cloudflare rotates them), at most once a minute."""
    if kid not in _CF_KEYS and time.time() - _CF_FETCHED[0] > 60:
        _CF_FETCHED[0] = time.time()
        url = f"https://{CLOUDFLARE_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs"
        with urllib.request.urlopen(url, timeout=5) as r:
            keys = json.load(r)["keys"]
        _CF_KEYS.clear()
        _CF_KEYS.update({k["kid"]: (int.from_bytes(_b64url(k["n"]), "big"), int.from_bytes(_b64url(k["e"]), "big"))
                         for k in keys if k.get("kty") == "RSA"})
    return _CF_KEYS.get(kid)


_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _rs256_ok(key, signed, sig):
    """RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 8.2.2): the signature, raised to e mod n, must be exactly the
    padded digest of what was signed."""
    n, e = key
    k = (n.bit_length() + 7) // 8
    s = int.from_bytes(sig, "big")
    if len(sig) != k or s >= n:
        return False
    t = _SHA256_DIGEST_INFO + hashlib.sha256(signed).digest()
    return hmac.compare_digest(pow(s, e, n).to_bytes(k, "big"), b"\x00\x01" + b"\xff" * (k - 3 - len(t)) + b"\x00" + t)


def _cloudflare(event):
    """The email in a valid Cloudflare Access JWT, or None."""
    token = (event.get("headers") or {}).get("cf-access-jwt-assertion", "")
    try:
        head64, claims64, sig64 = token.split(".")
        head, claims = json.loads(_b64url(head64)), json.loads(_b64url(claims64))
        key = head.get("alg") == "RS256" and _cf_keys(head.get("kid"))
        if not key or not _rs256_ok(key, f"{head64}.{claims64}".encode(), _b64url(sig64)):
            return None
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as e:
        if isinstance(e, OSError):
            print(json.dumps({"event": "cloudflare_keys_unavailable", "error": str(e)}))
        return None
    aud = claims.get("aud")
    now = time.time()
    if (CLOUDFLARE_AUD not in (aud if isinstance(aud, list) else [aud])
            or claims.get("iss") != f"https://{CLOUDFLARE_TEAM}.cloudflareaccess.com"
            or not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= now
            or (isinstance(claims.get("nbf"), (int, float)) and claims["nbf"] > now + 60)):
        return None
    return str(claims.get("email") or claims.get("common_name") or claims.get("sub") or "cloudflare")


def _identity(event):
    """(who, method) for the first method that is on and accepts the request, or None. Handlers read
    event["identity"] (the Basic user, or the Cloudflare email) and event["auth_method"]."""
    if CLOUDFLARE_AUTH:
        who = _cloudflare(event)
        if who:
            return who, "cloudflare"
    if HTTP_AUTH and _authed(event):
        return USER, "http"
    return None



ERRORS = [(BadRequest, 400), (Forbidden, 403), (NotFound, 404), (Busy, 409)]   # exception class -> HTTP status


def lambda_handler(event, context):
    http = (event.get("requestContext") or {}).get("http") or {}
    method, path = http.get("method", "GET"), urllib.parse.unquote(event.get("rawPath", "/"))
    problem = _auth_problem()
    if problem:   # fail closed: a sign-in that cannot work must not leave the page or the API open
        return _json(503, {"error": problem})
    signed = _identity(event)
    if signed is None and not HTTP_AUTH:   # Cloudflare alone: nothing is served without its JWT, the page included
        return _json(401, {"error": "sign in through Cloudflare Access", "http_auth": False})
    if method == "GET" and path in ("/", "/index.html"):
        return {"statusCode": 200, "body": INDEX_HTML,
                "headers": dict(PAGE_HEADERS, **{"content-type": "text/html; charset=utf-8", "cache-control": "no-cache"})}
    if signed is None:
        return _json(401, {"error": "bad credentials", "http_auth": True})
    event["identity"], event["auth_method"] = signed
    t0 = time.perf_counter()
    status, data = 404, {"error": f"no route: {method} {path}"}
    try:
        for route_method, pattern, handler in ROUTES:
            match = pattern.fullmatch(path)
            if match and route_method == method:
                out = handler(event, **match.groupdict())
                status, data = out if isinstance(out, tuple) else (200, out)
                break
    except Exception as e:  # noqa: BLE001 - every error becomes a JSON response
        status = next((s for cls, s in ERRORS if isinstance(e, cls)), 500)
        data = {"error": str(e) if status < 500 else f"{type(e).__name__}: {e}"}
    data.setdefault("ms", round((time.perf_counter() - t0) * 1000, 1))
    return _json(status, data)


# ---------------- the project's API: scanners = builds of the CodeBuild project; tasks = one queue in S3 ----------------

def _target(url):
    """The target URL, normalized, when it is on the allowlist; BadRequest / Forbidden otherwise.

    An allowlist entry is a host (any port), host:port (that port only) or *.domain (its subdomains, any port)."""
    if not isinstance(url, str):
        raise BadRequest(f"a target is a URL string, got {url!r}")
    parts = urllib.parse.urlsplit(url.strip())
    try:
        host, port = (parts.hostname or "").lower(), parts.port
    except ValueError:
        raise BadRequest(f"target {url!r}: bad port") from None
    if parts.scheme not in ("http", "https") or not host or parts.username or parts.password:
        raise BadRequest(f"target {url!r}: http(s)://host[:port][/path], no user or password in it")
    for entry in ALLOWED_TARGETS:
        name, _, want = entry.partition(":")
        if want and str(port or (443 if parts.scheme == "https" else 80)) != want:
            continue
        if host == name or (name.startswith("*.") and host.endswith(name[1:])):
            return parts.geturl()
    raise Forbidden(f"{host} is not on the allowlist (allowed_targets: {', '.join(ALLOWED_TARGETS)})")


def _scanner_id(scanner_id):
    if not SCANNER_ID.fullmatch(scanner_id):
        raise BadRequest(f"scanner id: a uuid, got {scanner_id!r}")
    return f"{PROJECT}:{scanner_id}"


def _task_key(task_id):
    if not TASK_ID.fullmatch(task_id):
        raise BadRequest(f"task id: <19 digits>-<4 hex>, got {task_id!r}")
    return f"{TASKS}{task_id}.json"


def _summary(build):
    env = {v["name"]: v["value"] for v in build.get("environment", {}).get("environmentVariables", [])}
    return {"id": build["id"].split(":", 1)[1], "status": build["buildStatus"], "phase": build.get("currentPhase"),
            "started": build.get("startTime"), "ended": build.get("endTime"), "by": env.get("STARTED_BY"),
            "compute_type": build.get("environment", {}).get("computeType")}


def _builds(ids):
    return codebuild.batch_get_builds(ids=ids)["builds"] if ids else []


def _recent():
    ids = codebuild.list_builds_for_project(projectName=PROJECT, sortOrder="DESCENDING").get("ids", [])[:LIST_LIMIT]
    return _builds(ids)


def _objects(prefix):
    """{key: etag} under prefix."""
    out = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix=prefix):
        out.update({o["Key"]: o["ETag"] for o in page.get("Contents", [])})
    return out


_CACHE = {}   # (key, etag) -> parsed JSON, kept while the Lambda is warm: a task never changes, a claim only on its end


def _read(key, etag):
    if (key, etag) not in _CACHE:
        if len(_CACHE) > 2000:
            _CACHE.clear()
        _CACHE[(key, etag)] = json.loads(s3.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    return _CACHE[(key, etag)]


def _utc(t):
    """A build time (datetime from boto3, ISO text from a fake) as an aware datetime."""
    if isinstance(t, str):
        t = datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))
    return t.astimezone(datetime.timezone.utc)


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _lease(scanner_id):
    try:
        return json.loads(s3.get_object(Bucket=BUCKET, Key=f"{LEASES}{scanner_id}.json")["Body"].read())
    except s3.exceptions.NoSuchKey:
        return None


def _write_lease(scanner_id, until, who):
    s3.put_object(Bucket=BUCKET, Key=f"{LEASES}{scanner_id}.json", ContentType="application/json",
                  Body=json.dumps({"until": _iso(until), "by": who}).encode())


def _claim(task_id):
    try:
        return json.loads(s3.get_object(Bucket=BUCKET, Key=f"{CLAIMS}{task_id}.json")["Body"].read())
    except s3.exceptions.NoSuchKey:
        return None


def ping(event):
    return {"ok": True}


def me(event):
    return {"identity": event["identity"], "auth_method": event["auth_method"]}


def config(event):
    return {"allowed_targets": ALLOWED_TARGETS, "modes": MODES, "instances": INSTANCES, "default_instance": DEFAULT_INSTANCE,
            "durations": DURATIONS, "default_minutes": DEFAULT_MINUTES, "extend_minutes": EXTEND_MINUTES,
            "max_session_minutes": MAX_SESSION_MINUTES, "max_scanners": MAX_SCANNERS,
            "idle_shutdown_minutes": IDLE_SHUTDOWN_MINUTES, "version": VERSION}


def list_scanners(event):
    """The latest scanners; one that is on carries its lease's end (until)."""
    out = []
    for b in _recent():
        s = _summary(b)
        if s["status"] == RUNNING:
            s["until"] = (_lease(s["id"]) or {}).get("until")
        out.append(s)
    return {"scanners": out}


def start_scanner(event):
    body = _body(event)
    compute_type, minutes = body.get("compute_type", DEFAULT_INSTANCE), body.get("minutes", DEFAULT_MINUTES)
    if compute_type not in INSTANCES:
        raise BadRequest(f"compute_type: one of {', '.join(INSTANCES)}, got {compute_type!r}")
    if minutes not in DURATIONS:
        raise BadRequest(f"minutes: one of {', '.join(map(str, DURATIONS))}, got {minutes!r}")
    on = sum(b["buildStatus"] == RUNNING for b in _recent())
    if on >= MAX_SCANNERS:
        raise Busy(f"{on} scanner(s) on already, the most max_scanners allows: shut one down first")
    try:
        build = codebuild.start_build(projectName=PROJECT, computeTypeOverride=compute_type, environmentVariablesOverride=[
            {"name": "STARTED_BY", "value": event["identity"], "type": "PLAINTEXT"}])["build"]
    except codebuild.exceptions.AccountLimitExceededException:
        raise Busy("max_scanners scanners are on already: shut one down first") from None
    out = _summary(build)
    until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=minutes)
    _write_lease(out["id"], until, event["identity"])
    out["until"] = _iso(until)
    print(json.dumps({"event": "scanner_started", "id": build["id"], "compute_type": compute_type, "until": out["until"],
                      "by": event["identity"]}))
    return 201, out


def extend_scanner(event, scanner_id):
    """+EXTEND_MINUTES from the lease's end (or from now, if that is later), never past the build timeout."""
    builds = _builds([_scanner_id(scanner_id)])
    if not builds or builds[0]["buildStatus"] != RUNNING:
        raise BadRequest(f"scanner {scanner_id} is off")
    now = datetime.datetime.now(datetime.timezone.utc)
    lease = _lease(scanner_id)
    until = max(now, _utc(lease["until"]) if lease else now) + datetime.timedelta(minutes=EXTEND_MINUTES)
    limit = _utc(builds[0]["startTime"]) + datetime.timedelta(minutes=MAX_SESSION_MINUTES)
    if until > limit:
        if (lease and _utc(lease["until"]) >= limit - datetime.timedelta(minutes=1)):
            raise BadRequest(f"scanner {scanner_id} is at its limit, {MAX_SESSION_MINUTES} min after its start (max_session_minutes)")
        until = limit
    _write_lease(scanner_id, until, event["identity"])
    print(json.dumps({"event": "scanner_extended", "id": builds[0]["id"], "until": _iso(until), "by": event["identity"]}))
    return dict(_summary(builds[0]), until=_iso(until))


def stop_scanner(event, scanner_id):
    build = codebuild.stop_build(id=_scanner_id(scanner_id))["build"]
    print(json.dumps({"event": "scanner_stopped", "id": build["id"], "by": event["identity"]}))
    return _summary(build)


def scanner_log(event, scanner_id):
    """A scanner's whole log (its own lines and its tasks'), from token on; the next token comes back."""
    builds = _builds([_scanner_id(scanner_id)])
    if not builds:
        raise NotFound(f"no scanner {scanner_id}")
    out = _summary(builds[0])
    token = (event.get("queryStringParameters") or {}).get("token") or None
    stream = builds[0].get("logs", {}).get("streamName")
    lines = []
    if stream:   # none until the instance has started
        args = {"logGroupName": LOG_GROUP, "logStreamName": stream, "startFromHead": True}
        if token:
            args["nextToken"] = token
        try:
            r = logs.get_log_events(**args)
            lines, token = [e["message"].rstrip("\n") for e in r["events"]], r["nextForwardToken"]
        except logs.exceptions.ResourceNotFoundException:
            pass   # the stream appears a moment after the build reports it
    out.update(log=lines, token=token)
    return out


def list_tasks(event):
    """The latest tasks, newest first, each with its claim (which scanner, the result) once a scanner took it."""
    tasks, claims = _objects(TASKS), _objects(CLAIMS)
    out = []
    for key in sorted(tasks, reverse=True)[:TASK_LIMIT]:
        task = dict(_read(key, tasks[key]))
        claim_key = CLAIMS + key[len(TASKS):]
        task["claim"] = _read(claim_key, claims[claim_key]) if claim_key in claims else None
        out.append(task)
    return {"tasks": out}


def add_task(event):
    """Queue a task: every target must be on the allowlist, else nothing is queued. Any scanner that is on takes it."""
    body = _body(event)
    targets, mode = body.get("targets"), body.get("mode")
    if mode not in MODES:
        raise BadRequest(f"mode: one of {', '.join(MODES)}, got {mode!r}")
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        raise BadRequest(f"targets: a list of 1 to {MAX_TARGETS} URLs")
    urls = [_target(t) for t in targets]   # all checked before anything is queued
    task = {"id": f"{time.time_ns():019d}-{os.urandom(2).hex()}",   # sorts in the order added
            "targets": urls, "mode": mode, "by": event["identity"], "added": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    s3.put_object(Bucket=BUCKET, Key=_task_key(task["id"]), Body=json.dumps(task).encode(), ContentType="application/json")
    print(json.dumps({"event": "task_added", **task}))
    return 201, dict(task, claim=None)


def get_task(event, task_id):
    """One task: its claim, its reports (presigned links, 1 hour) and its log lines from since (ms) on, read from the
    scanner that took it: every line of a task carries the task id."""
    key = _task_key(task_id)
    try:
        task = json.loads(s3.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    except s3.exceptions.NoSuchKey:
        raise NotFound(f"no task {task_id}") from None
    task["claim"] = claim = _claim(task_id)
    reports = {}
    prefix = f"{REPORTS}{task_id}/"
    for k in _objects(prefix):
        host, name = k[len(prefix):].split("/", 1)
        reports.setdefault(host, {})[name] = s3.generate_presigned_url(
            "get_object", Params={"Bucket": BUCKET, "Key": k}, ExpiresIn=LINK_SECONDS)
    events = []
    if claim and claim.get("scanner"):
        builds = _builds([f"{PROJECT}:{claim['scanner']}"])
        stream = builds and builds[0].get("logs", {}).get("streamName")
        if stream:
            since = int((event.get("queryStringParameters") or {}).get("since") or 0)
            args = {"logGroupName": LOG_GROUP, "logStreamNames": [stream], "filterPattern": f'"{task_id}"', "startTime": since}
            while len(events) < 10000:
                r = logs.filter_log_events(**args)
                events += [{"id": e["eventId"], "t": e["timestamp"], "line": e["message"].rstrip("\n")} for e in r["events"]]
                if not r.get("nextToken"):
                    break
                args["nextToken"] = r["nextToken"]
    task.update(reports=reports, log=events)
    return task


def cancel_task(event, task_id):
    """Cancel a task no scanner has taken: the cancel takes its claim, so no scanner ever will."""
    _task_key(task_id)
    claim = {"cancelled": True, "by": event["identity"], "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        s3.put_object(Bucket=BUCKET, Key=f"{CLAIMS}{task_id}.json", Body=json.dumps(claim).encode(),
                      ContentType="application/json", IfNoneMatch="*")
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "PreconditionFailed":
            raise Busy(f"task {task_id} was taken by a scanner already: shut that scanner down to stop it") from None
        raise
    return {"id": task_id, "claim": claim}


SCANNER = r"/api/scanners/(?P<scanner_id>[^/]+)"
TASK = r"/api/tasks/(?P<task_id>[^/]+)"
ROUTES = [
    ("GET",  re.compile(r"/api/ping"), ping),
    ("GET",  re.compile(r"/api/me"), me),
    ("GET",  re.compile(r"/api/config"), config),
    ("GET",  re.compile(r"/api/scanners"), list_scanners),
    ("POST", re.compile(r"/api/scanners"), start_scanner),
    ("GET",  re.compile(SCANNER + "/log"), scanner_log),
    ("POST", re.compile(SCANNER + "/extend"), extend_scanner),
    ("POST", re.compile(SCANNER + "/stop"), stop_scanner),
    ("GET",  re.compile(r"/api/tasks"), list_tasks),
    ("POST", re.compile(r"/api/tasks"), add_task),
    ("GET",  re.compile(TASK), get_task),
    ("POST", re.compile(TASK + "/cancel"), cancel_task),
]

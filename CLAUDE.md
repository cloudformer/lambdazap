# lambdazap — working notes for Claude

**This project is an IdleFree app** (cloudformer.github.io): OWASP ZAP scans from a web UI, ≈ $0 when idle. Not an
AWS service behind its client: no driver, no compatibility tests.

- `client/` is the pip package `lambdazap`: `lambdazap/server/` = the Lambda (web UI `index.html` + API,
  handler `lambdazap.server.lambda_function.lambda_handler`); `lambdazap/image/` = the scan image's build context
  (official ZAP, pinned in the Dockerfile, + `scan.py` installed as `lambdazap-scan`, the scanner loop).
- Deployment: the Registry module cloudformer/infra/aws//modules/lambdazap installs a released lambdazap from PyPI,
  builds the image with Docker, pushes it to ECR, and creates the CodeBuild project (component codebuild_project).
  Its README is the usage docs; this README only links to it.
- A scanner is one CodeBuild build, started from the page with a size and a lease (`leases/<scanner id>.json`,
  +1h from the page, at most `max_session_minutes` = the build timeout), stopped from the page, by the lease or by
  idle shutdown. Tasks are one queue, `tasks/<task id>.json` (ids sort in the order added); a scanner takes a task by
  creating `claims/<task id>.json` with `If-None-Match: *` and rewrites it with the result. The Lambda never scans;
  the image never decides what may be scanned: the allowlist is checked by the Lambda, the only writer of `tasks/`.
- Log contract between the image and the page (a task's lines carry its id): `::ready`,
  `::task <id> start|end <result>`, `::site <id> <url> start|end <result>`, `::out <id> <text>`,
  `::shutdown <idle|lease|secrets>`. Report layout: `reports/<task id>/<host, ':' as '_'>/report.{html,json,md}`.
  Change both sides together.
- The page uses the idlefree console shell (the CSS block shared with s3rds and the other consoles), unchanged.
- Tests: `python3 -m pytest tests -q`, fakes for CodeBuild, CloudWatch Logs, S3 and SSM; no AWS, no Docker.
- Frank runs every command (git, tags, PyPI, terraform). Versions are Frank's call. English in code and docs.
- Sister app: lambdakali: the same scanners, queue, leases and page; its task is tool + target + arguments instead of targets + mode.

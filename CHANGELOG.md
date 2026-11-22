# Changelog

## 0.1.5 — 2026-11-22

- Console: a browser-style tab strip of the running scanners above the console; the shown one is highlighted, and clicking a task marks the scanner it runs on. Idle shutdown default lowered to 10 minutes.

## 0.1.3

- Docs: a console and an architecture diagram under `docs/` (SVG), embedded in the README and the PyPI page; one
  source, referenced everywhere. No code change.

## 0.1.2

- `allowed_targets = ["*"]` turns the allowlist off (any host; sign-in is then the only gate) — handy for testing.

## 0.1.1

- Sign-in and the console CSS now come from the shared packages `idlefree-auth` and `idlefree-ui` instead of a
  copy carried here; behavior and the page are unchanged.

## 0.1.0

- First release: a web UI on a Lambda Function URL starts and shuts down scanners (CodeBuild instances with the
  official ZAP image; a size and a duration each, +1h from the page, up to `max_scanners` at once) and adds OWASP
  ZAP tasks (baseline, full, api) of hosts on the allowlist to one queue. A free scanner takes the next task (an S3
  claim), with a live log per task and the reports (HTML, JSON, Markdown) in S3 behind presigned links. A scanner
  shuts down by itself when its time is up or after `idle_shutdown_minutes` without a task.
- Secrets from SSM Parameter Store reach ZAP as environment variables (e.g. `ZAP_AUTH_HEADER_VALUE`), masked in
  the log.

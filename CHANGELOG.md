# Changelog

## 0.1.0

- First release: a web UI on a Lambda Function URL starts and shuts down scanners (CodeBuild instances with the
  official ZAP image; a size and a duration each, +1h from the page, up to `max_scanners` at once) and adds OWASP
  ZAP tasks (baseline, full, api) of hosts on the allowlist to one queue. A free scanner takes the next task (an S3
  claim), with a live log per task and the reports (HTML, JSON, Markdown) in S3 behind presigned links. A scanner
  shuts down by itself when its time is up or after `idle_shutdown_minutes` without a task.
- Secrets from SSM Parameter Store reach ZAP as environment variables (e.g. `ZAP_AUTH_HEADER_VALUE`), masked in
  the log.

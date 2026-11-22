"""lambdazap — OWASP ZAP scans of your own sites from a web UI on a Lambda Function URL; scanners are CodeBuild
instances started and shut down from the page, taking tasks from one queue. ≈ $0 while none is on.

lambdazap.server is the Lambda (the web UI and its API); lambdazap/image is the scan image's build context (official
ZAP + the scanner loop). The Terraform module cloudformer/infra/aws//modules/lambdazap deploys both from this package.
"""

__version__ = "0.1.2"

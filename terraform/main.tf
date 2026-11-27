# The deployment calls the lambdazap module, which deploys a released lambdazap from PyPI and builds the ZAP image
# with Docker on this machine (Docker must be running). Before a Registry release, use the local source line.
module "lambdazap" {
  # source  = "cloudformer/infra/aws//modules/lambdazap"  # stable: a released version
  # version = "0.2.0"
  source = "../../terraform-aws-infra/modules/lambdazap" # local: this repo's working-tree module

  project_name          = var.project_name
  allowed_targets       = var.allowed_targets
  http_auth             = var.http_auth
  cloudflare_auth       = var.cloudflare_auth
  function_url_auth     = var.function_url_auth
  secrets               = var.secrets
  compute_type          = var.compute_type
  max_scanners          = var.max_scanners
  idle_shutdown_minutes = var.idle_shutdown_minutes
  max_session_minutes   = var.max_session_minutes
  report_retention_days = var.report_retention_days
  log_retention_days    = var.log_retention_days
  architecture          = var.architecture
  force_destroy         = var.force_destroy
  lambdazap_version     = var.lambdazap_version # set in the tfvars file; bump it per release, module untouched
}

output "console_url" {
  value = module.lambdazap.console_url
}

output "bucket" {
  value = module.lambdazap.bucket
}

output "secret_parameters" {
  value = module.lambdazap.secret_parameters
}

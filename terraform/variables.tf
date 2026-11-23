# ---- deploy credentials ----
variable "region" {
  type    = string
  default = "us-east-2"
}

variable "aws_profile" {
  description = "Local AWS CLI profile; \"\" = default credential chain"
  type        = string
  default     = ""
}

variable "assume_role_arn" {
  description = "Deploy role to assume; \"\" = none. Pick this OR aws_profile."
  type        = string
  default     = ""

  validation {
    condition     = !(var.assume_role_arn != "" && var.aws_profile != "")
    error_message = "Set either aws_profile or assume_role_arn, not both."
  }
}

variable "env" {
  type    = string
  default = "dev"
}

variable "project_name" {
  type    = string
  default = "lambdazap"
}

variable "allowed_targets" {
  description = "Hosts a scan may target: example.com, app.example.com:8443, *.example.com. Only yours or ones you may test."
  type        = list(string)
}

variable "http_auth" {
  type = object({
    enabled  = bool
    username = optional(string, "")
    password = optional(string, "")
  })
  default   = { enabled = false }
  sensitive = true
}

variable "cloudflare_auth" {
  type = object({
    enabled = bool
    team    = optional(string, "")
    aud     = optional(string, "")
  })
  default = { enabled = false }
}

variable "function_url_auth" {
  type    = string
  default = "NONE"
}

variable "secrets" {
  description = "Secret names a scan may use (e.g. [\"ZAP_AUTH_HEADER_VALUE\"]); set each value with aws ssm put-parameter after apply"
  type        = list(string)
  default     = []
}

variable "compute_type" {
  type    = string
  default = "BUILD_GENERAL1_SMALL"
}

variable "max_scanners" {
  type    = number
  default = 2
}

variable "idle_shutdown_minutes" {
  type    = number
  default = 15
}

variable "max_session_minutes" {
  type    = number
  default = 480
}

variable "report_retention_days" {
  type    = number
  default = 30
}

variable "log_retention_days" {
  type    = number
  default = 14
}

variable "architecture" {
  type    = string
  default = "arm64"
}

variable "force_destroy" {
  type    = bool
  default = true
}

variable "lambdazap_version" {
  description = "The lambdazap release to deploy from PyPI. Bump this per release during testing; the module is not touched."
  type        = string
  default     = "0.1.9"
}

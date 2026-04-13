variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "paapv2_suite" {
  description = "PAAP v2 cryptographic suite"
  type        = string
  default     = "PAAPv2-OPRF-MODP14-SHA256"
  
  validation {
    condition     = contains(["PAAPv2-OPRF-MODP14-SHA256", "PAAPv2-RFC9474-RSA-2048-PSS-SHA256"], var.paapv2_suite)
    error_message = "PAAPV2_SUITE must be either PAAPv2-OPRF-MODP14-SHA256 or PAAPv2-RFC9474-RSA-2048-PSS-SHA256"
  }
}

terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.13.0"
    }
  }
}

# Supply CLOUDFLARE_API_TOKEN through the protected execution environment.
# S3 credentials are configured separately and never enter this state.
provider "cloudflare" {}

variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[a-f0-9]{32}$", var.account_id))
    error_message = "A Cloudflare account ID is required."
  }
}

variable "bucket_name" {
  type    = string
  default = "heterocloud-flash-disaster-backups"
}

resource "cloudflare_r2_bucket" "backups" {
  account_id    = var.account_id
  name          = var.bucket_name
  location      = "apac"
  jurisdiction  = "default"
  storage_class = "Standard"
  lifecycle {
    prevent_destroy = true
  }
}

resource "cloudflare_r2_managed_domain" "private" {
  account_id  = var.account_id
  bucket_name = cloudflare_r2_bucket.backups.name
  enabled     = false
}

output "s3_endpoint" {
  value = "https://${var.account_id}.r2.cloudflarestorage.com"
}

output "bucket_name" {
  value = cloudflare_r2_bucket.backups.name
}

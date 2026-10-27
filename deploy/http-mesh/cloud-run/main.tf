terraform {
  required_version = ">= 1.9.0"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 7.0" }
  }
}
variable "project" { type = string }
variable "region" { type = string }
variable "name" {
  type    = string
  default = "heteronet-http-member"
}
variable "image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[a-f0-9]{64}$", var.image))
    error_message = "Use the tested image's immutable digest."
  }
}
variable "endpoint" {
  type = string
  validation {
    condition     = can(regex("^https://[^/?#]+$", var.endpoint))
    error_message = "Enrollment requires an HTTPS control-plane origin."
  }
}
variable "join_token_secret" {
  description = "Existing Secret Manager secret ID; never supply its value to Terraform."
  type        = string
}
variable "min_instances" {
  type    = number
  default = 1
}
variable "max_instances" {
  type    = number
  default = 10
}
resource "google_service_account" "member" {
  project      = var.project
  account_id   = var.name
  display_name = "HeteroNetwork HTTP VPN member"
}
resource "google_secret_manager_secret_iam_member" "join" {
  project   = var.project
  secret_id = var.join_token_secret
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.member.email}"
}
resource "google_cloud_run_v2_service" "member" {
  project             = var.project
  location            = var.region
  name                = var.name
  deletion_protection = true
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  template {
    service_account = google_service_account.member.email
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }
    containers {
      image = var.image
      ports { container_port = 8080 }
      env {
        name  = "HETERONETWORK_ENDPOINT"
        value = var.endpoint
      }
      env {
        name = "HETERONETWORK_JOIN_TOKEN"
        value_source {
          secret_key_ref {
            secret  = var.join_token_secret
            version = "latest"
          }
        }
      }
      resources {
        limits = { cpu = "1", memory = "512Mi" }
        # Polling and VPN traffic continue when no public HTTP request is active.
        cpu_idle = false
      }
      startup_probe {
        initial_delay_seconds = 1
        period_seconds        = 5
        failure_threshold     = 24
        http_get { path = "/readyz" }
      }
      liveness_probe {
        period_seconds    = 10
        failure_threshold = 6
        http_get { path = "/healthz" }
      }
    }
  }
  depends_on = [google_secret_manager_secret_iam_member.join]
}
output "service" { value = google_cloud_run_v2_service.member.uri }

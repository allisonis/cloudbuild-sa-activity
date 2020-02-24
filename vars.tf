variable "project_id" {
  description = "ProjectID target project, required"
  default     = ""
}

variable "entrypoint" {
  description = "Cloud Function entrypoint/handler name"
  default     = "cloudbuild_service_account_alerts"
}

variable "region" {
  description = "Region"
  default     = "us-central1"
}

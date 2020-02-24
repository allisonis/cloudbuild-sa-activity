# Log Sink that captures potentially malicious CloudBuild requests
# Filters search for all requests where the principal is the Google Managed
# <project_id>cloudbuild.gserviceaccount.com service account, and not 
# from a google IP range. 
resource "google_logging_project_sink" "cloudbuild_logsink" {
  name    = "cloudbuild_logsink"
  project = var.project_id

  # Can export to pubsub, cloud storage, or bigquery
  destination = "pubsub.googleapis.com/projects/my-project/topics/cloudbuild-malicious-activity"

  # Filter for all instances of a reuqest to cloudbuild with the default service accounts from a
  # non GCP IP range. 
  #    protoPayload.authenticationInfo.principalEmail:(cloudbuild.gserviceaccount.com)
  #    protoPayload.requestMetadata.callerIp: "." AND NOT (35)
  filter = <<EOF
    protoPayload.authenticationInfo.principalEmail:(cloudbuild.gserviceaccount.com)
    protoPayload.requestMetadata.callerIp: "." AND NOT (35)"
  EOF

  # Use a unique writer (creates a unique service account used for writing)
  unique_writer_identity = true
}

# Stroage bucket to store Cloud Function source
resource "google_storage_bucket" "cloudbuild_alert_source" {
  name               = "cloudbuild-alert-source"
  project            = var.project_id
  force_destroy      = true
  bucket_policy_only = true
}

# Archive source file 
data "archive_file" "cloudbuild_alert_source_archive" {
  type        = "zip"
  source_file = "${path.module}/cloudbuild-source/main.py"
  output_path = "${path.module}/cloudbuild-source/main.zip"
}

resource "google_storage_bucket_object" "cloudbuild_alert_source_archive" {
  name   = "main.zip"
  bucket = google_storage_bucket.cloudbuild_alert_source.name
  source = data.archive_file.cloudbuild_alert_source_archive.output_path
}

# --------- PubSub --------- #
# PubSub subscription for the cloudbuild-alert-topic
# Recieves Stackdriver logs of "malicious" activity

resource "google_pubsub_topic" "cloudbuild_alert_topic" {
  name = "cloudbuild-malicious-activity"
}

resource "google_pubsub_subscription" "cloudbuild_alert_subscription" {
  name                  = "cloudbuild-alert-subscription"
  project               = var.project_id
  topic                 = google_pubsub_topic.cloudbuild_alert_topic.name
  ack_deadline_seconds  = 600
  retain_acked_messages = true
}


# Service account to attach to the Cloud Function
resource "google_service_account" "cloudbuild_alerts_sa" {
  project    = var.project_id
  account_id = "cloudbuild-alerts-sa"
}

# Cloudbuild alerts service account project IAM memeber, non authoritative.
# roles/pubsub.subscriber
resource "google_project_iam_member" "cloudbuild_alerts_sa_iam" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.cloudbuild_alerts_sa.email}"
}

# Cloud Build alerts Cloud Function
resource "google_cloudfunctions_function" "cloudbuild_alert" {
  name                  = "cloudbuild-alert"
  project               = var.project_id
  region                = var.region
  description           = "Parses CloudBuild log exports and generates alerts."
  runtime               = "python37"
  available_memory_mb   = 128
  source_archive_bucket = google_storage_bucket.cloudbuild_alert_source.name
  source_archive_object = google_storage_bucket_object.cloudbuild_alert_source_archive.name
  entry_point           = var.entrypoint
  service_account_email = google_service_account.cloudbuild_alerts_sa.email
  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.cloudbuild_alert_topic.name
  }
}

# # IAM entry for a single user to invoke the function
# resource "google_cloudfunctions_function_iam_member" "cloud_build_invoker" {
#   project        = google_cloudfunctions_function.cl.project
#   region         = google_cloudfunctions_function.function.region
#   cloud_function = google_cloudfunctions_function.function.name

#   role   = "roles/cloudfunctions.invoker"
#   member = "user:myFunctionInvoker@example.com"
# }
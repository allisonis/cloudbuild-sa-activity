# cloudbuild-metadata-activity
Alert Pipeline to catch malicious Cloudbuild executions
This is a demo application to capture potentially malicious CloudBuild Requests.  

Advanced Stack Driver query that can be used to alert on requests originating from the Google managed CloudBuild service account. This query looks for all logs where the principal contains the partial service account email `cloudbuild.gserviceaccount.com` that does not originate from GCP IP. This query can only capture malicious requests made from an extneral network. 

```bash
protoPayload.authenticationInfo.principalEmail:(cloudbuild.gserviceaccount.com)
protoPayload.requestMetadata.callerIp: "." AND NOT (35)
```

## Terraform configurations

In this repostory we configure the following resources to capture StackDriver events. 
* Log Sinks
* Pub/Sub events
* Cloud Functions

Requried varaibles: 
```hcl
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
```
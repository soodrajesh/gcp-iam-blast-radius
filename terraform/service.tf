resource "google_service_account" "app" {
  account_id   = "ib-app"
  display_name = "iam-blast runtime"
}
resource "google_project_iam_member" "app_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.app.email}"
}
resource "google_project_iam_member" "app_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.app.email}"
}
# Read-only IAM inspection for live mode (get/list IAM policies, service accounts, keys). It can
# read every IAM policy in the project but change nothing.
resource "google_project_iam_member" "app_security_reviewer" {
  project = var.project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${google_service_account.app.email}"
}

resource "google_cloud_run_v2_service" "app" {
  count               = var.image != "" ? 1 : 0
  name                = "iam-blast"
  location            = var.region
  deletion_protection = false
  labels              = { env = "demo", owner = "platform" }
  template {
    service_account                  = google_service_account.app.email
    timeout                          = "120s"
    max_instance_request_concurrency = 20
    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }
    containers {
      image = var.image
      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
      startup_probe {
        http_get { path = "/healthz" }
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "IAMBLAST_LLM"
        value = "vertex"
      }
      env {
        name  = "IAMBLAST_MODEL"
        value = var.model
      }
      env {
        name  = "IAMBLAST_ALLOWED_PROVIDERS"
        value = "vertex,none"
      }
      env {
        name  = "IAMBLAST_LIVE_PROJECTS"
        value = var.project_id
      }
      env {
        name  = "IAMBLAST_INTERNAL_DOMAINS"
        value = var.internal_domains
      }
      env {
        name  = "IAMBLAST_DAILY_BUDGET_USD"
        value = tostring(var.daily_budget_usd)
      }
    }
  }
  depends_on = [
    google_project_iam_member.app_vertex,
    google_project_iam_member.app_security_reviewer,
  ]
}

# Private: only the admin may invoke. No allUsers binding.
resource "google_cloud_run_v2_service_iam_member" "admin_invoker" {
  count    = var.image != "" ? 1 : 0
  name     = google_cloud_run_v2_service.app[0].name
  location = var.region
  role     = "roles/run.invoker"
  member   = "user:${var.admin_email}"
}

# Terraform Configuration for Google Cloud KMS HSM
# Provisions Google Cloud KMS infrastructure for Lux KMS

terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required APIs
resource "google_project_service" "cloudkms" {
  service            = "cloudkms.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam" {
  service            = "iam.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "cloudresourcemanager" {
  service            = "cloudresourcemanager.googleapis.com"
  disable_on_destroy = false
}

# Create Key Ring
resource "google_kms_key_ring" "lux_kms" {
  name     = var.key_ring_name
  location = var.key_location

  depends_on = [google_project_service.cloudkms]
}

# Create Primary Crypto Key (HSM-backed)
resource "google_kms_crypto_key" "lux_kms_primary" {
  name            = var.crypto_key_name
  key_ring        = google_kms_key_ring.lux_kms.id
  rotation_period = var.rotation_period

  purpose = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.protection_level
  }

  lifecycle {
    prevent_destroy = true  # Prevent accidental deletion
  }
}

# Create Service Account for Lux KMS
resource "google_service_account" "lux_kms" {
  account_id   = var.service_account_name
  display_name = "Lux KMS Service Account"
  description  = "Service account for Lux KMS HSM operations"

  depends_on = [google_project_service.iam]
}

# Grant Crypto Key Encrypter/Decrypter role
resource "google_kms_crypto_key_iam_member" "lux_kms_encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.lux_kms_primary.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.lux_kms.email}"
}

# Generate Service Account Key
resource "google_service_account_key" "lux_kms" {
  service_account_id = google_service_account.lux_kms.name
}

# Store service account key in local file (for initial setup)
resource "local_sensitive_file" "service_account_key" {
  content  = base64decode(google_service_account_key.lux_kms.private_key)
  filename = "${path.module}/lux-kms-credentials.json"
}

# Optional: Store credentials in Secret Manager (recommended for production)
resource "google_secret_manager_secret" "lux_kms_credentials" {
  count     = var.use_secret_manager ? 1 : 0
  secret_id = "lux-kms-service-account-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.cloudkms]
}

resource "google_secret_manager_secret_version" "lux_kms_credentials" {
  count       = var.use_secret_manager ? 1 : 0
  secret      = google_secret_manager_secret.lux_kms_credentials[0].id
  secret_data = google_service_account_key.lux_kms.private_key
}

# Grant Secret Manager access to Lux KMS service account
resource "google_secret_manager_secret_iam_member" "lux_kms_secret_accessor" {
  count     = var.use_secret_manager ? 1 : 0
  secret_id = google_secret_manager_secret.lux_kms_credentials[0].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.lux_kms.email}"
}

# Optional: Multi-region setup for high availability
resource "google_kms_key_ring" "lux_kms_regional" {
  for_each = toset(var.additional_regions)

  name     = "${var.key_ring_name}-${each.value}"
  location = each.value

  depends_on = [google_project_service.cloudkms]
}

resource "google_kms_crypto_key" "lux_kms_regional" {
  for_each = toset(var.additional_regions)

  name            = var.crypto_key_name
  key_ring        = google_kms_key_ring.lux_kms_regional[each.value].id
  rotation_period = var.rotation_period

  purpose = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.protection_level
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "lux_kms_regional_encrypter_decrypter" {
  for_each = toset(var.additional_regions)

  crypto_key_id = google_kms_crypto_key.lux_kms_regional[each.value].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.lux_kms.email}"
}

# Outputs
output "project_id" {
  description = "GCP Project ID"
  value       = var.project_id
}

output "key_ring_id" {
  description = "Key Ring ID"
  value       = google_kms_key_ring.lux_kms.id
}

output "crypto_key_id" {
  description = "Crypto Key ID"
  value       = google_kms_crypto_key.lux_kms_primary.id
}

output "service_account_email" {
  description = "Service Account Email"
  value       = google_service_account.lux_kms.email
}

output "service_account_key_file" {
  description = "Path to service account key file"
  value       = local_sensitive_file.service_account_key.filename
  sensitive   = true
}

output "environment_variables" {
  description = "Environment variables for Lux KMS"
  value = {
    HSM_ENABLED                      = "true"
    HSM_PROVIDER                     = "google-cloud"
    GOOGLE_CLOUD_PROJECT_ID          = var.project_id
    GOOGLE_CLOUD_LOCATION            = var.key_location
    GOOGLE_CLOUD_KEY_RING            = var.key_ring_name
    GOOGLE_CLOUD_CRYPTO_KEY          = var.crypto_key_name
    GOOGLE_CLOUD_PROTECTION_LEVEL    = var.protection_level
    GOOGLE_CLOUD_AUTO_ROTATE         = var.auto_rotate
    GOOGLE_CLOUD_ROTATION_PERIOD     = var.rotation_period
    GOOGLE_APPLICATION_CREDENTIALS   = local_sensitive_file.service_account_key.filename
  }
  sensitive = true
}

output "regional_key_rings" {
  description = "Regional key ring IDs"
  value = {
    for region in var.additional_regions :
    region => google_kms_key_ring.lux_kms_regional[region].id
  }
}

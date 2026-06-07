# Terraform Variables for Google Cloud KMS HSM

variable "project_id" {
  description = "GCP Project ID"
  type        = string
  default     = "lux-kms-production"
}

variable "region" {
  description = "GCP Region for resources"
  type        = string
  default     = "us-east1"
}

variable "key_location" {
  description = "Location for KMS key ring (global or regional)"
  type        = string
  default     = "global"

  validation {
    condition = contains([
      "global",
      "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4", "us-central1",
      "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6", "europe-north1",
      "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3", "asia-south1", "asia-southeast1",
      "australia-southeast1",
      "southamerica-east1"
    ], var.key_location)
    error_message = "Key location must be a valid GCP region or 'global'."
  }
}

variable "key_ring_name" {
  description = "Name of the KMS key ring"
  type        = string
  default     = "lux-kms-keyring"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]+$", var.key_ring_name))
    error_message = "Key ring name must contain only letters, numbers, hyphens, and underscores."
  }
}

variable "crypto_key_name" {
  description = "Name of the crypto key"
  type        = string
  default     = "lux-kms-key"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]+$", var.crypto_key_name))
    error_message = "Crypto key name must contain only letters, numbers, hyphens, and underscores."
  }
}

variable "protection_level" {
  description = "Protection level for the crypto key (HSM or SOFTWARE)"
  type        = string
  default     = "HSM"

  validation {
    condition     = contains(["HSM", "SOFTWARE"], var.protection_level)
    error_message = "Protection level must be either 'HSM' or 'SOFTWARE'."
  }
}

variable "rotation_period" {
  description = "Key rotation period in seconds (e.g., '7776000s' for 90 days)"
  type        = string
  default     = "7776000s"  # 90 days

  validation {
    condition     = can(regex("^[0-9]+s$", var.rotation_period))
    error_message = "Rotation period must be in seconds format (e.g., '7776000s')."
  }
}

variable "auto_rotate" {
  description = "Enable automatic key rotation"
  type        = bool
  default     = true
}

variable "service_account_name" {
  description = "Name of the service account for Lux KMS"
  type        = string
  default     = "lux-kms-sa"

  validation {
    condition     = can(regex("^[a-z](?:[-a-z0-9]{4,28}[a-z0-9])$", var.service_account_name))
    error_message = "Service account name must be 6-30 characters, start with lowercase letter, and contain only lowercase letters, numbers, and hyphens."
  }
}

variable "use_secret_manager" {
  description = "Store service account credentials in Secret Manager (recommended for production)"
  type        = bool
  default     = false
}

variable "additional_regions" {
  description = "Additional regions for multi-region key replication (for high availability)"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for region in var.additional_regions :
      contains([
        "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4", "us-central1",
        "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6", "europe-north1",
        "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3", "asia-south1", "asia-southeast1",
        "australia-southeast1",
        "southamerica-east1"
      ], region)
    ])
    error_message = "Additional regions must be valid GCP regions."
  }
}

variable "enable_monitoring" {
  description = "Enable Cloud Monitoring for KMS operations"
  type        = bool
  default     = true
}

variable "enable_audit_logs" {
  description = "Enable Cloud Audit Logs for KMS operations"
  type        = bool
  default     = true
}

variable "labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
  default = {
    environment = "production"
    application = "lux-kms"
    managed-by  = "terraform"
  }
}

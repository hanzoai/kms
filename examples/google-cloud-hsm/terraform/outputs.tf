# Terraform Outputs for Google Cloud KMS HSM

output "instructions" {
  description = "Post-deployment instructions"
  value = <<-EOT
    ================================================================================
    Google Cloud KMS HSM Setup Complete!
    ================================================================================

    Resources Created:
    - Project: ${var.project_id}
    - Key Ring: ${google_kms_key_ring.lux_kms.id}
    - Crypto Key: ${google_kms_crypto_key.lux_kms_primary.id}
    - Service Account: ${google_service_account.lux_kms.email}
    - Protection Level: ${var.protection_level}

    Next Steps:

    1. Export environment variables:
       export GOOGLE_CLOUD_PROJECT_ID="${var.project_id}"
       export GOOGLE_CLOUD_LOCATION="${var.key_location}"
       export GOOGLE_CLOUD_KEY_RING="${var.key_ring_name}"
       export GOOGLE_CLOUD_CRYPTO_KEY="${var.crypto_key_name}"
       export GOOGLE_APPLICATION_CREDENTIALS="${path.module}/lux-kms-credentials.json"

    2. Verify setup:
       gcloud kms keys describe ${var.crypto_key_name} \
         --location=${var.key_location} \
         --keyring=${var.key_ring_name}

    3. Test encryption:
       echo "test data" | gcloud kms encrypt \
         --location=${var.key_location} \
         --keyring=${var.key_ring_name} \
         --key=${var.crypto_key_name} \
         --plaintext-file=- \
         --ciphertext-file=-

    4. Deploy Lux KMS:
       - Copy .env.example to .env
       - Add environment variables from step 1
       - Run: docker-compose up -d

    5. Verify Lux KMS health:
       curl http://localhost:8080/health

    Security Reminders:
    - Store credentials securely (use Secret Manager in production)
    - Enable VPC Service Controls for additional security
    - Review IAM permissions regularly
    - Monitor Cloud Audit Logs for suspicious activity
    - Rotate service account keys every 90 days

    Documentation:
    - Setup Guide: /docs/kms-configuration/google-cloud-hsm
    - API Reference: /docs/api/hsm-operations
    - Troubleshooting: /docs/troubleshooting/google-cloud-kms

    ================================================================================
  EOT
}

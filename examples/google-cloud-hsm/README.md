# Google Cloud KMS HSM Integration Examples

This directory contains complete deployment examples for Lux KMS with Google Cloud KMS HSM backend.

## Contents

- **Terraform** - Infrastructure as Code for GCP KMS setup
- **Docker Compose** - Local/development deployment
- **Kubernetes** - Production GKE deployment with Workload Identity
- **Configuration** - Environment templates and examples

## Quick Start

### Prerequisites

1. **Google Cloud SDK**
   ```bash
   # Install gcloud CLI
   curl https://sdk.cloud.google.com | bash
   exec -l $SHELL
   gcloud init
   ```

2. **Terraform** (for infrastructure provisioning)
   ```bash
   # macOS
   brew install terraform

   # Linux
   wget https://releases.hashicorp.com/terraform/1.7.0/terraform_1.7.0_linux_amd64.zip
   unzip terraform_1.7.0_linux_amd64.zip
   sudo mv terraform /usr/local/bin/
   ```

3. **Docker & Docker Compose** (for local deployment)
   ```bash
   # macOS
   brew install --cask docker

   # Linux
   curl -fsSL https://get.docker.com | sh
   sudo usermod -aG docker $USER
   ```

4. **kubectl** (for Kubernetes deployment)
   ```bash
   # macOS
   brew install kubectl

   # Linux
   curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
   sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
   ```

## Deployment Options

### Option 1: Terraform (Recommended for Production)

Automated infrastructure provisioning with Terraform.

#### Step 1: Configure Terraform Variables

```bash
cd terraform

# Create terraform.tfvars
cat > terraform.tfvars <<EOF
project_id          = "your-gcp-project-id"
region              = "us-east1"
key_location        = "global"
key_ring_name       = "lux-kms-keyring"
crypto_key_name     = "lux-kms-key"
protection_level    = "HSM"
rotation_period     = "7776000s"  # 90 days
auto_rotate         = true
service_account_name = "lux-kms-sa"
use_secret_manager  = true  # Recommended for production

# Optional: Multi-region setup
additional_regions = ["us-west1", "europe-west1"]

labels = {
  environment = "production"
  application = "lux-kms"
  team        = "security"
}
EOF
```

#### Step 2: Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Review planned changes
terraform plan

# Apply configuration
terraform apply

# Save outputs
terraform output -json > outputs.json
```

#### Step 3: Configure Lux KMS

```bash
# Copy environment template
cp ../.env.example ../.env

# Export Terraform outputs
export GOOGLE_CLOUD_PROJECT_ID=$(terraform output -raw project_id)
export GOOGLE_CLOUD_LOCATION=$(terraform output -json | jq -r '.key_location.value')
export GOOGLE_CLOUD_KEY_RING=$(terraform output -json | jq -r '.key_ring_name.value')
export GOOGLE_CLOUD_CRYPTO_KEY=$(terraform output -json | jq -r '.crypto_key_name.value')
export GOOGLE_APPLICATION_CREDENTIALS=$(pwd)/lux-kms-credentials.json

# Update .env file
cat >> ../.env <<EOF
GOOGLE_CLOUD_PROJECT_ID=$GOOGLE_CLOUD_PROJECT_ID
GOOGLE_CLOUD_LOCATION=$GOOGLE_CLOUD_LOCATION
GOOGLE_CLOUD_KEY_RING=$GOOGLE_CLOUD_KEY_RING
GOOGLE_CLOUD_CRYPTO_KEY=$GOOGLE_CLOUD_CRYPTO_KEY
GOOGLE_APPLICATION_CREDENTIALS=$GOOGLE_APPLICATION_CREDENTIALS
EOF
```

### Option 2: Docker Compose (Local Development)

Simple local deployment for testing and development.

#### Step 1: Manual GCP Setup

```bash
# Set project
gcloud config set project YOUR_PROJECT_ID

# Enable APIs
gcloud services enable cloudkms.googleapis.com
gcloud services enable iam.googleapis.com

# Create key ring
gcloud kms keyrings create lux-kms-keyring --location=global

# Create crypto key (SOFTWARE for development)
gcloud kms keys create lux-kms-key \
  --location=global \
  --keyring=lux-kms-keyring \
  --purpose=encryption \
  --protection-level=software

# Create service account
gcloud iam service-accounts create lux-kms-sa \
  --display-name="Lux KMS Service Account"

# Grant permissions
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:lux-kms-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"

# Generate credentials
gcloud iam service-accounts keys create lux-kms-credentials.json \
  --iam-account=lux-kms-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

#### Step 2: Configure and Run

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your values
nano .env

# Start services
docker-compose up -d

# View logs
docker-compose logs -f lux-kms

# Check health
curl http://localhost:8080/health
```

#### Step 3: Optional Monitoring

```bash
# Start with monitoring stack
docker-compose --profile monitoring up -d

# Access Grafana
open http://localhost:3000  # admin/admin

# Access Prometheus
open http://localhost:9091
```

### Option 3: Kubernetes on GKE (Production)

Enterprise-grade deployment with high availability.

#### Step 1: Create GKE Cluster

```bash
# Set variables
export PROJECT_ID="your-gcp-project-id"
export CLUSTER_NAME="lux-kms-cluster"
export REGION="us-east1"

# Create cluster with Workload Identity enabled
gcloud container clusters create $CLUSTER_NAME \
  --region=$REGION \
  --workload-pool=$PROJECT_ID.svc.id.goog \
  --enable-autoscaling \
  --min-nodes=3 \
  --max-nodes=10 \
  --machine-type=e2-standard-4 \
  --enable-autorepair \
  --enable-autoupgrade \
  --enable-ip-alias \
  --network=default \
  --subnetwork=default \
  --addons=HorizontalPodAutoscaling,HttpLoadBalancing,GcePersistentDiskCsiDriver \
  --workload-metadata=GKE_METADATA

# Get credentials
gcloud container clusters get-credentials $CLUSTER_NAME --region=$REGION
```

#### Step 2: Setup Workload Identity

```bash
cd kubernetes

# Configure environment
export GOOGLE_CLOUD_PROJECT_ID=$PROJECT_ID
export GKE_CLUSTER_NAME=$CLUSTER_NAME
export GKE_CLUSTER_REGION=$REGION
export GCP_SERVICE_ACCOUNT="lux-kms-sa"  # Created by Terraform
export K8S_SERVICE_ACCOUNT="lux-kms-sa"
export K8S_NAMESPACE="lux-kms"

# Run setup script
./workload-identity-setup.sh
```

#### Step 3: Deploy Lux KMS

```bash
# Update deployment.yaml with your project ID
sed -i "s/PROJECT_ID/$PROJECT_ID/g" deployment.yaml

# Create secrets
kubectl create secret generic lux-kms-secrets \
  --namespace=lux-kms \
  --from-literal=GOOGLE_CLOUD_PROJECT_ID=$PROJECT_ID \
  --from-literal=DB_CONNECTION_URI=postgresql://user:password@postgres:5432/lux_kms \
  --from-literal=JWT_SECRET=$(openssl rand -hex 32) \
  --from-literal=REDIS_URL=redis://redis:6379 \
  --dry-run=client -o yaml | kubectl apply -f -

# Deploy
kubectl apply -f deployment.yaml

# Verify deployment
kubectl get pods -n lux-kms
kubectl logs -n lux-kms -l app.kubernetes.io/name=lux-kms
```

#### Step 4: Expose Service

```bash
# Get LoadBalancer IP
kubectl get svc lux-kms -n lux-kms

# Or use Ingress (recommended)
cat > ingress.yaml <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: lux-kms
  namespace: lux-kms
  annotations:
    kubernetes.io/ingress.class: "gce"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - kms.yourdomain.com
    secretName: lux-kms-tls
  rules:
  - host: kms.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: lux-kms
            port:
              number: 80
EOF

kubectl apply -f ingress.yaml
```

## Verification

### Test Google Cloud KMS Access

```bash
# Test encryption
echo "test data" | gcloud kms encrypt \
  --location=global \
  --keyring=lux-kms-keyring \
  --key=lux-kms-key \
  --plaintext-file=- \
  --ciphertext-file=- | base64

# Test with service account
export GOOGLE_APPLICATION_CREDENTIALS=./lux-kms-credentials.json
gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS
gcloud kms keys describe lux-kms-key \
  --location=global \
  --keyring=lux-kms-keyring
```

### Test Lux KMS

```bash
# Health check
curl http://localhost:8080/health

# Create a secret
curl -X POST http://localhost:8080/api/v1/secrets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "name": "test-secret",
    "value": "sensitive-data"
  }'

# Retrieve secret
curl http://localhost:8080/api/v1/secrets/test-secret \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Check metrics
curl http://localhost:9090/metrics
```

### Verify Workload Identity (Kubernetes)

```bash
# Run test pod
kubectl run -it --rm test-wi \
  --namespace lux-kms \
  --serviceaccount=lux-kms-sa \
  --image=google/cloud-sdk:slim \
  -- gcloud auth list

# Expected output should show: lux-kms-sa@PROJECT_ID.iam.gserviceaccount.com
```

## Monitoring

### Prometheus Metrics

Available metrics:
- `lux_kms_google_cloud_encrypt_total` - Total encryption operations
- `lux_kms_google_cloud_decrypt_total` - Total decryption operations
- `lux_kms_google_cloud_operation_duration_seconds` - Operation latency
- `lux_kms_google_cloud_errors_total` - Total errors

### Cloud Audit Logs

```bash
# View KMS operations
gcloud logging read "resource.type=cloudkms_cryptokey" \
  --limit 50 \
  --format json \
  --freshness=1h

# Filter by operation
gcloud logging read 'resource.type=cloudkms_cryptokey AND protoPayload.methodName="Encrypt"' \
  --limit 10
```

### Grafana Dashboards

Import pre-built dashboards from `grafana/dashboards/`.

## Troubleshooting

### Common Issues

**Issue: Permission denied errors**
```bash
# Check service account permissions
gcloud projects get-iam-policy YOUR_PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:lux-kms-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com"

# Grant missing permissions
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:lux-kms-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
```

**Issue: Key not found**
```bash
# List keys
gcloud kms keys list --location=global --keyring=lux-kms-keyring

# Describe key
gcloud kms keys describe lux-kms-key \
  --location=global \
  --keyring=lux-kms-keyring
```

**Issue: Workload Identity not working**
```bash
# Check annotation
kubectl get sa lux-kms-sa -n lux-kms -o yaml

# Check binding
gcloud iam service-accounts get-iam-policy \
  lux-kms-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com

# Re-run setup
cd kubernetes && ./workload-identity-setup.sh
```

## Cost Optimization

### Pricing Breakdown
- HSM key version: $2.50/month (active)
- Software key version: $0.06/month (active)
- Operations: $0.03 per 10,000 operations

### Optimization Tips

1. **Use global location** - Avoid cross-region data transfer costs
2. **Destroy old versions** - Remove disabled key versions
   ```bash
   gcloud kms keys versions destroy 1 \
     --location=global \
     --keyring=lux-kms-keyring \
     --key=lux-kms-key
   ```
3. **Software for dev/test** - Use SOFTWARE protection level for non-production
4. **Batch operations** - Reduce API call frequency

## Security Checklist

- [ ] Use HSM protection level for production keys
- [ ] Enable automatic key rotation (90 days recommended)
- [ ] Use Workload Identity instead of service account keys
- [ ] Enable Cloud Audit Logs
- [ ] Set up VPC Service Controls
- [ ] Implement least-privilege IAM policies
- [ ] Rotate service account keys regularly
- [ ] Enable Cloud Armor for DDoS protection
- [ ] Use private GKE clusters
- [ ] Encrypt etcd secrets in Kubernetes

## Migration

### From On-Premises HSM

1. Export secrets from on-premises system
2. Deploy Google Cloud KMS infrastructure (Terraform)
3. Run Lux KMS migration tool:
   ```bash
   lux-kms migrate \
     --from=on-premises \
     --to=google-cloud \
     --source-hsm=/path/to/pkcs11.so \
     --target-project=YOUR_PROJECT_ID
   ```

### From AWS CloudHSM

1. Export encrypted data from AWS
2. Set up Google Cloud KMS
3. Re-encrypt with new keys:
   ```bash
   lux-kms migrate \
     --from=aws-cloudhsm \
     --to=google-cloud \
     --aws-region=us-east-1 \
     --gcp-project=YOUR_PROJECT_ID
   ```

## Cleanup

### Docker Compose
```bash
docker-compose down -v
rm lux-kms-credentials.json
```

### Kubernetes
```bash
kubectl delete namespace lux-kms
gcloud container clusters delete $CLUSTER_NAME --region=$REGION
```

### Terraform
```bash
cd terraform
terraform destroy
```

**Warning**: Destroying crypto keys is a 24-hour process. Keys are scheduled for destruction, not immediately deleted.

## Support

- Documentation: `/docs/kms-configuration/google-cloud-hsm`
- GitHub Issues: https://github.com/luxfi/kms/issues
- Community Slack: https://lux-community.slack.com

## License

Apache 2.0 - See LICENSE file for details

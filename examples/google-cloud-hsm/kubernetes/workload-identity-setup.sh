#!/bin/bash
# Setup script for Google Cloud Workload Identity with Lux KMS
# This script configures Workload Identity binding between GKE and GCP service accounts

set -e

# Configuration
PROJECT_ID="${GOOGLE_CLOUD_PROJECT_ID:-lux-kms-production}"
CLUSTER_NAME="${GKE_CLUSTER_NAME:-lux-kms-cluster}"
CLUSTER_REGION="${GKE_CLUSTER_REGION:-us-east1}"
GCP_SA_NAME="${GCP_SERVICE_ACCOUNT:-lux-kms-sa}"
K8S_SA_NAME="${K8S_SERVICE_ACCOUNT:-lux-kms-sa}"
K8S_NAMESPACE="${K8S_NAMESPACE:-lux-kms}"

echo "========================================="
echo "Google Cloud Workload Identity Setup"
echo "========================================="
echo ""
echo "Configuration:"
echo "  Project ID:         $PROJECT_ID"
echo "  Cluster Name:       $CLUSTER_NAME"
echo "  Cluster Region:     $CLUSTER_REGION"
echo "  GCP SA:             $GCP_SA_NAME"
echo "  Kubernetes SA:      $K8S_SA_NAME"
echo "  Kubernetes NS:      $K8S_NAMESPACE"
echo ""

# Step 1: Enable Workload Identity on GKE cluster
echo "Step 1: Enabling Workload Identity on GKE cluster..."
gcloud container clusters update "$CLUSTER_NAME" \
  --region="$CLUSTER_REGION" \
  --workload-pool="$PROJECT_ID.svc.id.goog" \
  --project="$PROJECT_ID"

echo "✓ Workload Identity enabled on cluster"
echo ""

# Step 2: Create Kubernetes namespace
echo "Step 2: Creating Kubernetes namespace..."
kubectl create namespace "$K8S_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
echo "✓ Namespace created"
echo ""

# Step 3: Create Kubernetes Service Account
echo "Step 3: Creating Kubernetes Service Account..."
kubectl create serviceaccount "$K8S_SA_NAME" \
  --namespace "$K8S_NAMESPACE" \
  --dry-run=client -o yaml | kubectl apply -f -
echo "✓ Kubernetes Service Account created"
echo ""

# Step 4: Annotate Kubernetes Service Account
echo "Step 4: Annotating Kubernetes Service Account..."
kubectl annotate serviceaccount "$K8S_SA_NAME" \
  --namespace "$K8S_NAMESPACE" \
  iam.gke.io/gcp-service-account="$GCP_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
  --overwrite
echo "✓ Service Account annotated"
echo ""

# Step 5: Bind GCP Service Account to Kubernetes Service Account
echo "Step 5: Binding GCP SA to Kubernetes SA..."
gcloud iam service-accounts add-iam-policy-binding \
  "$GCP_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:$PROJECT_ID.svc.id.goog[$K8S_NAMESPACE/$K8S_SA_NAME]" \
  --project="$PROJECT_ID"

echo "✓ Workload Identity binding created"
echo ""

# Step 6: Verify configuration
echo "Step 6: Verifying Workload Identity configuration..."

# Check GCP SA exists
if gcloud iam service-accounts describe "$GCP_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
   --project="$PROJECT_ID" > /dev/null 2>&1; then
  echo "✓ GCP Service Account exists"
else
  echo "✗ GCP Service Account not found"
  exit 1
fi

# Check K8s SA exists and has correct annotation
K8S_SA_ANNOTATION=$(kubectl get serviceaccount "$K8S_SA_NAME" \
  --namespace "$K8S_NAMESPACE" \
  -o jsonpath='{.metadata.annotations.iam\.gke\.io/gcp-service-account}')

if [ "$K8S_SA_ANNOTATION" == "$GCP_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" ]; then
  echo "✓ Kubernetes Service Account properly annotated"
else
  echo "✗ Kubernetes Service Account annotation incorrect"
  echo "   Expected: $GCP_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
  echo "   Got: $K8S_SA_ANNOTATION"
  exit 1
fi

echo ""
echo "========================================="
echo "Workload Identity Setup Complete!"
echo "========================================="
echo ""
echo "Next Steps:"
echo ""
echo "1. Deploy Lux KMS:"
echo "   kubectl apply -f kubernetes/deployment.yaml"
echo ""
echo "2. Verify deployment:"
echo "   kubectl get pods -n $K8S_NAMESPACE"
echo ""
echo "3. Check logs:"
echo "   kubectl logs -n $K8S_NAMESPACE -l app.kubernetes.io/name=lux-kms"
echo ""
echo "4. Test Workload Identity:"
echo "   kubectl run -it --rm test-wi \\"
echo "     --namespace $K8S_NAMESPACE \\"
echo "     --serviceaccount=$K8S_SA_NAME \\"
echo "     --image=google/cloud-sdk:slim \\"
echo "     -- gcloud auth list"
echo ""
echo "   You should see: $GCP_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
echo ""
echo "5. Access Lux KMS:"
echo "   kubectl port-forward -n $K8S_NAMESPACE svc/lux-kms 8080:80"
echo "   curl http://localhost:8080/health"
echo ""

#!/bin/bash
# AWS CloudHSM Deployment Helper Script for Lux KMS
# This script automates the deployment of CloudHSM cluster and KMS

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not found. Install: https://aws.amazon.com/cli/"
    fi

    if ! command -v jq &> /dev/null; then
        log_warn "jq not found. Install for better output: sudo yum install jq"
    fi

    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured. Run: aws configure"
    fi

    log_info "Prerequisites check passed"
}

# Deploy CloudFormation stack
deploy_cloudformation() {
    log_info "Deploying CloudHSM cluster via CloudFormation..."

    # Prompt for VPC and subnets if not provided
    if [ -z "$VPC_ID" ]; then
        read -p "Enter VPC ID: " VPC_ID
    fi

    if [ -z "$SUBNET_IDS" ]; then
        read -p "Enter subnet IDs (comma-separated): " SUBNET_IDS
    fi

    # Deploy stack
    log_info "Creating CloudFormation stack: lux-kms-cloudhsm"
    aws cloudformation create-stack \
        --stack-name lux-kms-cloudhsm \
        --template-body file://cloudformation-template.yaml \
        --parameters \
            ParameterKey=VpcId,ParameterValue="$VPC_ID" \
            ParameterKey=PrivateSubnetIds,ParameterValue="$SUBNET_IDS" \
            ParameterKey=NumberOfHsms,ParameterValue="${NUMBER_OF_HSMS:-2}" \
            ParameterKey=Environment,ParameterValue="${ENVIRONMENT:-production}" \
        --capabilities CAPABILITY_NAMED_IAM

    log_info "Waiting for stack creation to complete (this may take 5-10 minutes)..."
    aws cloudformation wait stack-create-complete \
        --stack-name lux-kms-cloudhsm

    log_info "CloudFormation stack created successfully"
}

# Get cluster information
get_cluster_info() {
    log_info "Retrieving cluster information..."

    CLUSTER_ID=$(aws cloudformation describe-stacks \
        --stack-name lux-kms-cloudhsm \
        --query 'Stacks[0].Outputs[?OutputKey==`ClusterId`].OutputValue' \
        --output text)

    if [ -z "$CLUSTER_ID" ]; then
        log_error "Failed to retrieve cluster ID from CloudFormation stack"
    fi

    log_info "Cluster ID: $CLUSTER_ID"

    # Save to .env
    echo "AWS_CLOUDHSM_CLUSTER_ID=$CLUSTER_ID" >> .env

    # Get HSM IP
    HSM_IP=$(aws cloudhsmv2 describe-clusters \
        --filters clusterIds=$CLUSTER_ID \
        --query 'Clusters[0].Hsms[0].EniIp' \
        --output text)

    log_info "HSM IP: $HSM_IP"

    # Download cluster certificate
    log_info "Downloading cluster certificate..."
    aws cloudhsmv2 describe-clusters \
        --filters clusterIds=$CLUSTER_ID \
        --query 'Clusters[0].Certificates.ClusterCertificate' \
        --output text > cluster.crt

    log_info "Cluster certificate saved to: cluster.crt"
}

# Install CloudHSM client
install_client() {
    log_info "Installing CloudHSM client..."

    # Detect OS
    if [ -f /etc/redhat-release ]; then
        # RHEL/CentOS/Amazon Linux
        log_info "Detected RHEL-based system"
        wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-latest.el7.x86_64.rpm
        sudo yum install -y ./cloudhsm-client-latest.el7.x86_64.rpm cloudhsm-client-pkcs11
    elif [ -f /etc/lsb-release ]; then
        # Ubuntu/Debian
        log_info "Detected Ubuntu/Debian system"
        UBUNTU_VERSION=$(lsb_release -rs)
        if [[ "$UBUNTU_VERSION" == "22.04" ]]; then
            wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Jammy/cloudhsm-client_latest_u22.04_amd64.deb
            sudo apt install -y ./cloudhsm-client_latest_u22.04_amd64.deb cloudhsm-client-pkcs11
        else
            wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Bionic/cloudhsm-client_latest_u18.04_amd64.deb
            sudo apt install -y ./cloudhsm-client_latest_u18.04_amd64.deb cloudhsm-client-pkcs11
        fi
    else
        log_error "Unsupported OS. Please install CloudHSM client manually."
    fi

    log_info "CloudHSM client installed successfully"
}

# Configure CloudHSM client
configure_client() {
    log_info "Configuring CloudHSM client..."

    # Copy certificate
    sudo cp cluster.crt /opt/cloudhsm/etc/

    # Configure client
    sudo /opt/cloudhsm/bin/configure -a "$HSM_IP"

    log_info "CloudHSM client configured"
    log_info "Configuration file: /opt/cloudhsm/etc/cloudhsm_client.cfg"
}

# Initialize cluster instructions
initialize_cluster() {
    log_warn "====================================="
    log_warn "CLUSTER INITIALIZATION REQUIRED"
    log_warn "====================================="
    echo ""
    log_info "Run the following commands to initialize the cluster:"
    echo ""
    echo "1. Start CloudHSM management utility:"
    echo "   /opt/cloudhsm/bin/cloudhsm_mgmt_util /opt/cloudhsm/etc/cloudhsm_mgmt_util.cfg"
    echo ""
    echo "2. In cloudhsm_mgmt_util, run:"
    echo "   loginHSM CO admin admin"
    echo "   changePswd CO admin <new-strong-password>"
    echo "   createUser CU luxkms <strong-cu-pin>"
    echo "   quit"
    echo ""
    log_warn "IMPORTANT: Save the CU PIN securely - you will need it for KMS deployment"
}

# Generate keys instructions
generate_keys() {
    log_warn "====================================="
    log_warn "KEY GENERATION REQUIRED"
    log_warn "====================================="
    echo ""
    log_info "Run the following commands to generate encryption keys:"
    echo ""
    echo "1. Start key management utility:"
    echo "   /opt/cloudhsm/bin/key_mgmt_util"
    echo ""
    echo "2. In key_mgmt_util, run:"
    echo "   loginHSM -u CU -s luxkms -p <cu-pin>"
    echo "   genSymKey -t 31 -s 32 -l lux-kms-key"
    echo "   findKey -l lux-kms-key"
    echo "   quit"
}

# Deploy KMS with Docker Compose
deploy_kms() {
    log_info "Deploying Lux KMS with Docker Compose..."

    # Create .env if it doesn't exist
    if [ ! -f .env ]; then
        log_info "Creating .env file from template..."
        cp .env.example .env

        # Update cluster ID
        sed -i "s/AWS_CLOUDHSM_CLUSTER_ID=.*/AWS_CLOUDHSM_CLUSTER_ID=$CLUSTER_ID/" .env

        log_warn "Please edit .env file and add:"
        log_warn "  - AWS_CLOUDHSM_PIN (CU PIN from initialization)"
        log_warn "  - POSTGRES_PASSWORD"
        log_warn "  - REDIS_PASSWORD"
        log_warn "  - AWS credentials (or use IAM instance role)"
        echo ""
        read -p "Press Enter after editing .env file..."
    fi

    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Install Docker: https://docs.docker.com/engine/install/"
    fi

    # Start services
    log_info "Starting KMS services..."
    docker-compose up -d

    log_info "Waiting for services to be healthy..."
    sleep 10

    # Check health
    if curl -f http://localhost:8080/health &> /dev/null; then
        log_info "✓ KMS is running and healthy!"
        log_info "Access KMS at: http://localhost:8080"
    else
        log_warn "KMS health check failed. Check logs: docker-compose logs -f kms"
    fi
}

# Main menu
show_menu() {
    echo ""
    log_info "AWS CloudHSM Deployment Helper"
    echo "=============================="
    echo "1. Deploy CloudHSM cluster (CloudFormation)"
    echo "2. Get cluster information"
    echo "3. Install CloudHSM client"
    echo "4. Configure CloudHSM client"
    echo "5. Show cluster initialization steps"
    echo "6. Show key generation steps"
    echo "7. Deploy KMS (Docker Compose)"
    echo "8. Full deployment (steps 1-7)"
    echo "9. Exit"
    echo ""
    read -p "Select option: " choice

    case $choice in
        1) deploy_cloudformation ;;
        2) get_cluster_info ;;
        3) install_client ;;
        4) configure_client ;;
        5) initialize_cluster ;;
        6) generate_keys ;;
        7) deploy_kms ;;
        8)
            check_prerequisites
            deploy_cloudformation
            get_cluster_info
            install_client
            configure_client
            initialize_cluster
            generate_keys
            log_warn "Complete steps 5 and 6 before deploying KMS"
            read -p "Press Enter after completing initialization and key generation..."
            deploy_kms
            ;;
        9) exit 0 ;;
        *) log_error "Invalid option" ;;
    esac
}

# Main execution
main() {
    # Change to script directory
    cd "$(dirname "$0")"

    # Show menu in loop
    while true; do
        show_menu
    done
}

# Run main
main

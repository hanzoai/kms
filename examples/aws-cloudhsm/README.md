# AWS CloudHSM Examples for Lux KMS

This directory contains examples for deploying Lux KMS with AWS CloudHSM.

## Files

- **cloudformation-template.yaml** - CloudFormation template for creating CloudHSM cluster
- **docker-compose.yml** - Docker Compose configuration for KMS with CloudHSM
- **.env.example** - Environment variable template
- **deploy.sh** - Helper script for deployment
- **cloudhsm_client.cfg.example** - CloudHSM client configuration example

## Quick Start

### 1. Deploy CloudHSM Cluster

```bash
# Set your VPC and subnet IDs
export VPC_ID=vpc-xxxx
export SUBNET_IDS=subnet-aaa,subnet-bbb

# Deploy cluster using CloudFormation
aws cloudformation create-stack \
  --stack-name lux-kms-cloudhsm \
  --template-body file://cloudformation-template.yaml \
  --parameters \
    ParameterKey=VpcId,ParameterValue=$VPC_ID \
    ParameterKey=PrivateSubnetIds,ParameterValue="$SUBNET_IDS" \
    ParameterKey=NumberOfHsms,ParameterValue=2 \
  --capabilities CAPABILITY_NAMED_IAM

# Wait for stack creation
aws cloudformation wait stack-create-complete \
  --stack-name lux-kms-cloudhsm

# Get cluster ID
CLUSTER_ID=$(aws cloudformation describe-stacks \
  --stack-name lux-kms-cloudhsm \
  --query 'Stacks[0].Outputs[?OutputKey==`ClusterId`].OutputValue' \
  --output text)

echo "Cluster ID: $CLUSTER_ID"
```

### 2. Initialize Cluster

```bash
# Download cluster certificate
aws cloudhsmv2 describe-clusters \
  --filters clusterIds=$CLUSTER_ID \
  --query 'Clusters[0].Certificates.ClusterCertificate' \
  --output text > cluster.crt

# Get HSM IP
HSM_IP=$(aws cloudhsmv2 describe-clusters \
  --filters clusterIds=$CLUSTER_ID \
  --query 'Clusters[0].Hsms[0].EniIp' \
  --output text)

echo "HSM IP: $HSM_IP"

# Install CloudHSM client (on KMS host)
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-latest.el7.x86_64.rpm
sudo yum install -y ./cloudhsm-client-latest.el7.x86_64.rpm cloudhsm-client-pkcs11

# Configure client
sudo cp cluster.crt /opt/cloudhsm/etc/
sudo /opt/cloudhsm/bin/configure -a $HSM_IP

# Initialize cluster (first time only)
/opt/cloudhsm/bin/cloudhsm_mgmt_util /opt/cloudhsm/etc/cloudhsm_mgmt_util.cfg
```

In `cloudhsm_mgmt_util`:

```
aws-cloudhsm> loginHSM CO admin admin
aws-cloudhsm> changePswd CO admin <new-strong-password>
aws-cloudhsm> createUser CU luxkms <strong-cu-pin>
aws-cloudhsm> quit
```

### 3. Generate Keys

```bash
/opt/cloudhsm/bin/key_mgmt_util

# In key_mgmt_util:
loginHSM -u CU -s luxkms -p <cu-pin>
genSymKey -t 31 -s 32 -l lux-kms-key
findKey -l lux-kms-key
quit
```

### 4. Deploy KMS with Docker Compose

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your values
vim .env

# Start KMS
docker-compose up -d

# Check logs
docker-compose logs -f kms

# Verify health
curl http://localhost:8080/health
```

## Environment Variables

Required variables in `.env`:

```bash
# CloudHSM
AWS_CLOUDHSM_CLUSTER_ID=cluster-abc123xyz
AWS_CLOUDHSM_PIN=<cu-pin-from-step2>
AWS_REGION=us-east-1
HSM_KEY_LABEL=lux-kms-key

# AWS Credentials (or use IAM role)
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...

# Database
POSTGRES_PASSWORD=secure-password
REDIS_PASSWORD=secure-password
```

## Deployment Scenarios

### Scenario 1: EC2 with IAM Instance Role

```bash
# Create EC2 instance with KMS instance profile
INSTANCE_PROFILE=$(aws cloudformation describe-stacks \
  --stack-name lux-kms-cloudhsm \
  --query 'Stacks[0].Outputs[?OutputKey==`KMSInstanceProfileArn`].OutputValue' \
  --output text)

aws ec2 run-instances \
  --image-id ami-xxxx \
  --instance-type t3.medium \
  --iam-instance-profile Arn=$INSTANCE_PROFILE \
  --security-group-ids sg-xxxx \
  --subnet-id subnet-aaa \
  --user-data file://user-data.sh

# user-data.sh installs Docker and runs docker-compose
```

### Scenario 2: ECS with Task Role

```yaml
# ecs-task-definition.json
{
  "family": "lux-kms",
  "taskRoleArn": "arn:aws:iam::123456789012:role/lux-kms-role-production",
  "networkMode": "awsvpc",
  "containerDefinitions": [
    {
      "name": "kms",
      "image": "luxfi/kms:latest",
      "environment": [
        {"name": "AWS_CLOUDHSM_CLUSTER_ID", "value": "cluster-abc123"},
        {"name": "AWS_REGION", "value": "us-east-1"}
      ],
      "secrets": [
        {
          "name": "AWS_CLOUDHSM_PIN",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:cloudhsm-pin-xxxxx"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "cloudhsm",
          "containerPath": "/opt/cloudhsm"
        }
      ]
    }
  ],
  "volumes": [
    {
      "name": "cloudhsm",
      "host": {
        "sourcePath": "/opt/cloudhsm"
      }
    }
  ]
}
```

### Scenario 3: Kubernetes with IRSA

```yaml
# kms-deployment.yaml
apiVersion: v1
kind: Secret
metadata:
  name: cloudhsm-credentials
type: Opaque
stringData:
  pin: "<cu-pin>"
  cluster-id: "cluster-abc123"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lux-kms
spec:
  replicas: 2
  selector:
    matchLabels:
      app: lux-kms
  template:
    metadata:
      labels:
        app: lux-kms
    spec:
      serviceAccountName: kms-service-account
      containers:
      - name: kms
        image: luxfi/kms:latest
        env:
        - name: AWS_CLOUDHSM_CLUSTER_ID
          valueFrom:
            secretKeyRef:
              name: cloudhsm-credentials
              key: cluster-id
        - name: AWS_CLOUDHSM_PIN
          valueFrom:
            secretKeyRef:
              name: cloudhsm-credentials
              key: pin
        volumeMounts:
        - name: cloudhsm
          mountPath: /opt/cloudhsm
          readOnly: true
      volumes:
      - name: cloudhsm
        hostPath:
          path: /opt/cloudhsm
```

## Troubleshooting

### "No AWS CloudHSM slots found"

```bash
# Check client configuration
cat /opt/cloudhsm/etc/cloudhsm_client.cfg

# Verify connectivity
ping <hsm-ip>

# Restart client
sudo service cloudhsm-client restart

# Check logs
tail -f /var/log/cloudhsm/cloudhsm_client.log
```

### "Login failed"

- Verify CU PIN is correct
- Check user exists: `/opt/cloudhsm/bin/cloudhsm_mgmt_util`

### "Cluster not active"

```bash
# Check cluster state
aws cloudhsmv2 describe-clusters --filters clusterIds=$CLUSTER_ID

# If UNINITIALIZED, complete initialization
# If DEGRADED, check HSM health
```

## Security Best Practices

1. **Never commit .env file** - Use AWS Secrets Manager
2. **Use IAM roles** - Avoid hardcoded credentials
3. **Enable MFA** - For HSM deletion
4. **Rotate CU PIN** - Regularly
5. **Monitor CloudWatch** - Set up alarms

## Cost Estimation

For 2 HSMs (high availability):
- **CloudHSM**: ~$1.60/hour/HSM × 2 = $2,300/month
- **EC2** (t3.medium): ~$30/month
- **Total**: ~$2,330/month

## Support

- AWS CloudHSM Documentation: https://docs.aws.amazon.com/cloudhsm/
- Lux KMS Documentation: https://docs.lux.network/kms
- GitHub Issues: https://github.com/luxfi/kms

## License

See [LICENSE](../../LICENSE)

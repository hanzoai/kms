# Zymbit HSM Integration Examples

This directory contains example configurations for deploying KMS with Zymbit HSM support on various platforms.

## Prerequisites

1. **Hardware**: Zymbit SCM/HSM4 module installed on supported device (Raspberry Pi, Jetson, etc.)
2. **Software**: Zymbit SDK and PKCS#11 library installed
3. **Configuration**: Zymbit device initialized with PIN set

## Files

- `docker-compose.yml` - Docker Compose deployment with Zymbit HSM
- `kubernetes-deployment.yaml` - Full Kubernetes deployment manifests
- `.env.example` - Environment variable template

## Quick Start

### Docker Compose

1. **Prepare environment**:
   ```bash
   # Copy example environment file
   cp .env.example .env.secrets

   # Edit .env.secrets with actual values
   nano .env.secrets
   ```

2. **Generate secrets**:
   ```bash
   # Generate encryption key
   openssl rand -hex 32

   # Generate auth secret
   openssl rand -hex 32
   ```

3. **Start services**:
   ```bash
   docker-compose up -d
   ```

4. **Verify deployment**:
   ```bash
   # Check logs
   docker-compose logs -f kms

   # Health check
   curl http://localhost/api/status/health
   ```

### Kubernetes

1. **Label nodes with Zymbit hardware**:
   ```bash
   kubectl label nodes <node-name> hardware.zymbit.com/hsm=true
   ```

2. **Update secrets in `kubernetes-deployment.yaml`**:
   - Replace `HSM_PIN` with actual Zymbit PIN
   - Replace `ENCRYPTION_KEY` with generated key
   - Replace `AUTH_SECRET` with generated secret
   - Replace `DB_PASSWORD` with secure password

3. **Deploy to cluster**:
   ```bash
   kubectl apply -f kubernetes-deployment.yaml
   ```

4. **Verify deployment**:
   ```bash
   # Check pod status
   kubectl get pods -n kms-zymbit

   # View logs
   kubectl logs -n kms-zymbit deployment/kms

   # Port forward for testing
   kubectl port-forward -n kms-zymbit svc/kms-service 8080:80

   # Health check
   curl http://localhost:8080/api/status/health
   ```

## Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `HSM_ENABLED` | Enable HSM support | `true` |
| `HSM_PROVIDER` | HSM provider type | `zymbit` |
| `HSM_LIB_PATH` | PKCS#11 library path | `/usr/lib/libzk_pkcs11.so` |
| `HSM_PIN` | Zymbit PIN | `12345678` |
| `HSM_SLOT` | HSM slot number | `0` |
| `HSM_KEY_LABEL` | Key identifier | `lux-kms-key` |
| `ENCRYPTION_KEY` | KMS encryption key | 32-byte hex |
| `AUTH_SECRET` | Auth secret | Random string |
| `DB_CONNECTION_URI` | Database URI | `postgresql://...` |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ZYMBIT_DEVICE_PATH` | Zymbit device path | `/dev/zymkey` |
| `ZYMBIT_TAMPER_CHECK` | Enable tamper detection | `true` |
| `LOG_LEVEL` | Logging level | `info` |
| `JWT_EXPIRATION` | JWT expiration | `1h` |
| `REDIS_URL` | Redis connection | `redis://redis:6379` |

## Security Best Practices

1. **Secrets Management**:
   - Never commit actual secrets to version control
   - Use Kubernetes secrets or external secret managers
   - Rotate secrets regularly

2. **Physical Security**:
   - Install Zymbit in tamper-evident enclosure
   - Monitor tamper detection events
   - Enable secure boot

3. **Network Security**:
   - Use NetworkPolicy to restrict traffic
   - Enable TLS for all external communication
   - Use private networks for database access

4. **Access Control**:
   - Use RBAC for Kubernetes deployments
   - Limit privileged container access
   - Audit all HSM operations

## Monitoring

### Prometheus Metrics

KMS exposes Prometheus metrics at `/metrics`:

```bash
# View all metrics
curl http://localhost/metrics

# Key HSM metrics:
# - hsm_operations_total{operation="encrypt"}
# - hsm_operations_total{operation="decrypt"}
# - hsm_operation_duration_seconds
# - hsm_tamper_checks_total
```

### Health Checks

```bash
# Overall health
curl http://localhost/api/status/health

# HSM-specific health
curl http://localhost/api/v1/hsm/health
```

## Troubleshooting

### Common Issues

1. **Device not found**:
   ```bash
   # Check device
   ls -l /dev/zymkey

   # Rebind if needed
   sudo zkbind -i2c 1
   ```

2. **Permission denied**:
   ```bash
   # Check device permissions
   ls -l /dev/zymkey /dev/i2c-1

   # Docker needs --privileged or --device flags
   # Kubernetes needs privileged: true
   ```

3. **PIN errors**:
   ```bash
   # Reset PIN
   sudo zksetpin

   # Ensure PIN matches HSM_PIN in secrets
   ```

4. **Key not found**:
   ```bash
   # List keys
   pkcs11-tool --module /usr/lib/libzk_pkcs11.so --login --list-objects

   # Create key if missing
   pkcs11-tool --module /usr/lib/libzk_pkcs11.so --login \
     --keypairgen --key-type AES:32 --label "lux-kms-key"
   ```

## Performance Tuning

### Docker

```yaml
# In docker-compose.yml
services:
  kms:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### Kubernetes

```yaml
# In kubernetes-deployment.yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

## Backup and Recovery

### Database Backup

```bash
# Docker Compose
docker-compose exec postgres pg_dump -U kms kms > backup.sql

# Kubernetes
kubectl exec -n kms-zymbit postgres-0 -- pg_dump -U kms kms > backup.sql
```

### Key Backup

**Important**: Zymbit keys are hardware-bound and cannot be exported. For disaster recovery:

1. Use multiple Zymbit devices with replicated keys
2. Maintain backup devices in secure location
3. Document key recreation procedures

## Support

- [Zymbit Documentation](https://www.zymbit.com/docs/)
- [KMS Documentation](/documentation/platform/kms-configuration/zymbit-hsm)
- [GitHub Issues](https://github.com/lux/kms/issues)

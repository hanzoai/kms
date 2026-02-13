# kms-standalone

![Version: 1.4.0](https://img.shields.io/badge/Version-1.4.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.0.1](https://img.shields.io/badge/AppVersion-1.0.1-informational?style=flat-square)

A helm chart to deploy KMS

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| https://charts.bitnami.com/bitnami | postgresql | 14.1.3 |
| https://charts.bitnami.com/bitnami | redis | 18.14.0 |
| https://kubernetes.github.io/ingress-nginx | ingress-nginx | 4.0.13 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| fullnameOverride | string | `""` | Overrides the full name of the release, affecting resource names |
| kms.affinity | object | `{}` | Node affinity settings for pod placement |
| kms.databaseSchemaMigrationJob.image.pullPolicy | string | `"IfNotPresent"` | Pulls image only if not present on the node |
| kms.databaseSchemaMigrationJob.image.repository | string | `"ghcr.io/groundnuty/k8s-wait-for"` | Image repository for migration wait job |
| kms.databaseSchemaMigrationJob.image.tag | string | `"no-root-v2.0"` | Image tag version |
| kms.deploymentAnnotations | object | `{}` | Custom annotations for KMS deployment |
| kms.enabled | bool | `true` |  |
| kms.fullnameOverride | string | `""` | Override for the full name of KMS resources in this deployment |
| kms.image.imagePullSecrets | list | `[]` | Secret references for pulling the image, if needed |
| kms.image.pullPolicy | string | `"IfNotPresent"` | Pulls image only if not already present on the node |
| kms.image.repository | string | `"ghcr.io/hanzoai/kms"` | Image repository for the KMS service |
| kms.image.tag | string | `"v0.93.1-postgres"` | Specific version tag of the KMS image. View the latest version here https://hub.docker.com/r/ghcr.io/hanzoai/kms |
| kms.kubeSecretRef | string | `"kms-secrets"` | Kubernetes Secret reference containing KMS root credentials |
| kms.name | string | `"kms"` |  |
| kms.podAnnotations | object | `{}` | Custom annotations for KMS pods |
| kms.replicaCount | int | `2` | Number of pod replicas for high availability |
| kms.resources.limits.memory | string | `"600Mi"` | Memory limit for KMS container |
| kms.resources.requests.cpu | string | `"350m"` | CPU request for KMS container |
| kms.service.annotations | object | `{}` | Custom annotations for KMS service |
| kms.service.nodePort | string | `""` | Optional node port for service when using NodePort type |
| kms.service.type | string | `"ClusterIP"` | Service type, can be changed based on exposure needs (e.g., LoadBalancer) |
| kms.serviceAccount.annotations | object | `{}` | Custom annotations for the auto-created service account |
| kms.serviceAccount.create | bool | `true` | Creates a new service account if true, with necessary permissions for this chart. If false and `serviceAccount.name` is not defined, the chart will attempt to use the Default service account |
| kms.serviceAccount.name | string | `nil` | Optional custom service account name, if existing service account is used |
| ingress.annotations | object | `{}` | Custom annotations for ingress resource |
| ingress.enabled | bool | `true` | Enable or disable ingress configuration |
| ingress.hostName | string | `""` | Hostname for ingress access, e.g., app.example.com |
| ingress.ingressClassName | string | `"nginx"` | Specifies the ingress class, useful for multi-ingress setups |
| ingress.nginx.enabled | bool | `true` | Enable NGINX-specific settings, if using NGINX ingress controller |
| ingress.tls | list | `[]` | TLS settings for HTTPS access |
| nameOverride | string | `""` | Overrides the default release name |
| postgresql.auth.database | string | `"kmsDB"` | Database name for KMS |
| postgresql.auth.password | string | `"root"` | Password for PostgreSQL database access |
| postgresql.auth.username | string | `"kms"` | Database username for PostgreSQL |
| postgresql.enabled | bool | `true` | Enables an in-cluster PostgreSQL deployment. To achieve HA for Postgres, we recommend deploying https://github.com/zalando/postgres-operator instead. |
| postgresql.fullnameOverride | string | `"postgresql"` | Full name override for PostgreSQL resources |
| postgresql.name | string | `"postgresql"` | PostgreSQL resource name |
| postgresql.useExistingPostgresSecret.enabled | bool | `false` | Set to true if using an existing Kubernetes secret that contains PostgreSQL connection string |
| postgresql.useExistingPostgresSecret.existingConnectionStringSecret.key | string | `""` | Key name in the Kubernetes secret that holds the connection string |
| postgresql.useExistingPostgresSecret.existingConnectionStringSecret.name | string | `""` | Kubernetes secret name containing the PostgreSQL connection string |
| redis.architecture | string | `"standalone"` | Redis deployment type (e.g., standalone or cluster) |
| redis.auth.password | string | `"mysecretpassword"` | Redis password |
| redis.cluster.enabled | bool | `false` | Clustered Redis deployment |
| redis.enabled | bool | `true` | Enables an in-cluster Redis deployment |
| redis.fullnameOverride | string | `"redis"` | Full name override for Redis resources |
| redis.name | string | `"redis"` | Redis resource name |
| redis.usePassword | bool | `true` | Requires a password for Redis authentication |

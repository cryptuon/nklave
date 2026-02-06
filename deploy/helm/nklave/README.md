# Nklave Helm Chart

A Helm chart for deploying Nklave - a secure signing layer for PoS validators with slashing protection.

## Prerequisites

- Kubernetes 1.23+
- Helm 3.8+
- PV provisioner support in the underlying infrastructure (for persistence)

## Installation

### Add the Helm repository (if published)

```bash
helm repo add nklave https://charts.nklave.io
helm repo update
```

### Install from local chart

```bash
# Clone the repository
git clone https://github.com/nklave/nklave.git
cd nklave

# Install with default values
helm install my-nklave ./deploy/helm/nklave

# Install with custom values
helm install my-nklave ./deploy/helm/nklave -f my-values.yaml

# Install for production
helm install my-nklave ./deploy/helm/nklave -f ./deploy/helm/nklave/values-production.yaml
```

### Install in a specific namespace

```bash
helm install my-nklave ./deploy/helm/nklave --namespace validators --create-namespace
```

## Configuration

The following table lists the configurable parameters and their default values.

### General

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `nklave/nklave` |
| `image.tag` | Image tag | Chart appVersion |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full name | `""` |

### Service Account

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |

### Security Context

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podSecurityContext.runAsNonRoot` | Run as non-root | `true` |
| `podSecurityContext.runAsUser` | Run as user ID | `1000` |
| `podSecurityContext.runAsGroup` | Run as group ID | `1000` |
| `podSecurityContext.fsGroup` | FS group ID | `1000` |
| `securityContext.allowPrivilegeEscalation` | Allow privilege escalation | `false` |
| `securityContext.readOnlyRootFilesystem` | Read-only root filesystem | `true` |
| `securityContext.capabilities.drop` | Dropped capabilities | `["ALL"]` |

### Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.port` | HTTP API port | `9000` |
| `service.metricsPort` | Metrics port | `9001` |

### Ingress

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts | See values.yaml |
| `ingress.tls` | Ingress TLS configuration | `[]` |

### Resources

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |

### Persistence

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.enabled` | Enable persistence | `true` |
| `persistence.storageClass` | Storage class | `""` |
| `persistence.accessMode` | Access mode | `ReadWriteOnce` |
| `persistence.size` | Volume size | `1Gi` |
| `persistence.annotations` | PVC annotations | `{}` |

### Nklave Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.server.listenAddr` | API listen address | `0.0.0.0:9000` |
| `config.server.metricsAddr` | Metrics listen address | `0.0.0.0:9001` |
| `config.server.checkpointIntervalSecs` | Checkpoint interval | `300` |
| `config.server.checkpointBackupCount` | Checkpoint backup count | `3` |
| `config.api.requestTimeoutSecs` | Request timeout | `30` |
| `config.api.maxConcurrentRequests` | Max concurrent requests | `100` |
| `config.api.maxBodySize` | Max request body size | `1048576` |
| `config.auth.mode` | Auth mode (none/bearer/mtls/bearer_or_mtls) | `bearer` |
| `config.auth.tokens` | API bearer tokens | `[]` |
| `config.logging.encrypt` | Encrypt audit logs | `false` |
| `config.logging.rotation.maxSizeMb` | Max log size in MB | `100` |
| `config.logging.rotation.maxFiles` | Max log files | `10` |
| `config.logging.rotation.compress` | Compress rotated logs | `false` |
| `config.security.keyProvider` | Key provider (local/aws-kms) | `local` |

### TLS

| Parameter | Description | Default |
|-----------|-------------|---------|
| `tls.enabled` | Enable TLS | `false` |
| `tls.certManager.enabled` | Use cert-manager | `false` |
| `tls.certManager.issuerRef.name` | Issuer name | `""` |
| `tls.certManager.issuerRef.kind` | Issuer kind | `ClusterIssuer` |
| `tls.secretName` | TLS secret name | `""` |
| `tls.certPath` | Certificate path | `/etc/nklave/tls/tls.crt` |
| `tls.keyPath` | Key path | `/etc/nklave/tls/tls.key` |

### Replication (HA)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replication.enabled` | Enable replication | `false` |
| `replication.role` | Node role (primary/passive) | `primary` |
| `replication.listenAddr` | Replication listen address | `0.0.0.0:26660` |
| `replication.heartbeatIntervalMs` | Heartbeat interval | `1000` |
| `replication.maxBufferSize` | Max buffer size | `10000` |
| `replication.tls.enabled` | Enable replication TLS | `false` |

### Probes

| Parameter | Description | Default |
|-----------|-------------|---------|
| `livenessProbe.initialDelaySeconds` | Initial delay | `10` |
| `livenessProbe.periodSeconds` | Period | `10` |
| `readinessProbe.initialDelaySeconds` | Initial delay | `5` |
| `readinessProbe.periodSeconds` | Period | `5` |

### Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.enabled` | Enable ServiceMonitor | `false` |
| `serviceMonitor.interval` | Scrape interval | `30s` |
| `serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `serviceMonitor.labels` | Additional labels | `{}` |

### Pod Disruption Budget

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podDisruptionBudget.enabled` | Enable PDB | `true` |
| `podDisruptionBudget.minAvailable` | Minimum available pods | `1` |

## Examples

### Production deployment with TLS and authentication

```yaml
# values-production.yaml
replicaCount: 1

image:
  tag: "v0.1.0"  # Pin to specific version
  pullPolicy: Always

resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 250m
    memory: 256Mi

persistence:
  enabled: true
  storageClass: "fast-ssd"
  size: 10Gi

config:
  auth:
    mode: "bearer_or_mtls"
  logging:
    encrypt: true

tls:
  enabled: true
  certManager:
    enabled: true
    issuerRef:
      name: "letsencrypt-prod"
      kind: ClusterIssuer

serviceMonitor:
  enabled: true
```

### Set API tokens via environment variable

```bash
helm install my-nklave ./deploy/helm/nklave \
  --set config.auth.mode=bearer \
  --set-string extraEnv[0].name=NKLAVE_API_TOKENS \
  --set-string extraEnv[0].value="token1,token2"
```

### High availability with replication

Deploy primary:
```bash
helm install nklave-primary ./deploy/helm/nklave \
  --set replication.enabled=true \
  --set replication.role=primary
```

Deploy passive:
```bash
helm install nklave-passive ./deploy/helm/nklave \
  --set replication.enabled=true \
  --set replication.role=passive \
  --set-string extraEnv[0].name=NKLAVE_REPLICATION_PRIMARY_ADDR \
  --set-string extraEnv[0].value="nklave-primary-headless:26660"
```

## Upgrading

```bash
helm upgrade my-nklave ./deploy/helm/nklave -f my-values.yaml
```

## Uninstalling

```bash
helm uninstall my-nklave
```

**Note:** PersistentVolumeClaims are not deleted automatically. To delete them:

```bash
kubectl delete pvc -l app.kubernetes.io/instance=my-nklave
```

## Security Considerations

1. **Enable TLS**: Always enable TLS in production environments
2. **Enable Authentication**: Use `bearer` or `bearer_or_mtls` auth mode
3. **Encrypt Logs**: Set `config.logging.encrypt: true` for sensitive environments
4. **Use Read-Only Root FS**: Enabled by default via securityContext
5. **Resource Limits**: Set appropriate CPU/memory limits
6. **Network Policies**: Consider adding NetworkPolicy resources

## Troubleshooting

### Check pod status
```bash
kubectl get pods -l app.kubernetes.io/name=nklave
kubectl describe pod <pod-name>
```

### View logs
```bash
kubectl logs -f <pod-name>
```

### Access the API
```bash
kubectl port-forward svc/my-nklave 9000:9000
curl http://localhost:9000/eth/v1/keystores
```

## License

Apache 2.0

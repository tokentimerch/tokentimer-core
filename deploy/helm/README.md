# TokenTimer Helm Chart

Token, certificate, and secret expiration management for teams.

## What This Chart Deploys

| Component | Kind | Purpose |
|---|---|---|
| API | Deployment + Service | REST API server (Node.js, port 4000) |
| Dashboard | Deployment + Service | React frontend (nginx, port 80) |
| Alert Discovery | CronJob | Scans tokens and queues expiry alerts |
| Alert Delivery | CronJob | Processes alert queue, sends notifications |
| Weekly Digest | CronJob | Sends weekly token-expiry summaries |
| Endpoint Check | CronJob | SSL certificate and health monitoring |
| Auto Sync | CronJob | Scheduled integration scans |
| PostgreSQL | CloudNativePG Cluster | Database (optional, can use external) |

Optional resources (disabled by default): Ingress, HPA, PDB, ServiceMonitor, PrometheusRule, NetworkPolicy.

## Prerequisites

- Kubernetes >= 1.29
- Helm >= 3.14
- [CloudNativePG operator](https://cloudnative-pg.io/) if using the default in-cluster PostgreSQL (see below), or an existing PostgreSQL instance
- Prometheus Operator if enabling ServiceMonitor or PrometheusRule

### Installing the CloudNativePG operator (optional)

By default, the chart creates a [CloudNativePG](https://cloudnative-pg.io/) `Cluster` to provision PostgreSQL. This requires the CNPG operator to be installed on the cluster beforehand:

```bash
helm repo add cnpg https://cloudnative-pg.github.io/charts
helm repo update
helm install cnpg-operator cnpg/cloudnative-pg \
  --namespace cnpg-system --create-namespace \
  --version 0.23.0 \
  --wait
```

Verify the CRDs are registered:

```bash
kubectl get crd clusters.postgresql.cnpg.io
```

If you already have a PostgreSQL instance, skip the operator entirely and point the chart at your database instead:

```yaml
postgresql:
  cloudnative:
    enabled: false
  external:
    enabled: true
    host: "db.example.com"
    port: 5432
    database: tokentimer
    username: tokentimer
    password: "secret"       # or use existingSecret
    sslMode: require
```

## Quick Start

```bash
helm install tokentimer oci://ghcr.io/tokentimerch/charts/tokentimer \
  --namespace tokentimer --create-namespace \
  --set config.adminEmail=admin@example.com

# Port-forward to access locally
kubectl port-forward -n tokentimer svc/tokentimer-api 4000:4000 &
kubectl port-forward -n tokentimer svc/tokentimer-dashboard 8080:80 &
```

If the admin password was auto-generated, retrieve it with:

```bash
kubectl get secret -n tokentimer tokentimer-secrets \
  -o go-template='{{index .data "ADMIN_PASSWORD" | base64decode}}{{println}}'
```

Open http://localhost:8080 and log in with your admin credentials.

> When installing from a local checkout, run
> `helm dependency update ./deploy/helm` first, then use `./deploy/helm`
> instead of the OCI URL.

> **TLS Warning:** With `NODE_ENV=production`, the API sets the `Secure` flag on session cookies. Browsers will not persist or send secure cookies over plain HTTP. For anything beyond local port-forwarding, place HTTPS in front of the API and dashboard (via Ingress with TLS or a reverse proxy).

## Configuration Precedence

Several settings can be configured at multiple levels. The app resolves them with a clear precedence (highest wins):

| Setting | DB (System Settings UI) | DB (per-workspace) | Env var (Helm values) | Code default |
|---|---|---|---|---|
| SMTP config | **Wins** | -- | Fallback | `localhost:587` |
| Twilio credentials + SIDs | **Wins** | -- | Fallback | Disabled |
| Alert thresholds | -- | **Wins** | Fallback | `30,14,7,1,0` |
| Delivery window | -- | **Wins** | Fallback | `00:00-23:59 UTC` |
| Admin bootstrap | -- | -- | **Only source** | Skip if admin exists |

In practice this means:
- **SMTP / Twilio** values set in the Helm chart are the initial bootstrap config. Once an admin configures them in the System Settings UI, the DB values take over and the env vars are ignored.
- **Alert thresholds** and **delivery windows** from the chart are global defaults. Each workspace can override them through its own Alert Preferences in the dashboard.

## Configuration

The chart exposes first-class values for the most common settings (database, SMTP, Twilio, monitoring, ingress). For the full list of environment variables the app supports (rate limits, delivery windows, webhook security, auth tuning, etc.), see the [configuration reference](../../docs/CONFIGURATION.md).

Any env var not exposed as a dedicated values key can be passed through:
- `api.env` / `api.envFrom` for the API deployment
- `worker.env` / `worker.envFrom` for all CronJob workers
- `api.extraVolumes` / `api.extraVolumeMounts` for the API
- `worker.extraVolumes` / `worker.extraVolumeMounts` for all workers

Example -- setting delivery window and DB SSL cert for workers:

```yaml
worker:
  env:
    DELIVERY_WINDOW_DEFAULT_START: "08:00"
    DELIVERY_WINDOW_DEFAULT_END: "18:00"
    DELIVERY_WINDOW_DEFAULT_TZ: "Europe/Zurich"
    PGSSLROOTCERT: /etc/pg-ssl/ca.crt
  extraVolumes:
    - name: pg-ca
      secret:
        secretName: my-pg-ca-cert
  extraVolumeMounts:
    - name: pg-ca
      mountPath: /etc/pg-ssl
      readOnly: true
```

### Secrets Management

The chart generates a Kubernetes Secret with auto-generated values for `SESSION_SECRET`, `DB_PASSWORD`, and `ADMIN_PASSWORD` (when `adminEmail` is set). You only need to provide explicit passwords for production stability (auto-generated values change on each `helm upgrade`).

For production, use pre-existing secrets instead of setting plaintext values:

```yaml
config:
  existingSecret: "my-tokentimer-secrets"  # must contain SESSION_SECRET

postgresql:
  external:
    existingSecret: "my-db-secret"         # all DB_* keys

smtp:
  existingSecret: "my-smtp-secret"         # all SMTP_* + FROM_* keys

twilio:
  existingSecret: "my-twilio-secret"       # all TWILIO_* keys
```

When `existingSecret` is set for a group, the chart renders **no keys** for that group in the ConfigMap or generated Secret, so the existing secret becomes the single source of truth with no empty-value conflicts.

### Ingress

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: tokentimer.example.com
      paths:
        - path: /
          pathType: Prefix
          service: dashboard
        - path: /api
          pathType: Prefix
          service: api
  tls:
    - secretName: tokentimer-tls
      hosts:
        - tokentimer.example.com
```

### Private Registry

```yaml
global:
  imageRegistry: "registry.example.com"
  imagePullSecrets:
    - name: my-registry-secret
```

### Monitoring

```yaml
monitoring:
  metrics:
    enabled: true
    pushgatewayUrl: "http://pushgateway.monitoring.svc:9091"
  serviceMonitor:
    enabled: true
    labels:
      release: kube-prometheus-stack
  prometheusRules:
    enabled: true
    labels:
      release: kube-prometheus-stack
    groups:
      - name: tokentimer.rules
        rules:
          - alert: AppErrorsRecent
            expr: sum(increase(app_log_errors_total[5m])) > 0
            for: 0m
            labels:
              severity: warning
            annotations:
              summary: Application errors detected
```

### Autoscaling

```yaml
api:
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 80
  podDisruptionBudget:
    enabled: true
    minAvailable: 1
```

## Security

The chart defaults to a hardened security posture:

- `runAsNonRoot: true`, `runAsUser: 1000`
- `readOnlyRootFilesystem: true` (writable `/tmp` via emptyDir)
- `allowPrivilegeEscalation: false`
- All capabilities dropped
- `seccompProfile: RuntimeDefault`
- `automountServiceAccountToken: false`
- NetworkPolicy available (opt-in)

## Upgrading

```bash
helm upgrade tokentimer oci://ghcr.io/tokentimerch/charts/tokentimer -f my-values.yaml -n tokentimer
```

CronJob spec changes are applied on the next scheduled run. Deployments roll automatically via config/secret checksum annotations.

## Uninstalling

```bash
helm uninstall tokentimer -n tokentimer
```

CloudNativePG PVCs are retained by default. Delete them manually if no longer needed.

## Example Values

See the `examples/` directory:
- `values-minimal.yaml` -- single-node CNPG, no ingress
- `values-external-db.yaml` -- external PostgreSQL with ingress and monitoring

## Environment Variables Reference

For the complete list of supported environment variables (auth, rate limiting, delivery windows, webhook security, integration allowlists, etc.), see the [configuration reference](../../docs/CONFIGURATION.md).

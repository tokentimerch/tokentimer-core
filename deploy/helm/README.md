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
| CertOps Controller | Deployment | Optional cert-manager observation and safe `Certificate` provisioning |

Optional resources (disabled by default): Ingress, HPA, PDB, ServiceMonitor, PrometheusRule, NetworkPolicy.

## Prerequisites

- Kubernetes >= 1.29
- Helm >= 3.14
- [CloudNativePG operator](https://cloudnative-pg.io/) if using the default in-cluster PostgreSQL (see below), or an existing PostgreSQL instance
- Prometheus Operator if enabling ServiceMonitor or PrometheusRule
- cert-manager CRDs (`certificates.cert-manager.io` and
  `certificaterequests.cert-manager.io`) before enabling the CertOps controller

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

When `postgresql.cloudnative.enabled` is true (the default), the chart connects to the in-cluster database with `DB_SSL=verify` and automatically mounts the CA CloudNativePG generates (`<release>-pg-ca` secret) into the API and worker/cronjob pods at `/etc/pg-ssl/ca.crt`. No manual TLS setup is required for the default in-cluster database.

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

> **TLS Warning:** With `NODE_ENV=production`, the API sets the `Secure` flag on session cookies and enforces CSRF protection. Browsers will not persist or send secure cookies over plain HTTP, and mutating requests (including login) over `http://localhost` port-forwards will fail with 403 CSRF errors. For local testing, set `config.nodeEnv=development`, or inject `SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE=true` on the API via `api.envFrom`. For anything beyond local port-forwarding, place HTTPS in front of the API and dashboard (via Ingress with TLS or a reverse proxy).

## Configuration Precedence

Several settings can be configured at multiple levels. The app resolves them with a clear precedence (highest wins):

| Setting | DB (System Settings UI) | DB (per-workspace) | Env var (Helm values) | Code default |
|---|---|---|---|---|
| SMTP config (incl. `smtp.secure`, `smtp.requireTls`) | **Wins** | -- | Fallback | `localhost:587` |
| Twilio credentials + SIDs | **Wins** | -- | Fallback | Disabled |
| Alert thresholds | -- | **Wins** | Fallback | `30,14,7,1,0` |
| Delivery window | -- | **Wins** | Fallback | `00:00-23:59 UTC` |
| Admin bootstrap (`config.adminEmail` / `config.disableAdminBootstrap`) | -- | -- | **Only source** | Skip if admin exists |

In practice this means:
- **SMTP / Twilio** values set in the Helm chart are the initial bootstrap config. Once an admin configures them in the System Settings UI, the DB values take over and the env vars are ignored.
- **Alert thresholds** and **delivery windows** from the chart are global defaults. Each workspace can override them through its own Alert Preferences in the dashboard.

## Configuration

The chart exposes first-class values for the most common settings (database, SMTP, Twilio, monitoring, ingress). For the full list of environment variables the app supports (rate limits, delivery windows, webhook security, auth tuning, etc.), see the [configuration reference](../../docs/CONFIGURATION.md).

Any env var not exposed as a dedicated values key can be passed through:
- `api.env` / `api.envFrom` for the API deployment (`envFrom` ref names support Helm `tpl`)
- `worker.env` / `worker.envFrom` for all CronJob workers (same `tpl` behavior)
- `api.extraVolumes` / `api.extraVolumeMounts` for the API
- `worker.extraVolumes` / `worker.extraVolumeMounts` for all workers

Example -- setting delivery window and DB SSL cert for an **external** PostgreSQL instance on workers (not needed for the default in-cluster CloudNativePG database, whose CA is mounted automatically):

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

### CertOps Controller

The customer-cluster CertOps controller is a separate image and is disabled by
default. When enabled, its default `observe` mode watches cert-manager public
status and reports outbound to the TokenTimer API. TokenTimer never connects
inbound to Kubernetes and no kubeconfig is uploaded. Explicit `provision` mode
keeps observation enabled and additionally creates or Merge Patches only an
owned cert-manager `Certificate`. cert-manager—not TokenTimer—generates the
private key and manages the TLS Secret.

Create a machine token in the target workspace, bind it immutably to the same
lowercase cluster ID used below, and mount it from an existing Kubernetes
Secret. Scopes do not imply one another:

| Mode | Required machine-token scopes |
|---|---|
| `observe` | `certops:observations:write` |
| `provision` | `certops:observations:write`, `certops:provision:execute`, `certops:events:write`, `certops:evidence:write` |

The raw token is returned only when it is created. Store it under the configured
Secret key; do not put a raw token in Helm values.

```yaml
certops:
  controller:
    enabled: true
    mode: observe
    api:
      url: "https://api.tokentimer.example"
      workspaceId: "workspace-123"
      clusterId: "cluster-123"
    apiToken:
      existingSecret: "tokentimer-controller-api-token"
      key: token
    # Empty means the Helm release namespace. Set this only for an explicit
    # namespaced allow-list, or use clusterWide: true (never both).
    watchNamespaces: []
    clusterWide: false
    # Adds `get` on Secrets only; leave false unless public-certificate Secret
    # fallback is required.
    secretFallbackEnabled: false
```

The controller image reads the mounted token file on every request, so normal
Kubernetes Secret-volume rotation is picked up without retaining the token.
`api.url` must be reachable from the controller Pod; use HTTPS for external
control planes. `workspaceId` and `clusterId` must match the immutable token
binding. `watchNamespaces: []` resolves to the Helm release namespace, a
non-empty list renders one Role/RoleBinding per namespace, and
`clusterWide: true` is an explicit alternative. Invalid names, overlapping namespace and
cluster-wide settings, modes other than `observe`/`provision`, and replica
counts other than one fail rendering.

#### Zero-custody and RBAC model

Observation is status-first. The optional fallback performs one Secret `get`
and intentionally reads only `Secret.data["tls.crt"]`; `tls.key` is never
accessed, logged, serialized, or reported. Kubernetes RBAC cannot authorize one
data key inside a Secret, so enabling fallback necessarily grants access to the
whole Secret object even though the controller code consumes only `tls.crt`.
Leave fallback disabled unless public certificate parsing requires it. All
outbound observation envelopes are scanned for private material and fail
closed.

| Capability | cert-manager `Certificate` | `CertificateRequest` | Secret |
|---|---|---|---|
| `observe` | `get`, `list`, `watch` | `get`, `list`, `watch` | none; optional `get` for fallback |
| `provision` | `get`, `list`, `watch`, `create`, `patch` | `get`, `list`, `watch` | none; optional `get` for fallback |

Both modes forbid wildcard permissions, Secret writes, CertificateRequest
writes, and delete operations. Namespace mode uses Role/RoleBinding resources;
cluster-wide mode uses an explicit ClusterRole/ClusterRoleBinding. Provision
mode uses a `Recreate` deployment strategy to prevent overlapping write-capable
Pods until leader election exists.

Provisioning success means the desired `Certificate` resource was accepted or
reconciled by the Kubernetes API. Issuance is not complete at that point;
cert-manager updates status and the controller reports the eventual public
certificate asynchronously. Existing resources without the exact TokenTimer
workspace/cluster/managed-certificate ownership identity are rejected and are
never adopted. TokenTimer does not automatically delete or roll back a
Certificate.

#### Pause, topology, and operations

The workspace pause switch blocks new human provision intents and provisioning
command delivery. It does not delete queued/running records, and passive
observations plus the existing executor event/evidence surfaces remain
available. The deployment-wide `certops.enabled` rollout flag is a separate
outer gate.

| From | To | Direction and purpose |
|---|---|---|
| CertOps controller | TokenTimer API | Outbound HTTP(S): observations, command polling, events, evidence |
| CertOps controller | Kubernetes API | Outbound: list/watch Certificate and CertificateRequest; optional Secret `get`; owned Certificate create/patch in provision mode |
| cert-manager | Kubernetes API | In-cluster reconciliation of Certificate/CertificateRequest and TLS Secret resources |
| TokenTimer API | customer Kubernetes API | No connection |

When `networkPolicy.enabled` is also true,
`networkPolicy.egress.kubeApiServerCidrs` must list the Kubernetes API server
CIDRs. The controller policy permits DNS, Kubernetes API TCP 443, and either
the in-chart API Service or the explicit
`networkPolicy.egress.controllerApiCidrs`/`controllerApiPort` allow-list. It has
no ingress rule and grants no database, SMTP, or Pushgateway egress.

Use the Pod's `/healthz` endpoint for liveness and `/readyz` for readiness.
Readiness requires both Certificate watches, the CertificateRequest watches,
the observation reporter, and—in provision mode—the provisioning transport and
write adapter. Common failures are:

- invalid/expired token or missing scopes: rotate the mounted token and verify
  the exact mode scope set above;
- workspace/cluster mismatch: recreate the token with the intended immutable
  cluster binding and align Helm values;
- namespace-policy denial: add the namespace to `watchNamespaces` or explicitly
  choose cluster-wide mode, then verify rendered RBAC;
- missing cert-manager CRDs: install the pinned cert-manager version selected by
  the cluster operator before enabling the controller;
- public certificate unavailable: inspect cert-manager status first, then
  enable Secret fallback only if its security tradeoff is accepted;
- unmanaged-resource conflict: rename the desired Certificate or resolve the
  foreign owner manually; the controller will not adopt it;
- paused workspace: resume the workspace before creating/delivering new
  provisioning work;
- transient API failure: the bounded retry policy handles network errors,
  `408`, `429`, and `5xx`; permanent `4xx` responses require configuration
  correction.

Safe rollback is to disable the controller or switch from `provision` to
`observe`. Shutdown stops new work before waiting for bounded in-flight work.
Neither rollback path deletes Kubernetes resources.

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

When the optional CertOps controller is enabled, it is the only workload that
opts into a mounted Kubernetes ServiceAccount token. Its distinct identity has
the mode-specific least-privilege RBAC described above, with Secret `get` added
only when fallback is explicitly enabled.

## Upgrading

```bash
helm upgrade tokentimer oci://ghcr.io/tokentimerch/charts/tokentimer -f my-values.yaml -n tokentimer
```

CronJob spec changes apply on the next scheduled run (job pod template carries the same checksum annotations).

API and dashboard Deployments roll automatically when you `helm upgrade`:
- `checksum/config` and `checksum/secret` change when `tokentimer.config`, SMTP, Twilio, or DB-related values change
- `checksum/helm-release-revision` changes on every upgrade (picks up parent-chart-only ConfigMaps in umbrella charts such as enterprise SSO env)

Pods read ConfigMap/Secret env vars only at start; a rollout is required after changing `config.baseUrl`, `config.apiUrl`, or SSO env.

## Uninstalling

```bash
helm uninstall tokentimer -n tokentimer
```

CloudNativePG PVCs are retained by default. Delete them manually if no longer needed.

## Example Values

See the `examples/` directory:
- `values-minimal.yaml` -- single-node CNPG, no ingress (smallest viable install)
- `values-external-db.yaml` -- external PostgreSQL with ingress and monitoring
- `values-full-test.yaml` -- lab/Minikube with HPA, metrics, all workers enabled

## Environment Variables Reference

For the complete list of supported environment variables (auth, rate limiting, delivery windows, webhook security, integration allowlists, etc.), see the [configuration reference](../../docs/CONFIGURATION.md).

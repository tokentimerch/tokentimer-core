Prerequisites: Kubernetes 1.29+, Helm 3.14+, and access to a published Core chart. The commands use Bash.

# Install Core with Helm

The chart deploys the API and dashboard as Deployments, the workers as CronJobs, and PostgreSQL as a CloudNativePG `Cluster` by default (an existing external PostgreSQL is also supported). Optional resources (disabled by default): Ingress, HPA, PDB, ServiceMonitor, PrometheusRule, NetworkPolicy.

## Step 1 - Install the CloudNativePG operator (if using in-cluster PostgreSQL)

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

If you already have PostgreSQL, skip the operator and point the chart at your database:

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

## Step 2 - Install the chart

Select a published chart version and save it with your deployment configuration.

```bash
read -r -p 'Core chart version: ' CORE_CHART_VERSION
helm install tokentimer oci://ghcr.io/tokentimerch/charts/tokentimer \
  --namespace tokentimer --create-namespace \
  --version "$CORE_CHART_VERSION" \
  --set config.baseUrl="https://tokentimer.example.com" \
  --set config.apiUrl="https://tokentimer.example.com" \
  --set config.adminEmail="admin@your-company.com" \
  --set config.adminPassword="SecurePassword123!" \
  --set config.sessionSecret="replace-with-long-random-value" \
  --set postgresql.auth.password="your-db-password" \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host="tokentimer.your-domain.com"
```

For production, prefer a values file (`cp deploy/helm/values.yaml my-values.yaml`, edit, then `-f my-values.yaml`) and pre-existing Kubernetes Secrets instead of plaintext values:

```yaml
config:
  existingSecret: "my-tokentimer-secrets"  # see the note below for the required keys

postgresql:
  external:
    existingSecret: "my-db-secret"         # DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, DB_SSL

smtp:
  existingSecret: "my-smtp-secret"         # all SMTP_* + FROM_* keys
```

Two further variants exist:

- `postgresql.auth.existingSecret` supplies the credentials for the in-cluster CloudNativePG cluster. It must be of type `kubernetes.io/basic-auth` with `username` and `password` keys, and because it only feeds CNPG bootstrap you must **also** provide `DB_PASSWORD` to the app through `config.existingSecret`.
- `twilio.existingSecret` supplies the Twilio credentials and template SIDs.

Setting any `existingSecret` makes the chart stop emitting that group's generated keys entirely, so your Secret has to be complete for that group.

> **`config.existingSecret` replaces the whole generated Secret**
>
> Setting it makes the chart skip its entire generated Secret, not just `SESSION_SECRET`. Your own Secret must therefore carry every key the chart would have produced:
>
> | Key | When required |
> |---|---|
> | `SESSION_SECRET` | Always |
> | `CERTOPS_SIGNING_ENCRYPTION_KEY` | While CertOps is enabled (`config.certopsEnabled` defaults to `true`) |
> | `CERTOPS_REGISTRATION_ENCRYPTION_KEY` | While CertOps is enabled |
> | `ADMIN_PASSWORD` | When you bootstrap an admin with `config.adminEmail` |
> | `DB_PASSWORD` | Unless the password comes from `postgresql.auth.existingSecret` or `postgresql.external.existingSecret` |
>
> The CertOps pair is the easy one to miss: `CERTOPS_ENABLED` still renders as `"true"`, so the deployment comes up looking healthy and then fails closed on every agent register and job dispatch. Verify with `kubectl get secret my-tokentimer-secrets -n tokentimer -o jsonpath='{.data}'` before cutting over, or set `config.certopsEnabled=false` if you are not using CertOps.

> **Note**
>
> The chart auto-generates `SESSION_SECRET`, `DB_PASSWORD`, and `ADMIN_PASSWORD` (when `adminEmail` is set) if you do not provide them. Generated values are **preserved across `helm upgrade`**: the chart reads them back from the existing release Secret. Set explicit values or use `existingSecret` when you manage secrets externally, or when you render manifests with `helm template` (which cannot read the existing Secret back and therefore produces a new value on each render).

> **CertOps requires two encryption keys in Kubernetes too**
>
>
> `config.certopsEnabled` defaults to `true`, and the API **fails closed** without `CERTOPS_SIGNING_ENCRYPTION_KEY` and `CERTOPS_REGISTRATION_ENCRYPTION_KEY`: agent registration and signed job dispatch reject with `CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING` / `CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING`, so the CertOps UI appears but no agent can ever register.
>
> The chart generates both when unset and preserves them on upgrade like the secrets above. To set them explicitly:
>
> ```yaml
> config:
>   certopsSigningEncryptionKey: "<64 hex chars>"      # openssl rand -hex 32
>   certopsRegistrationEncryptionKey: "<64 hex chars>"
> ```
>
> Rotating either value makes the data it wrapped unreadable: signing keys must be re-issued and agents must re-register.

## Step 3 - Wait for pods and access the dashboard

```bash
kubectl get pods -n tokentimer -w
```

**You should see:** API and dashboard pods reach `Running`/`Ready`, and the PostgreSQL cluster become healthy.

Also confirm all six worker CronJobs exist, since a missing one fails silently (nothing crashes, the work just never runs):

```bash
kubectl get cronjobs -n tokentimer
```

**You should see** six entries: `tokentimer-alert-discovery`, `tokentimer-alert-delivery`, `tokentimer-weekly-digest`, `tokentimer-endpoint-check`, `tokentimer-auto-sync` and `tokentimer-certops`. If `tokentimer-certops` is absent, certificates never renew automatically and offline agents are never marked offline; re-check `worker.cronjobs.certops.enabled` (default `true`).

Open the configured HTTPS dashboard URL. For local diagnostics, use `kubectl port-forward svc/tokentimer-dashboard 8080:80 -n tokentimer` and open `http://localhost:8080`; the API also needs a reachable local URL for browser calls. See the [URL and cookie reference](CONFIGURATION.md).

If the admin password was auto-generated, retrieve it with:

```bash
kubectl get secret -n tokentimer tokentimer-secrets \
  -o go-template='{{index .data "ADMIN_PASSWORD" | base64decode}}{{println}}'
```

> **Warning**
>
> With `NODE_ENV=production`, the API sets the `Secure` flag on session cookies. Browsers will not persist or send secure cookies over plain HTTP. For anything beyond local port-forwarding, place HTTPS in front of the API and dashboard (Ingress with TLS or a reverse proxy).

<a id="first-login"></a>

## First login

TokenTimer creates the admin user automatically on first startup from `ADMIN_EMAIL` and `ADMIN_PASSWORD`.

1. Navigate to your dashboard URL and open the login page.
2. Log in with your configured `ADMIN_EMAIL` and `ADMIN_PASSWORD`.
3. **You should see** your default admin workspace.

> **Warning**
>
> After first login, remove `ADMIN_PASSWORD` from your `.env` file (or values). It is only needed for the bootstrap on first start.

Recommended next steps: invite team members (Workspace Settings, Members), add your first [token](https://tokentimer.ch/docs/self-hosted/tokens/index), configure alert thresholds and channels in [Expiry reminders and thresholds](https://tokentimer.ch/docs/self-hosted/alerts/index), and configure SMTP (via System Settings UI or [env vars](CONFIGURATION.md)).

Continue with [First asset and alert check](FIRST_ASSET.md). Optional network policy, monitoring, and scaling are covered in [Kubernetes operations](KUBERNETES_OPERATIONS.md).

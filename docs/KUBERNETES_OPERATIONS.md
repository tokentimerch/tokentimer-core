Start after [installing with Helm](INSTALL_HELM.md). Enable one optional component at a time and verify its effect.

# Kubernetes operations

These are all disabled by default. Each needs more than its `enabled` flag to behave the way you would expect.

### NetworkPolicy

`networkPolicy.enabled=true` installs a default-deny posture. It does **not** infer where your traffic comes from, so the namespaces must be named explicitly or the matching inbound rule is simply not emitted:

```yaml
networkPolicy:
  enabled: true
  ingressNamespace: "ingress-nginx"   # without this, no ingress-controller traffic reaches the API
  monitoringNamespace: "monitoring"   # without this, Prometheus cannot scrape /metrics
  egress:
    smtpCidrs: ["0.0.0.0/0"]          # ports 25/465/587 from api and worker pods
    httpsCidrs: ["0.0.0.0/0"]         # port 443: OAuth/SAML, integrations, webhooks
    kubeApiServerCidrs: []            # required when the CertOps controller is enabled
```

Egress CIDRs default to `0.0.0.0/0` to preserve out-of-the-box behavior; narrow them to your real endpoints, or set a list to `[]` to disable that protocol's egress entirely.

> **Warning**
>
> Leaving `ingressNamespace` empty renders the API policy with `ingress: []`, which means the Ingress controller cannot reach the API and the app appears down even though every pod is `Ready`.

### Autoscaling and pod disruption budgets

```yaml
api:
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 5
    targetCPUUtilizationPercentage: 80
  podDisruptionBudget:
    enabled: true
    minAvailable: 1      # maxUnavailable takes precedence if you set both
```

### ServiceMonitor

Enabling it is not enough on its own: kube-prometheus-stack only selects ServiceMonitors carrying the release label it was configured to match, so set `labels` as well.

```yaml
monitoring:
  serviceMonitor:
    enabled: true
    labels:
      release: kube-prometheus-stack   # must match your Prometheus serviceMonitorSelector
    interval: 30s
```

### Pinning images (private registries, air-gapped, reproducible deploys)

Image tags default to the chart's `appVersion`. For a mirrored registry or a byte-for-byte reproducible deploy:

```yaml
global:
  imageRegistry: "registry.internal.example.com"
  imagePullSecrets:
    - name: my-registry-credentials

api:
  image:
    digest: "sha256:..."   # takes precedence over tag; from the release manifest
```

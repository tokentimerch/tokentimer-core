<p align="center">
  <a href="https://tokentimer.ch"><img src="docs/assets/logo.svg" alt="TokenTimer" width="120" /></a>
</p>

<h3 align="center">The token, certificate, license, and secret expiration manager for teams.</h3>

<p align="center">
  <b>
  <a href="#introducing-tokentimer">Introducing</a> &bull;
  <a href="#get-started">Get Started</a> &bull;
  <a href="#documentation">Docs</a> &bull;
  <a href="#contributing">Contributing</a> &bull;
  <a href="#reporting-a-security-issue">Security</a> &bull;
  <a href="#license">License</a>
  </b>
</p>

<br>

---

<br>

# Introducing TokenTimer

Operational incidents caused by expired assets are still a recurring problem. Certificates expire, API keys get rotated, secrets are forgotten, and renewal ownership is often unclear. Most systems expose expiration data inconsistently, offer limited notification support, and lack a centralized cross-provider view.

TokenTimer is a security-first expiration manager that aggregates expiring assets across providers and environments into one place. It helps teams monitor certificates, tokens, secrets, licenses, subscriptions, and other time-bound assets through configurable multi-channel alerting and team collaboration workflows.

**What makes TokenTimer different?**

- **Unified expiration visibility:** Track certificates, tokens, secrets, licenses, subscriptions, and other expiring assets across providers and environments in one place.
- **Flexible multi-channel alerting:** Notify teams through email, Slack, Microsoft Teams, Discord, PagerDuty, WhatsApp, and webhooks, with configurable delivery and escalation options.
- **Native integrations, auto-sync, and automated discovery:** Connect TokenTimer to providers like HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Azure AD, GCP Secret Manager, GitHub, and GitLab to automatically import and keep expiration metadata up to date, discover public subdomains for SSL certificate imports, and monitor HTTPS endpoints for SSL expiry and health.
- **Certificate operations (CertOps):** Maintain a managed-certificate inventory linked to your tokens, import public certificates, and retire certificates without losing history. Automate renewals end to end with the outbound-only TokenTimer Agent (ACME via certbot/acme.sh, DNS-01 across major providers, atomic deploy with rollback, service reload, and post-deploy verification), observe rotations via endpoint monitoring or a cert-manager controller integration, or report from your own executors and CI hooks with a machine API token. Approval gates, a workspace kill switch, and renewal-failure alerts keep humans in control. The control plane never receives or stores private key material.
- **Built for teams and audits** ([demo](docs/assets/dashboard-overview.gif)): Organize assets with workspaces, control access with RBAC, and keep an audit trail of important actions and alert activity.
- **Security-first by design:** TokenTimer stores expiration metadata, ownership, and status information without storing secret values or private keys. Integration scan credentials are discarded after one-off imports; if you enable auto-sync, they are encrypted at rest in the database for scheduled re-scans.

<p align="center">
  <img src="docs/assets/dashboard-workflow.gif" alt="Import, subdomain discovery, and dashboard filtering in TokenTimer" width="800" />
</p>

<br>

---

<br>

# Get Started

| [![TokenTimer Cloud](docs/assets/readme/tokentimer-cloud-cta.svg)](https://tokentimer.ch) | [![TokenTimer Enterprise](docs/assets/readme/tokentimer-enterprise-cta.svg)](https://tokentimer.ch/pricing) | [![TokenTimer Core](docs/assets/readme/tokentimer-core-cta.svg)](QUICKSTART.md) |
|:---:|:---:|:---:|

### Run it on your own server

| [![Docker Compose](docs/assets/readme/docker-icon.svg)](QUICKSTART.md#option-1-docker-compose-fastest) | [![Kubernetes / Helm](docs/assets/readme/kubernetes-icon.svg)](QUICKSTART.md#option-3-kubernetes-helm) | [![Local Development](docs/assets/readme/local-dev-icon.svg)](QUICKSTART.md#option-2-local-development) |
|:--:|:--:|:--:|

<br>

# Documentation

| | |
|---|---|
| [QUICKSTART.md](QUICKSTART.md) | Step-by-step setup guide |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Local development, worker runner, and cron scheduling |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Full environment variables reference |
| [docs/certops/CONTEXT.md](docs/certops/CONTEXT.md) | Certificate operations (CertOps) domain model and behavior |
| [docs/certops/agent.md](docs/certops/agent.md) | TokenTimer Agent: install, config, policy, DNS-01 providers, ACME, deploy, and verification |
| [docs/certops/executor-api.md](docs/certops/executor-api.md) | Machine API tokens and executor job API for external renewal tooling |
| [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) | Auth model, admin bootstrap, invitations, RBAC |
| [deploy/helm/README.md](deploy/helm/README.md) | Helm chart installation and configuration |
| [apps/worker/queue-architecture.md](apps/worker/queue-architecture.md) | Alert queue and worker design |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |
| [ROADMAP.md](ROADMAP.md) | Engineering roadmap and metrics |
| [https://tokentimer.ch/docs](https://tokentimer.ch/docs) | Online user docs (self-hosted and cloud; Certificates at [/docs/certificates](https://tokentimer.ch/docs/certificates)) |

**Worker deployment:** Docker Compose runs one worker type per container. The
worker image default command runs all workers in one process (`runner.js all`).
See [DEVELOPMENT.md](DEVELOPMENT.md) for scheduling, timezones, and observability.

<br>

# Contributing

We welcome contributions. Start by reading the documentation above and exploring the codebase. Join the discussions on [GitHub Issues](https://github.com/tokentimerch/tokentimer-core/issues) for feature requests, bug reports, and questions.

<br>

# Reporting a security issue

If you've found a security-related issue with TokenTimer, please email [support@tokentimer.ch](mailto:support@tokentimer.ch). Submitting to GitHub makes the vulnerability public, making it easy to exploit. We'll do a public disclosure of the security issue once it's been fixed.

After receiving a report, TokenTimer will take the following steps:

- Confirmation that the issue has been received and that it's in the process of being addressed.
- Attempt to reproduce the problem and confirm the vulnerability.
- Prepare a patch/fix and associated automated tests.
- Release a new version of all affected versions.
- Prominently announce the problem in the release notes.
- If requested, give credit to the reporter.

<br>

# License

This project is licensed under the [Business Source License 1.1](LICENSE) with an Additional Use Grant that permits production use for your organization's internal purposes. You may self-host, modify, and integrate TokenTimer freely. The only restriction is offering it as a competing hosted or managed service.

Each release converts to [AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html) four years after its publication date.

For commercial licensing or questions, contact [support@tokentimer.ch](mailto:support@tokentimer.ch).

"TokenTimer" is a trademark of Tokentimer Sàrl, Switzerland.

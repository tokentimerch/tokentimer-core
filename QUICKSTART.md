# TokenTimer Core — Quick start

Install Core, sign in, and check one harmless asset reminder. Choose a deployment method; integrations and certificate automation can follow once the basic notification path works.

## Choose an installation

- [Docker Compose](docs/INSTALL_COMPOSE.md): released images on one host. Requires Git, Docker, and Docker Compose.
- [Kubernetes with Helm](docs/INSTALL_HELM.md): a cluster with in-cluster or external PostgreSQL. Requires Kubernetes 1.29+ and Helm 3.14+.
- [Local development](DEVELOPMENT.md): run from source to contribute or debug.

## After sign-in

Follow [First asset and alert check](docs/FIRST_ASSET.md): test SMTP, select recipients, create a sample expiring tomorrow, and confirm both delivery history and the inbox. A healthy API does not prove email delivery.

An asset is metadata. Do not store the real API key, password, or certificate private key in its fields.

## When you need more

[Configuration basics](docs/CONFIGURATION_BASICS.md) · [Variable reference](docs/CONFIGURATION.md) · [Backup and restore](docs/BACKUP_RESTORE.md) · [Upgrade](docs/UPGRADE.md) · [Authentication and roles](docs/AUTHENTICATION.md)

For certificate issuance and renewal, start with the [agent overview](docs/certops/agent.md).

## Previous quickstart sections

<a id="tokentimer-core---quick-start-guide"></a>
<a id="prerequisites"></a>
<a id="option-1-docker-compose-fastest"></a>
<a id="1-clone-and-configure"></a>
<a id="2-edit-env"></a>
<a id="3-start-all-services"></a>
<a id="4-access-the-dashboard"></a>
<a id="5-check-status"></a>
<a id="option-2-local-development"></a>
<a id="1-install-dependencies"></a>
<a id="2-configure-environment"></a>
<a id="3-start-development-servers"></a>
<a id="4-access-the-dashboard-1"></a>
<a id="option-3-kubernetes-helm"></a>
<a id="1-install-the-helm-chart"></a>
<a id="2-wait-for-pods"></a>
<a id="3-access-dashboard"></a>
<a id="first-steps-after-installation"></a>
<a id="1-login-as-admin"></a>
<a id="2-invite-team-members-optional"></a>
<a id="3-add-your-first-token"></a>
<a id="4-configure-alerts"></a>
<a id="5-test-alerts"></a>
<a id="troubleshooting"></a>
<a id="api-wont-start"></a>
<a id="worker-not-sending-alerts"></a>
<a id="dashboard-shows-errors"></a>
<a id="login-returns-401-on-localhost-in-production-mode"></a>
<a id="configuration-reference"></a>
<a id="minimum-required-variables-docker-compose"></a>
<a id="health-checks"></a>
<a id="api-health"></a>
<a id="database-health"></a>
<a id="backup-and-restore"></a>
<a id="backup-database"></a>
<a id="restore-database"></a>
<a id="upgrading"></a>
<a id="docker-compose"></a>
<a id="kubernetes"></a>
<a id="uninstalling"></a>
<a id="docker-compose-1"></a>
<a id="kubernetes-1"></a>
<a id="getting-help"></a>
<a id="next-steps"></a>
The complete installation sequence is now in [Compose](docs/INSTALL_COMPOSE.md) or [Helm](docs/INSTALL_HELM.md). Source development is in [DEVELOPMENT.md](DEVELOPMENT.md); first login and alert checks are in [First asset](docs/FIRST_ASSET.md); recovery and version changes are in [Backup](docs/BACKUP_RESTORE.md) and [Upgrade](docs/UPGRADE.md).

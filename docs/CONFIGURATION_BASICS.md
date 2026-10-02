# Configuration basics

Start with a working [Compose](INSTALL_COMPOSE.md) or [Helm](INSTALL_HELM.md) deployment. You need **system administrator** access to System Settings; workspace Admin and Workspace Manager roles do not grant it.

## Where to change a setting

Compose reads deployment values from `.env`; Helm renders them from chart values and Kubernetes Secrets. The System Settings UI stores selected settings in the database.

- SMTP and Twilio fields supplied by the environment override database values and are locked in the UI. Change their deployment configuration to unlock or replace them.
- Workspace alert thresholds and delivery windows override deployment defaults for that workspace. A contact group can override thresholds again for its own recipients.
- Admin bootstrap is controlled by deployment variables. Remove the bootstrap password after verifying the account; this does not delete the account.

Defaults and precedence vary by setting. Consult the [complete variable reference](CONFIGURATION.md) when changing an unfamiliar field.

<a id="smtp"></a>

## Set up email first

Configure `SMTP_HOST`, `SMTP_PORT`, the server's authentication requirements (`SMTP_USER` and `SMTP_PASS` when required), and sender identity (`FROM_EMAIL`, `FROM_EMAIL_NAME`). Match `SMTP_SECURE` and TLS requirements to your mail server; do not guess encryption from a copied port number.

Use the System Settings SMTP test and check the receiving inbox. Then follow [First asset and alert check](FIRST_ASSET.md) to verify recipients, thresholds, scheduling, and delivery. SMTP transport alone does not prove asset routing.

See the [SMTP reference](CONFIGURATION.md) for all fields. WhatsApp provider setup is a separate [operator guide](https://tokentimer.ch/docs/self-hosted/runbooks/whatsapp-provider).

<a id="restart"></a>

## Apply environment changes

Environment values are loaded at process startup. After changing Compose `.env`, recreate the affected API and worker services using the same files and image selection as the installation. `docker compose restart` does not reload a changed `.env` into an existing container. Use the install command with `up -d` (and `--no-build` for released Core images).

For Helm, update your values or managed Secret and run `helm upgrade` with the same pinned chart version. Chart-managed configuration changes can trigger Deployment rollouts. Updating an external Secret or ConfigMap alone does not restart existing pods: roll out affected Deployments, and confirm subsequent worker Jobs use the new environment.

## Preserve recovery keys

Keep `SESSION_SECRET` stable: it protects sessions and derives the key used to encrypt stored settings. CertOps has separate signing and registration wrapping keys. Enterprise also has an SSO secrets keyring. Back up these alongside the database and matching deployment version.

Key rotation is an operation with its own recovery requirements. Do not generate replacement keys during an ordinary upgrade or restore. See [Backup and restore](BACKUP_RESTORE.md) and the [advanced reference](CONFIGURATION.md).

# Operator walkthroughs

Start in **Set up TokenTimer** (`/onboarding` on your dashboard). Choose the
workspace first, then the goal that matches your task. The setup wizard uses
the same inventory, recipients, agents, and jobs as the rest of the dashboard;
continue with those records instead of creating a second setup. Its step-level
documentation links provide the detailed settings for the selected workflow.

These written procedures are the required operator path. A completed setup
screen proves only the checks it explicitly reports: generated configuration
does not prove a working deployment, and a staging order does not prove a
production certificate is trusted.

## Install, configure, and upgrade

Install the control plane with [Compose](INSTALL_COMPOSE.md) or
[Helm](INSTALL_HELM.md), then sign in with your bootstrap administrator.
Prepare SMTP and restart changed services using
[Configuration basics](CONFIGURATION_BASICS.md). For individual environment
variables, use the [configuration reference](CONFIGURATION.md).

For upgrades, follow [Upgrade Core](UPGRADE.md) and preserve a matching
[database, configuration, and secrets backup](BACKUP_RESTORE.md). Agents have
their own [upgrade ordering and state-preservation requirements](certops/agent/operations.md#upgrade-and-uninstall).
Check compatibility and a fresh heartbeat after upgrading, then repeat a
signed dry run before resuming real execution. Reverting container images
alone does not reverse migrations or recover lost agent state.

## Monitor a service and prove notification delivery

1. In the setup wizard, choose HTTPS monitoring and enter an endpoint you are
   authorized to monitor. Follow the endpoint step and inspect its resulting
   certificate and latest check. A saved URL alone is not a successful check.
2. Follow the recipient steps in the same wizard. Select an existing contact
   group or configure recipients and channels. Check the workspace default
   and effective thresholds before saving. Empty explicit group selections
   inherit the workspace default; they do not mean notifications are disabled.
   In an asset, certificate, endpoint, or agent form, open **Contact groups**
   and choose **Add new group**. The same **New contact group** modal used in
   Alert Preferences opens. Enter a group name, choose **Contacts and channels**,
   and configure **Webhook channels (unlimited)**, **Threshold override**, and
   **Weekly Digest** as needed, then choose **Save group**. The new group is selected
   automatically; a multiple-group field retains its existing selections.
   When opened from a selection field, this modal also offers **Add contact**.
   Use the existing contact form to enter the person's details; a new contact
   with a valid email is checked in the group draft automatically. The contact
   is saved to the workspace immediately, even if you later cancel the group.
   Group membership still requires **Save group**, and assignment requires
   saving the parent form. This shortcut is not shown inside the group modal
   in workspace preferences, where the Contacts section already provides it.
   Your unfinished form stays open with its entered data. **Cancel** or a failed
   save leaves its original selection unchanged. Creation requires a workspace
   manager or administrator; if a group or recipient limit prevents saving,
   follow the displayed instructions and retry or use an existing group.
   The existing workspace default is retained; when the workspace has no
   default, the first group becomes its default using the existing preferences
   behavior. Save the parent form to assign its new selection.
3. For self-hosted email, have a system administrator configure SMTP and send
   the wizard's SMTP test. Environment-managed values must be changed in the
   deployment. Confirm receipt in the inbox.
4. Complete [First asset and alert check](FIRST_ASSET.md) to prove the full
   scheduled notification path. The SMTP test verifies transport; it does
   not prove a monitor or asset has reached an alert threshold.

If an endpoint check fails, inspect the endpoint's latest result and confirm
DNS, connectivity, port, certificate chain, and the requested hostname from
the monitoring environment. Monitoring observes expiry; agent automation is
a separate goal and requires a host that can access the certificate's key.

## Install an agent and issue a first certificate

Use a disposable hostname and target for the first issuance. The wizard's
ACME path uses the Let's Encrypt **staging** CA; its certificates are not
trusted by normal browsers.

1. Choose the certificate automation goal and the supported infrastructure in
   the wizard. Prepare the generated local configuration on the target host
   before registration, including certificate names, DNS zone and provider,
   allowed commands, paths, and CA endpoints. Keep DNS credentials on that host.
2. Follow [Linux installation](certops/agent/install-linux.md) or
   [Windows installation](certops/agent/install-windows.md). Verify the released
   package and runtime requirements, then use the workspace bootstrap token.
   Check the service and a fresh heartbeat in the agent fleet. Registration
   alone does not mean execution is enabled or compatible.
   In **Agent for this setup**, choose the eligible host for the intended
   platform, command profile, and target. This choice stays pinned for the test
   and issuance; another healthy host does not silently replace it. If the
   selected agent becomes unavailable or incompatible, correct its readiness
   or return to this step to deliberately choose another eligible host.
3. Set `execution.enabled: true` and retain `execution.dryRun: true` while
   testing. Restart the service. Request the wizard's signed dry run and
   approve it if required. Wait for `dry_run_complete`; neither `pending`
   nor a healthy heartbeat proves the dry run completed.
   The execution step refreshes readiness and test status every five seconds;
   use **Check again** after a configuration change or service restart.
   **Open test job details** shows the actual job, error, timeline, and evidence.
   After correcting the cause of a **failed**, **blocked**, **rejected**, or
   **cancelled** test, use **Retry test job** when offered. This creates a fresh
   attempt only for the wizard's dry-run `noop` test. An uncertain outcome or
   required operator reconciliation has no retry action: investigate and
   reconcile first. These instructions do not authorize repeating real work.
4. Inspect the plan and [local policy](certops/agent/configuration.md). Set
   `execution.dryRun: false` and restart only when the intended target is ready
   for changes. Request the staging certificate in the wizard. If approval is
   required, open **Certificate Management → Jobs** with an authorized
   approver, review the target and operation, and approve the actual job.
5. Wait for a successful real job and inspect its evidence. On Linux, check
   the chosen certificate path and service verification; on Windows, check
   the intended IIS binding. Inspect the resulting certificate in inventory.
   Before production use, change the CA and its local allowlist deliberately
   and verify the production hostname and trust chain from the client side.

For ongoing renewal, open **Certificate Management → Renewals**, review the
certificate's renewal profile, agent assignment, schedule, and approval policy.
Ensure the CertOps worker is running with CertOps enabled. Check an actual
renewal's terminal result and deployment evidence; observing a certificate
or preparing a profile does not prove automatic renewal works.
See [DNS and ACME](certops/agent/dns-and-acme.md) for provider setup.

## AD CS and IIS

Choose the AD CS goal in the wizard and use a domain-joined Windows host.
Prepare the local CA/template enrollment rule before registration; restart
an already installed agent after changing the rule so its capabilities are
reported. Follow [AD CS enrollment](certops/agent/adcs.md) for service-account
permissions, CA connectivity, template restrictions, and asynchronous requests.

Continue in **Certificate Management → Renewals → AD CS issuers** to create
and check the issuer and pin its CA certificate, then create the AD CS renewal
profile for the intended IIS site and certificate name. Attach the profile
to the certificate and inspect the first enrollment's real result there.
The wizard prepares and checks prerequisites; it cannot verify enrollment
against your CA. Keep the setup a candidate until enrollment and the IIS
binding have been verified on that host. Review
[Windows runtime and retention](certops/agent/windows-runtime.md) before
changing stores, bindings, or retained keys.

## Read certificate details

**Certificate identity** describes one exact public certificate: serial, public-key
algorithm, signature, names and SHA-256 fingerprint. Renewal normally produces a
new identity even when the DNS names stay the same. Use **Management source** to
choose the source whose **Renewal and key custody** settings you need to inspect.
That selection controls the management and deployment context, not the immutable
certificate facts. An observed copy proves a sighting; it does not prove that a
service uses it. Publication of a candidate is separate from verified deployment
on a destination. Follow the relevant job and compare the served certificate's
fingerprint to verify what the service actually uses.

## Investigate a job, retry, or recover

1. Open **Certificate Management → Jobs** and select the job. Record its ID,
   operation, mode, certificate, assigned agent, status, timestamps, timeline,
   error code, and evidence. Check whether it is a preview or real execution.
2. **Pending approval:** obtain an authorized decision after reviewing the
   target. **Pending:** check the assigned agent, execution setting, matching
   capabilities/selectors, compatibility, and heartbeat. A different healthy
   agent does not satisfy an explicitly assigned job.
3. **Claimed or running:** inspect progress and agent logs before submitting
   another job. On Linux use `journalctl -u tokentimer-agent -n 100 --no-pager`;
   use the Windows service/log guidance in the
   [Windows installation guide](certops/agent/install-windows.md).
4. **Rejected or failed:** use the error and evidence to fix the cause before
   requesting new work. Local allowlist failures require a host configuration
   change; clock errors require checking time synchronization. For a missing
   result, inspect the local outbox and connectivity before assuming execution
   failed. See [agent troubleshooting](certops/agent/operations.md#troubleshooting).
5. **Cancelled:** check the timeline and host evidence. Cancellation is not
   proof that an in-flight external operation was undone. Verify the served
   certificate and target before submitting replacement work.
6. **Needs review / `orphaned_unknown_effect`:** stop retries for the affected
   certificate and target. Inspect the live files, IIS binding, and recovery
   journal; reconcile the actual host state before requesting work. There is
   no general dashboard action for clearing this flag: preserve evidence and
   obtain support for the affected recovery path. Do not edit database flags
   or remove journals to bypass it. Follow [execution and crash recovery](certops/agent/execution.md).

If retiring an agent is blocked by active leases, normally wait for the jobs
to finish. **Force retire** requires a reason and immediately cancels claimed
jobs; running jobs become **Needs review / `orphaned_unknown_effect`** because
the host may already have changed. Retirement neither undoes those changes nor
automatically moves the jobs to another agent. Use **Review jobs** in the
retirement dialog and the [retirement recovery runbook](certops/agent/operations.md#forced-agent-retirement-and-in-flight-work).
Reconcile the actual certificate and target before requesting replacement work
through its original workflow. A replacement agent alone does not resolve
uncertain effects or recover a missing private key.

After a correction, request again through the workflow that created the job
and follow the new job to its terminal result. Do not equate an accepted request
with successful recovery. Keep a redacted job ID, timeline, and relevant logs
when seeking support; never include private keys, bootstrap tokens, DNS/Vault
credentials, or unredacted configuration.

## First-use acceptance and optional videos

Have an operator unfamiliar with the implementation follow the monitoring,
staging issuance, and failed-job investigation procedures above without
developer assistance. For each task, record the release, platform, starting
permissions, expected and observed result, hesitation point, help requested,
and whether the operator could name the next action. Record unexecuted paths
as unverified; a document review or automated test does not replace this check.

Installation, upgrades, first use, recovery, and troubleshooting must remain
complete in writing before v1. Videos are optional supplements. Prioritize
stable walkthroughs of agent setup, issuance and renewal, AD CS/IIS, contact
groups and SMTP, and job troubleshooting. Start recordings in the same setup
wizard and use the same verification outcomes as these written procedures.
Re-record only after labels and behavior are stable; an absent video must
never block an operator from completing a supported task.

**AD CS release qualification:** the current 0.18.0 candidate agent omits `adcs-enroll-v1` from its production qualification manifest. Local enrollment configuration does not make these jobs claimable. Use the AD CS reference for the required independently qualified Windows artifact; do not treat the setup wizard or unit tests as that qualification.

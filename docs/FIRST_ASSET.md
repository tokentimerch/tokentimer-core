
# First asset and alert check

After installation, create a harmless sample and check that its reminder reaches your inbox. This workflow verifies both inventory and notification routing.

## Before you start

- Sign in to your deployment with the administrator account created at first startup. Open your own dashboard URL, not the Cloud sign-in page.
- Have an email inbox you can inspect. Self-hosted email requires working SMTP; the installation does not provide a mail service.

An **asset**, called a **token** in TokenTimer, is a metadata record. Do not paste the real API key, password, or certificate private key into it. A **workspace** contains the assets, members, recipients, and alert settings for a team. A **contact group** chooses recipients and channels; it can also override alert thresholds.

## 1. Check email delivery

As a system administrator, configure SMTP in **System Settings** or through deployment environment variables. Use the SMTP test action and confirm that the test message arrives. Values supplied through environment variables are locked in the UI; edit the deployment configuration to change them. See [Configuration basics](CONFIGURATION_BASICS.md) for SMTP settings.

A successful SMTP test checks transport only. The asset check below verifies workspace routing, thresholds, and worker delivery as well.

## 2. Choose recipients

In your workspace alert settings:

1. Add a workspace contact with your email address.
2. Add that contact to a contact group and enable its email channel.
3. Select that group as the workspace default. If a suitable default already exists, use it.
4. Review the threshold days and delivery window. Ensure `1` is a threshold for this check and that the window includes the time you expect delivery. Save the settings.

Threshold `1` means one day before expiry; `0` means the expiry day. See [Contact groups & channels](https://tokentimer.ch/docs/self-hosted/alerts/contact-groups) and [Expiry reminders and thresholds](https://tokentimer.ch/docs/self-hosted/alerts/index).

## 3. Create a sample asset

1. Open **Asset Inventory** and click **Create New Token** (the plus icon).
2. Enter **Documentation expiry check** as the name, **General** as the category, and **Other** as the type.
3. Set the expiration date to tomorrow. Leave **Contact groups (alerts)** empty to use the workspace default you checked above.
4. Click **Create Token**.

**Expected result:** the asset appears in the inventory with tomorrow's date. Open **Details → Alerting and alert history** to inspect eligibility and upcoming thresholds.

## 4. Verify an alert

Saving an asset does not send an alert immediately. The discovery worker queues eligible alerts; the delivery worker sends them during the workspace delivery window. Default discovery and delivery schedules run about every five minutes; deferred or retried deliveries can take longer. See [Expiry reminders and thresholds](https://tokentimer.ch/docs/self-hosted/alerts/delivery#delivery-window).

Open **Control Center → Workspace alerting**. **Eligibility** explains whether a threshold is due; **Queue** and **Activity** explain delivery after it is queued. Check the sample asset's own alert history too.

**Success:** history records a successful delivery and the email reaches your inbox. A healthy API, a due asset, or a pending queue row alone is not an end-to-end result.

If it does not arrive:

1. Confirm the correct workspace, tomorrow's expiry, and a `1` threshold on the effective contact group.
2. Confirm that the default group includes your email and its email channel is enabled.
3. Check the delivery window and its timezone.
4. Repeat the SMTP test; inspect spam filtering and the configured sender.
5. Check discovery and delivery workers. In the Compose directory, run `docker compose logs --tail 100 worker-discovery worker-delivery`. In Kubernetes, inspect the corresponding CronJobs and their latest Jobs. Avoid sharing unredacted logs or environment values.

No new alert is expected when the same threshold has already been delivered. File and provider imports also suppress thresholds that have already passed; use a manually created sample for this check. For more detail, see [Expiry reminders and thresholds](https://tokentimer.ch/docs/self-hosted/alerts/delivery#control-center).

## Continue

Keep or delete the sample after the check. Then [import an existing inventory](https://tokentimer.ch/docs/self-hosted/tokens/import-file), [connect an integration](https://tokentimer.ch/docs/self-hosted/integrations/index), or [monitor an HTTPS endpoint](https://tokentimer.ch/docs/self-hosted/monitoring/endpoint-monitoring).

Tracking a certificate's expiry does not configure renewal. Set up [certificate automation](https://tokentimer.ch/docs/self-hosted/automation) separately when you are ready to manage issuance and renewal.

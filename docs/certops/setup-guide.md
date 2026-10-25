# Use the setup guide

Keep one workspace selected while configuring and verifying your first result. Use a workspace administrator for the full configuration workflow; certificate tasks also require access to their target hosts and CA/DNS services.

## Open the guide

Use **Preferences → Setup guide → Open setup guide**. For certificate work, use **Certificate Management → Settings → CertOps quickstart**. Choose assets, alerts or certificate management, then the result you need. Existing work can be continued instead of recreated.

Core and Enterprise share the host workflow. Cloud 0.18 uses the wizard with hosted plan/delivery rules: platform SMTP and workers are managed by the service, and provider imports are one-time rather than scheduled.

## First asset and alert route

1. Choose **Monitor a website certificate**, enter a reachable HTTPS URL and the offered monitoring options, then inspect the returned certificate expiration. You can instead enter asset metadata or import a file/service scan.
2. Select the intended contact group. Creating a group makes it available; selecting it assigns the asset's route.
3. Review thresholds, delivery window and timezone. Positive days are before expiry, zero is expiry day and negative days are after expiry. Group overrides apply where configured.
4. Finish, reload inventory/monitoring in the same workspace and find the saved records. Then follow the first-asset email check supplied with your installation. A saved route or eligible alert does not prove delivery to an inbox.

## Certificate setup

1. Prepare the existing service and local policy. Install/register an agent or choose **My agent is already set up**. Merge into existing config and preserve its enrolled identity, credentials and custody state.
2. Run the signed no-op smoke check with execution enabled and local dry-run protection on. It checks dispatch/reporting, not later issuance permissions or external effects.
3. Complete the issuer-specific prerequisites. AD CS needs a real read-only CA/template check, independent CA-key confirmation, pinning and a fresh post-pin check on the same agent.
4. Deliberately allow real mutating execution only when ready for issuance/enrollment/deployment. Restart only the agent, then continue the same saved guide.
5. Follow the operation's evidence and verify the [certificate actually served](verify-live-service.md). A completed form or job is not proof that a listener uses the replacement.

Continue with [Linux](agent/install-linux.md), [Windows/IIS](agent/install-windows.md), [Microsoft AD CS](agent/adcs.md#operator-sequence) or [Vault distribution](vault-first-distribution.md). The AD CS post-pin check currently uses **Renewals → issuer → Check again**; the guide's own refresh does not dispatch it. Vault consumer assignment and rollout use the supported API handoff. Trust anchors use **Agents → Trust anchors**, not a separate onboarding goal.

## Start again

**Preferences → Setup guide → Start over** resets progress, not inventory or job history. For a new distribution, leave existing-distribution reuse off. Reusing an earlier verified distribution is a separate explicit choice; an idempotent replay can return an older job rather than create fresh work.

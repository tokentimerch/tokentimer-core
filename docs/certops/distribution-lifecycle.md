# Certificate distribution

Use Distribution to publish a certificate to a customer-controlled store, deploy its exact version to registered consumers and track whether each service uses it. Private keys and store credentials remain on customer systems.

## Before you start

Use matching API, worker and agent versions. Follow [Set up certificate distribution](vault-first-distribution.md) to register agents, configure local store and deployment profiles, and explicitly choose shared-key mode. Vault and OpenBao KV v2 support Linux distribution. Azure Key Vault material storage, shared Windows/IIS material deployment, independent Linux staging and exact-version Vault/OpenBao cleanup require separately qualified capabilities and remain disabled. Existing Windows certificate automation is unaffected.

## Configure consumers and rollout

Open **Certificate Management → Distribution**, or select **Manage distribution** from a certificate's Deployments view. Add consumers using registered agents and customer-local deployment-profile aliases. Mark each consumer required or optional and configure its wave, activation method and verification policy. Disabling a binding does not release its agent/profile alias. A binding cannot be reassigned while its previous destination has live or uncertain work.

Select a published version and request a rollout. Reviewers approve the exact version, consumer scope and policy in Jobs when required. Manual distribution is the default; approval requests and reviewed automatic distribution require explicit configuration. A change to the authorized scope, relevant membership or policy can require a new independent review.

## Maintenance and activation

Configure a consumer's maintenance calendar with its IANA time zone, allowed windows and blackouts. Blackouts take precedence; disruptive activation waits for an allowed window. Supported Linux targets can install files and use an approved local reload profile; unsupported service actions remain unavailable. An administrator may request a scoped, time-limited emergency exception that still requires rollout approval.

Independent Linux preparation, when separately qualified, stages material before activation without changing the destination or proving service use. Activation remains a separate authorized job and requires unchanged scope, intact staged material and an open window. Windows independent staging is unavailable.

## Verify and monitor

Published, installed, served and trusted are different states. Select each consumer's required assurance and freshness policy. Recurring verification and incidents are off by default; enable them deliberately and configure eligible notification recipients. A new source publication does not prove consumers have converged. Required failures and stale canary evidence can pause a rollout; inspect Jobs and explicitly resume when safe.

Distribution PagerDuty recovery targets each integration that accepted the original alert, even if contact groups change. If an endpoint or routing key is removed or rotated, restore the original configuration to deliver recovery, or resolve the incident in PagerDuty. Recovery waits while distribution incident alerts are disabled. If a trigger response is lost, recovery still targets its original integration without assuming acceptance. Failed recovery retries continue with backoff. Legacy blocked alerts with failures in other channels may need manual review, even if only webhooks remain in the retry list. See [PagerDuty incidents](../PAGERDUTY.md).

Discovery reports observed relationships and coverage. A certificate found in a machine store is not proof that a service uses it.

## Discovery and recovery

Use preflight to check current prerequisites without deploying material. For uncertain work, request a separately approved read-only reconciliation before changing the consumer or starting another rollout. The original agent must still have the original local authorization and exact protected journal and installation proof; missing or replaced proof remains unresolved. An inspection can settle an older obligation after a previous edit or rollout, but does not change the original outcome or establish current consumer verification. If its approval becomes stale, request a new inspection and approval.

## Retention

Retention starts in report-only mode. Preview the protection reasons before requesting any action. Referenced, uncertain and rollback-protected versions remain protected. Exact-version Vault/OpenBao soft deletion requires a qualified cleanup capability, explicit local and group opt-ins and independent approval; it does not destroy versions, delete metadata or purge a store. See [Retention and cleanup](distribution-retention-cleanup.md).

For upgrade precautions, see [Migration compatibility](distribution-compatibility.md).

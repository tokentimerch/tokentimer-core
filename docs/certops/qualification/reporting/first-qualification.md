# Start qualification without an Azure lab

Ordinary Windows, Linux, API/PostgreSQL, browser, local ACME/DNS and local Kubernetes qualification needs no Azure lab subscription, Azure OIDC identity, Azure environment secrets or lab opt-in flag. Use the existing disposable GitHub-hosted runners first. Nothing in this runbook has been configured or dispatched remotely.

Print the reviewed starting sequence from the Core checkout:

```sh
node scripts/certops-qualification-start.js
node scripts/certops-qualification-start.js --candidate <40-character-main-sha> --json
node scripts/certops-qualification-start.js --profiles
```

This entrypoint only reads committed workflow definitions and prints commands. It does not launch CI, create cloud resources, install a runner or configure credentials. The commands target `main`, preserving the repository's trusted-reference policy. New workflows must exist on trusted `main` before dispatch; do not substitute a pull-request ref to bypass the guards. Record each run's actual `headSha` and attempt. Reports from different candidates cannot be combined; a new commit on `main` may require new qualification runs.

## First pass

1. Run `certops-qualification.yml` with `lane=tooling`. Inspect source, report, selector and security failures first.
2. Run the same workflow with `lane=stack`, then `lane=windows`. These are the ordinary API/PostgreSQL and hosted Windows lanes. The `all` choice means these three standard lanes only; it does not dispatch the separate native or AD CS workflows. Relevant trusted pushes select these lanes by changed paths; a retry does not broaden the original selection.
3. Run `certops-windows-e2e.yml` with `windows_server=windows-2022`, `key_profile=rsa-2048`, `historical_upgrade=false` and `wer_probe=false`. This is real installed Windows agent/API/local-ACME/CNG/store/IIS/HTTP.sys qualification without a domain or Azure. Turning off the historical comparison for this initial pass does not qualify upgrades. The optional WER probe remains experimental.
4. Run `certops-linux-systemd.yml`, then `certops-real-acme.yml` with `client=certbot` and `eab=none`. The systemd workflow currently runs both supported Ubuntu versions. Pebble and its challenge server are owned local fixtures, not a public CA or live DNS provider.
5. Run `certops-browser-qualification.yml`, `certops-dns-routing-qualification.yml` and `certops-dns-provider-errors.yml`. These use the actual application or owned local protocol fixtures. Provider fault fixtures are not evidence of a live provider account.
6. Run `certops-kubernetes-qualification.yml` and `certops-kubernetes-http01-qualification.yml`. They create disposable local kind clusters on hosted Linux runners; AKS and other externally managed clusters are not prerequisites.

The GitHub CLI commands printed by the entrypoint require your usual repository Actions permissions. Use the workflow UI instead if preferred. Inspect each completed run's mandatory scenario report, cleanup outcome and uploaded artifacts before proceeding. A green supporting suite is not native qualification of a capability it did not execute.

## Expand hosted coverage deliberately

After the first pass, use `windows_server=all` and `key_profile=all` for the Windows ACME matrix, enable the separately documented historical upgrade comparison, and run `certops-windows-fixed-root.yml` for canonical installation. Its two Server hosts are already explicit in the workflow. The ARM64 CNG, packaged-SCM and installed-agent workflows are separate Windows 11 desktop scopes; they do not replace Server/IIS or domain-backed qualification. A published-package slot still fails if its required artifact is absent or incomplete.

Other Azure-lab-free workflows cover Linux published upgrades, Alpine clients, filesystem deployment, Linux OS trust, nginx/Apache/HAProxy, native agents, signing rotation, scheduler capacity, alerts, log maintenance and focused API integration. The consuming-server workflow defaults to one Ubuntu/service cell; select `os=all,service=all` deliberately. Supporting integration defaults to one `group`; `group=all` runs its committed groups. An integration group named `adcs` tests server-side behavior and fixtures; it does not provision a CA.

The dedicated native ACME browser console and issue/renew lifecycle workflows are manual Ubuntu/certbot scopes. They require their actual built dashboard, pinned browser and local stack, all prepared by the workflow. None requires an Azure lab identity. Complete every selected environment required by the [release matrix](../../release-qualification-matrix.json), rather than treating this starting sequence as exhaustive.

## Live DNS credentials are separate

`certops-dns-provider-qualification.yml` is optional for the initial pass. It requires an explicitly enrolled provider, a dedicated disposable DNS zone, provider-specific environment approval/credentials and cleanup verification. Follow the [DNS-provider guide](../dns-acme/dns-provider-qualification.md); never use a production zone. An Azure DNS provider account is a separate provider credential requirement, not permission to provision the AD CS VM lab. Local DNS, Pebble and kind qualification need neither.

The `standard-hosted` collection profile means **no domain-lab campaigns**, not credential-free or minimal smoke. It still includes live DNS-provider and currently blocked published-package cells. Missing reports and blocked artifacts remain failures; the collector does not silently omit them.

## Optional domain-backed AD CS setup

Only prepare this environment when running genuine enterprise AD CS scenarios. Follow the [disposable AD CS lab guide](../../../../infra/certops-adcs/README.md), including its bounded OIDC permissions, protected environments, image/language prerequisites, resource ownership, lease limits and cleanup receipts. Configure the protected `certops-adcs-lab` and unattended `certops-adcs-cleanup` environments with the documented `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_SUBSCRIPTION_ID` variables and their respective OIDC trust. Confirm that the janitor schedules are enabled and cleanup can authenticate and remove only proven owned resources. Then explicitly set the repository variable `CERTOPS_ADCS_LAB_ENABLED=true` when ready to permit the guarded lab jobs.

No Azure resources are provisioned by a normal push. AD CS provisioning requires explicit opt-in plus its manual preparation/provisioning workflow and protected authorization. Scheduled finalizers and janitors operate on existing owned campaigns; they are not a substitute for enabling cleanup before preparation. To stop new preparation, stop manual dispatches and withhold preparation approvals while keeping cleanup enabled. Leave the opt-in true and janitors enabled until Azure independently shows that all owned resources are gone, then disable the opt-in. If an emergency requires disabling it earlier, scheduled controllers also stop: dispatch the ownership-aware cleanup manually and retain its authentication until teardown is verified. Manual cleanup remains available after opt-in is disabled. Failed, canceled or interrupted runs require independent ownership-aware cleanup; a failed delete must not be reported as successful teardown.

Baseline and hierarchy AD CS are separate from the occasional elapsed pending, default 24-hour AD CS TTL, post-issuance 24-hour retention and installed-service timer campaigns. Those long campaigns can incur a day of VM runtime and must be explicitly selected. The existing timer campaign uses the AD CS lab because its preparation really issues through AD CS; it is optional extended-domain evidence, not a prerequisite for ordinary Windows retention checks. Hosted bounded/configured retention tests do not replace its genuine six-hour elapsed observation. Do not transfer machine-bound CNG keys or shorten actual deadlines to make a hosted job appear qualified.

## Collect the scope actually executed

The existing collection workflow now exposes a `profile` choice. Its default remains `full`; choose `standard-hosted` explicitly for Azure-lab-free collection, `adcs` for baseline/hierarchy domain cells, or `extended-adcs` for the declared elapsed campaigns. Supply the exact candidate SHA and explicit completed run IDs. Collection only reads bounded reports; it starts no host tests and creates no lab.

Every selected cell must have matching successful evidence. The result reports exact selected and omitted slot IDs. Non-full profiles report `fullMatrixQualified=false` and cannot stand in for full release qualification. An initial smoke pass will normally leave selected `standard-hosted` cells missing; collect only when the intended profile is complete, or retain that failure as an honest inventory of remaining evidence. See [release collection](release-qualification.md) for the full evidence contract.

Use the entrypoint's `--profiles` option for current counts and exact selected/omitted slot IDs from the committed matrix. This is a read-only inventory, not a verdict. It does not infer that a published archive is usable: missing or incomplete published-package evidence must stay blocked in the actual report, even when its slot belongs to `standard-hosted`.

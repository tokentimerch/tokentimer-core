# Certificate lifecycle qualification

Use the test and harness comments for scenario-specific setup, commands, independent assertions and cleanup. This guide contains the shared workflow and evidence rules. The machine-readable [suite inventory, scenario catalog and release matrix](qualification-suites.json) define the actual obligations; runnable source alone is not successful execution.

## Start and select workflows

Use Node 24 and the locked pnpm version from `package.json`. Begin with these read-only checks:

```sh
pnpm test:certops:qualification
pnpm check:certops:catalog
node scripts/certops-qualification-start.js
node scripts/certops-qualification-start.js --profiles
```

The starting planner prints reviewed dispatch commands; it never launches workflows, configures credentials or provisions infrastructure. Its sequence is an initial smoke pass. Qualification workflows require trusted `main`; do not bypass those guards with a PR ref. Record the actual candidate SHA and run attempt, and repeat affected qualification after source changes.

The standard `certops-qualification.yml` lanes are `tooling`, `stack` and `windows`; `all` selects those three lanes. Separate native, browser, DNS, Kubernetes and domain workflows have explicit dispatch inputs. GitHub requires entrypoint YAML directly in `.github/workflows`; their `CertOps / ` display names group them in Actions. Detailed selection policy lives beside [the selector](../../scripts/certops-ci-selection.js).

Ordinary hosted Windows/Linux, API/PostgreSQL, browser, local ACME/DNS and kind runs need no Azure domain lab. They still need their documented tools and disposable fixtures. Live DNS qualification requires an explicitly authorized disposable zone and provider credentials. Published-package cases require complete candidate artifacts. Neither is implied by a local fixture pass.

## Find the owning source

- [API suite runner](../../scripts/certops-api-qualification.js): maps suites to the actual E2E tests and report settings. Each test describes its own prerequisites and assertions.
- [Supporting database runner](../../scripts/certops-integration-qualification.js): exact named integration groups and bounded reporting.
- [Windows qualification sources](../../packages/agent/scripts/host) and [E2E helpers](../../tests/e2e/helpers): host fixtures, safety boundaries and cleanup.
- [Native and browser E2E tests](../../tests/e2e): public API, installed agents, independent TLS and UI journeys.
- [Distribution guide](qualification/distribution/README.md): shared disposable lab operation; scenario details are beside its tests.
- [AD CS lab guide](../../infra/certops-adcs/README.md): protected environment setup, ownership and independent TTL cleanup.
- [Release collector](../../scripts/certops-release-qualification.js) and [skip mapper](../../scripts/certops-skip-qualification.js): evidence validation and inventory maintenance.

## Disposable execution and cleanup

Use owned, isolated fixtures with unique resource identities. Global scheduler, maintenance and retention sweeps require an exclusive disposable stack. Never reuse production certificate stores, CA resources, DNS zones or service identities. Remove only proven owned resources, stop owned children before deleting their state, and independently verify cleanup even after test failure or cancellation. Successful assertions do not imply successful teardown. Never use global Docker cleanup.

Domain-backed AD CS is a separately opted-in scope. Follow the lab guide before authorizing preparation: protected environments, bounded OIDC permissions, native OS/language and service identity, ownership receipts, lease limits and authenticated janitors are required. Enable cleanup before preparation. Keep cleanup authorization, opt-in and janitors enabled until Azure independently confirms teardown; only then disable the opt-in. Disabling opt-in early also stops scheduled controllers, so use explicit ownership-aware manual cleanup if necessary. Long pending/TTL/retention/timer campaigns require deliberate selection and actual elapsed time. Do not shorten production deadlines, rewrite clocks or move machine-bound CNG keys to obtain a pass.

## Evidence and release collection

Full E2E exercises the real API or browser, worker/database, execution plane, issuer and destination. Independently inspect public certificate bytes and trusted served TLS identity; a successful job receipt alone cannot prove convergence. Seeded SQL, injected command results and protocol fixtures retain their supporting classification. Source-mounted distribution labs remain experimental and cannot qualify a released native artifact.

Strict runs must fail on absent prerequisites, empty selection, missing reports, failed/skipped mandatory cases, stale source digests or failed cleanup. Reports identify the exact commit/artifact, actual environment and service identity, required scenario outcomes and cleanup. Do not upload keys, credentials, cookies, raw database dumps, private process logs or unbounded assertion payloads. Keep only approved sanitized evidence.

Collect one exact candidate with explicit successful run IDs using `certops-release-qualification.yml`, or inspect downloaded reports locally:

```sh
node scripts/certops-release-qualification.js <40-character-candidate-sha> <report.json> <report.jsonl> ...
```

Local reports cannot satisfy hosted release slots. Collection validates bounded artifacts and never starts host tests or enables a feature. `full` is the default profile. Explicit `standard-hosted`, `adcs` and `extended-adcs` profiles require every selected cell and expose every omitted slot with `fullMatrixQualified=false`. `standard-hosted` excludes domain campaigns but still includes live DNS and published-package obligations; it is not the credential-free smoke sequence. A complete committed matrix still reports `allFeaturesQualified=false` separately from catalog implementation status.

Downstream editions must qualify their actual composed candidate, Core pin, contracts and edition policy with their own source/provenance and cleanup evidence. Entitlement fixtures do not establish billing or license behavior; an older Core pin cannot qualify newer Core changes.

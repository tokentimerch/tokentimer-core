# Auto-sync lifecycle and rollout

## Configuration and inventory identity

Configuration IDs are durable. Public `name` maps to `connection_key`: whitespace is collapsed, names contain 1–100 characters, and PostgreSQL enforces case-insensitive uniqueness per workspace and provider. Name and schedule edits keep an active run valid. Credentials, scan parameters, cleanup policy, and enabled state advance `scan_version` and supersede the active run. All comparisons use the locked current configuration, including concurrent edits.

Inventory identity is the existing `(workspace, provider, instance, owner key, source kind, source object ID)` tuple. Configurations finding that same identity share one token and have separate associations. This feature does not infer identity from secret values. GitHub/GitLab currently scope scan identity to the authenticated principal, so different principals' views of repository assets can have separate rows; changing that boundary requires provider-specific attribution and migration. Legacy rows are attached only through verified rediscovery, never guessed from provider alone. Migration cannot prove creation ownership from existing token data and leaves legacy inventory unmanaged and unassigned.

`auto_sync_managed` is false by default. Only creation inside a validated fenced import makes it true. Rediscovery of existing inventory never changes it to true. Manual integration import or confirmed CSV/JSON duplicate import makes it false. Deleting a configuration detaches its associations; otherwise orphaned inventory becomes unmanaged and remains present. Other configurations still protect their associations.

## Run and transaction boundaries

Claiming a due configuration locks its row with `FOR UPDATE SKIP LOCKED`, increments its generation, assigns a random run ID and lease owner, and records an allowlisted non-secret settings snapshot. The lease lasts 300 seconds and is renewed every 60 seconds. An expired owner cannot renew or write; the next claim supersedes its run and advances generation. Import, scan persistence, association writes and completion lock and validate the current configuration/run/generation/scan-version/owner in PostgreSQL. Provider calls occur outside the claim transaction.

Run-now sets a durable boolean request. Repeated clicks during an active run coalesce into one subsequent manual run. Scan-affecting edits queue a replacement when the configuration is enabled. Manual and replacement requests coalesce into one next run, with manual taking precedence. Disabled configurations do not execute pending requests until enabled. Completion uses the current schedule, so schedule edits during a run are retained.

Workers send `auto_sync_run` on scan and import requests. Scan persistence atomically binds each scan to its run under the fence. The observation timestamp is captured when the HTTP scan request begins, before provider network calls; older results cannot masquerade as newer observations. Stale runs cannot persist scan observations. Imports can use only scans bound to their own current run.

Import looks up and updates/creates inventory in one transaction, taking deterministic advisory locks on source identity and legacy name/location, then a token row lock. This also serializes overlapping discoveries and manual adoption. `attached` and `detached` events preserve the configuration ID/name and token ID snapshot. PostgreSQL forbids changing their payload or deleting them while the workspace exists; token deletion may clear only the live token foreign key, and workspace deletion may cascade history.

## Destructive reconciliation

Negative reconciliation requires **all** scans registered to the run, every requested persisted scope positively complete, every observed item imported and associated in this generation, no durable import errors from any batch, and a current lease/version/owner fence. A verified complete zero-item scan is valid. Missing pagination, truncation, rate limits, inaccessible scopes, provider/item errors and partial scans retain associations. Partial status is reported even if cleanup is disabled.

Within the transaction, unseen associations are considered only for the exact provider/instance/owner/kind/dimensions that the complete scan covered. Vault path prefixes are literal prefixes, including `%`, `_`, and backslashes; SQL wildcard matching cannot broaden the scanned scope. Assets outside the newly requested universe are not confirmed absent: changing instance, principal, filters or mounts can retain old associations until verified scanning covers them or the configuration is deleted. There is no destructive inference from a changed filter alone.

Detach, event insertion, association recheck and conditional managed-token deletion commit together. Attach and detach share the token row lock; a fresh statement snapshot detects another configuration's committed attachment. The existing observation fence also retains inventory rediscovered by a newer scan before import. Manual scan cleanup rechecks associations after acquiring the token lock. Inventory is deleted automatically only if it remains managed and has zero active configuration associations.

## History and public errors

`GET /api/v1/workspaces/:id/auto-sync/:configId/runs` returns run ID, trigger, generation, scan version, timestamps, status, settings snapshot and separate discovered/created/updated/detached/deleted/error counts. Pages use an opaque cursor over the unique generation, avoiding timestamp precision loss. `limit` is an integer from 1 to 100. Import tokens offers **Earlier runs**; Control Center opens the selected configuration by ID.

Scan and credential-validation errors appear directly below each integration connection form, before scan filters and results. File import errors remain in the file import flow. GitLab must establish a valid user identity before scanning inventory; failed authentication, redirects, rate limits, server failures, and non-GitLab responses fail that connection check immediately. Redirect feedback asks for the canonical HTTPS instance URL; credentialed redirects remain disabled. Scope errors after successful authentication still follow the partial-scan rules.

Token and certificate details group ownership and configuration names in a labeled Auto-sync section. Show history expands the association events; Earlier history loads another page from `GET /api/tokens/:id/auto-sync-provenance`. `next_before` is the event ID cursor. Deleted configurations remain identifiable in events, and retained inventory keeps its deletion explanation visible while history is collapsed. Reads use the normal token membership authorization, including viewer access.

Provider error bodies, raw exception messages and import item names are not persisted as public auto-sync errors. Controlled categories retain HTTP status, timeouts or import/completeness outcomes; credential-like JSON, header values and multiline secrets cannot enter run history, audit or incident notifications through these messages. Credentials never enter settings snapshots; the allowlist contains scope/filter metadata and sanitized source instance/account identity.

## Activation and rollback

Migration leaves the persisted activation flag off. PostgreSQL also rejects a second configuration before activation, including inserts from an old API node after the first config was renamed. Deploy the new API fleet, drain every old worker, deploy and verify the fencing-aware worker image, then activate as a system administrator with `POST /api/v1/admin/auto-sync/activation` and `{"workers_drained":true,"worker_image_verified":true}`. These attestations are an operator requirement; the API cannot inspect an external worker fleet. GET reports persisted state.

Before activation, legacy worker imports can update inventory but the new API suppresses their unfenced destructive cleanup. From activation onward, legacy worker scans/imports lacking fenced run context fail closed on the new API. Older API or worker versions are unsupported after activation and must never rejoin a multi-configuration installation. Roll forward or restore a pre-activation backup; do not merely downgrade images. Cloud has no auto-sync worker or management UI and requires no issue-specific implementation PR.

## Verification

Unit tests cover fences, ownership, partial scans, settings normalization and controlled errors. The real PostgreSQL gate uses actual models/routes and concurrent connections for discovery, attach/detach, manual cleanup, expired leases, edit invalidation, coalescing, deletion, activation and microsecond history pagination.

Create a disposable PostgreSQL database with a name ending in `_issue71_test`, set `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD` if required, and `DB_NAME`, then run `node apps/api/migrations/migrate.js` and `pnpm test:auto-sync:postgres`. The name guard prevents running the fixture against ordinary databases. No provider credentials or live provider account are needed. The process exits after test hooks because importing the API starts operational timers. Drop the entire disposable database afterward; audit fixture users are intentionally retained because audit rows are immutable.

# PR draft: customer Vault publication and independent pinned consumers

Wildcard renewal previously had no durable shared material publication contract
or independently tracked fleet deployment. This change adds customer-local Vault
KV v2 publication and signed, explicitly assigned `deploy-from-store` jobs.
Private material stays on customer infrastructure; Core stores public identities,
immutable logical versions, exact provider versions and per-consumer receipts.

Migration 68 introduces workspace-scoped groups, material versions, frozen
approved rollouts, bindings and deployment/current-state records. Existing
issuance, DNS, native deployment, approvals, signatures, nonce/claim/lease,
fingerprint history and worker outbox paths are reused. Rollouts support canary
waves, bounded retries, pause, explicit rollback with increasing generation and
approved read-only drift checks. The Renewals page includes an independent
consumer matrix. Lost publication responses recover the same staged pair;
uncertain installation effects require customer-side reconciliation.

Validation uses real PostgreSQL, Vault, Pebble DNS-01 and independent NGINX and
HAProxy processes, plus contract, unit, secret-boundary and legacy regressions.
See `tests/wildcard-vault/README.md` for reproducible commands and the
implementation ledger for executed evidence and outstanding gates.

Release depends on coordinated Cloud migrations 86/87, policy mappings and Enterprise
composition of the exact reviewed Core candidate. New execution capabilities
remain absent from the shipped qualification input pending complete enrolled
agent/customer qualification. Appliance, Windows shared-key and Kubernetes
bundle execution remain unsupported. No release or production deployment is
part of this PR.

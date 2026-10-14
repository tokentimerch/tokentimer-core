# Certificate audit history qualification

`certificate-audit-api` runs eight strict named scenarios through actual authenticated API routes and PostgreSQL. The central API qualification runner includes it automatically; `CERTOPS_AUDIT_REPORT` selects its sanitized report. Focused execution passed all eight cases against an isolated local stack, followed by independent report verification. Hosted/full CI execution remains pending.

Public AD CS profile creation and editing produce real audit events for a Windows store/IIS target. Confirmed issuer metadata is seeded solely as an administrative prerequisite; these tests never contact a CA, create a CNG key or deploy to IIS. They assert actor/workspace/profile/issuer/reference identity, exact action and reference search, literal percent/underscore escaping, non-injectable search, stable pagination, cross-workspace isolation, viewer refusal and manager access. Run-owned API identities and immutable audit rows are removed under the explicitly disposable fixture policy.

The existing audit table has an integer `target_id`; UUID profile identities therefore live in `metadata.profileId` and `target_id` remains null. The tests preserve that actual contract. This supporting integration evidence does not qualify native issue/preflight/failure/retire/trust audit store/site/port/SNI variants or browser filters.

An additional public Windows-target issue job is genuinely admitted, claimed by an authenticated protocol-declared Windows identity and reported failed. Its searchable audit event must retain WebHosting store, IIS site/port/SNI, job and agent context; replay creates no duplicate. The fixture does not execute native IIS/CNG/CA operations.

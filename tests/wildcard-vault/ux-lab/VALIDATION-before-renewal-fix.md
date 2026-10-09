# Executed user/API lab — 9 October 2026

**Overall result: failed at the public renewal workflow.** The lab itself is running and usable. Ten checks passed across setup, publication, bindings, rejection, and authorization in a fresh run without manual repair. Recovery assertions were not reached and are not reported as passes.

- Core source commit: `63a8aa37909b71ab5086fe50ea6839eeb79735f5`, with the lab files added locally.
- Isolated project: `tt-wildcard-ux-20261009-r3`.
- Workspace: `94f4760b-49ef-4f32-b28c-03d21e44e345` (`Wildcard API UX Lab 57bf288d`).
- Certificate: `9830d989-64f1-4d5f-9979-21bf16335a77`.
- Distribution group: `be4b46af-493c-4985-84f6-e6455be9f962`.
- Issuance job: `5c06d74b-7143-402d-9b5c-113e17b86330`.
- Published version: `be3d83bd-f5f0-53a4-ad59-5d6f37d3760e`.
- Initial rollout approval: `106f4350-8313-4254-ae81-1b0268f95b69`.
- nginx binding: `99b6bf82-2141-46f7-ba14-94c487b5d69f`.
- HAProxy binding: `aff73f6c-3e93-48dc-bc7b-3746e11e2542`.

Executed with `run.ps1 -Action Up` followed by `run.ps1 -Action Test`. The normal dashboard build, CJS syntax checks, Compose configuration validation, and PowerShell parser validation passed. `run.ps1 -Action Status` confirmed the named stack remained running and API/PostgreSQL were healthy after the failed journey. This does not constitute release CI parity.

## Observed behavior

Normal invitation/email verification, owner/approver separation, and enrollment of three real agents succeeded. The issuer performed DNS-01 issuance and Vault publication. Its canonical key was promoted into the configured custom directory with mode `0600`, with no canonical key in the default directory.

Both nginx and HAProxy loaded and served the published certificate with trusted probe evidence. Concurrent identical binding PUTs kept authorization revision 1. Repeating the rollout request before approval, after expansion, after completion, and after a membership change returned its original approval job. Reusing its idempotency key with changed parallelism returned 409. The temporary membership-check binding was removed through PUT; its historical row remains visible in the matrix and must not be mistaken for a third live consumer.

A separate never-claimed publication was rejected through the approver API. Its material version became `failed` with `allocation_release_reason=rejected_before_execution`, retaining its history. A real nginx binding edit advanced authorization revision once to 2 and invalidated the old proof; repeating that edit kept revision 2. Updating customer-local policy and approving a new rollout restored both real consumers to **Verified and current**, generation 2. A cross-workspace group request was denied.

Browser actions independently verified owner sign-in, CertOps job outcomes, and the distribution matrix. The generic inventory Renew button opened a metadata expiration-date editor, which was cancelled without saving. The CertOps Renewals page showed **No key access** and **No renewal profiles yet** for the published certificate.

## Reproducible failure

The session-authenticated owner submitted the normal public request:

```json
{
  "operation": "renew",
  "subjectType": "managed_certificate",
  "subjectId": "9830d989-64f1-4d5f-9979-21bf16335a77",
  "assignedAgentId": "f521adc1-05b8-4db3-8df8-369b4f67bd3d",
  "requiresApproval": true,
  "idempotencyKey": "57bf288d-7bc5-42fe-96b4-f79155c9bbbb-rejected",
  "payload": {}
}
```

`POST /api/v1/workspaces/94f4760b-49ef-4f32-b28c-03d21e44e345/certops/jobs` returned HTTP 400, `CERTOPS_RENEWAL_PROFILE_INCOMPLETE`. The public certificate detail had `profileId: null` and `keyMode: vault-managed`.

A separate read-only diagnosis of the certificate PEM obtained through that public API confirmed the Pebble leaf is SAN-only (`commonName: null`, SANs `*.wildcard.test` and `wildcard.test`). Calling the pure profile derivation function on that public certificate and the original public job payload raised **Reconciled certificate has no common name**. Publication catches this derivation failure, leaving issuance successful with no renewal profile. This diagnosis performed no database query or mutation. The existing deployability key-mode allowlist also excludes `vault-managed`, consistent with the UI's **No key access** classification; that is a separate integration gap to assess when fixing the renewal path.

No product code was changed to hide or bypass these failures. Lost-response recovery, rotated-key reuse on a subsequent renewal, same-group corrected renewal, and offline catch-up after renewal remain blocked. Never-claimed cancellation and historical migration backfill are outside this public journey, as explained in README.md.

The machine-readable result is `validation-2026-10-09.json`. Full local evidence, public API inspection, and the UI screenshot are retained in `.scratch/tt-wildcard-ux-20261009-r3/`. Earlier harness bring-up evidence is retained separately in `.scratch/wildcard-ux/`; it is not the final clean replay. The manual audit PostgreSQL was still healthy with unchanged start time `2026-10-07T08:43:12.063869281Z`.

# Operator-supplied CSR workflow: manual test plan

Use a disposable Core deployment and workspace. Keep every private key on the
operator/test host, outside the repository and outside the Core containers.
Only copy the `.csr.pem` and `.crt.pem` files into the dashboard or API. A
self-signed test certificate is sufficient: CA trust decisions are outside
this workflow.

## Preparation

1. Start Core with CertOps enabled and apply migration 56. Verify that
   `certificate_csr_workflows` exists. Sign in as a workspace manager. Prepare
   a viewer in the same workspace and a manager in another workspace.
2. Prepare one target without an observation source (create it from the CSR
   form) and one existing target fed by an endpoint monitor, agent, or
   controller. Arrange for the monitored target to serve/observe a test leaf
   on demand. Record the workspace, target, and managed certificate IDs.
3. On the operator host, use OpenSSL to generate two local keys and CSRs. Make
   one signed leaf with the CSR's requested names and one whose SAN differs.
   For example, the following commands make the changed-name fixture. Keep
   the key file local and never paste or upload it except in the explicit
   rejection check below.

   ```sh
   mkdir -p csr-manual-test && cd csr-manual-test
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key-a.pem
   openssl req -new -key key-a.pem -subj '/CN=csr.example.test' \
     -addext 'subjectAltName=DNS:csr.example.test' -out request-a.csr.pem
   printf '[v3_req]\nsubjectAltName=DNS:issued.example.test\n' > issued.cnf
   openssl x509 -req -in request-a.csr.pem -signkey key-a.pem -days 30 \
     -extfile issued.cnf -extensions v3_req -out changed-a.crt.pem
   ```

   Repeat with a second key for SPKI mismatch. Issue a second certificate
   from `request-a.csr.pem` with `DNS:csr.example.test` for the unchanged-name
   cases. Generate another CSR from `key-a.pem` with a different subject to
   prove that CSR DER, rather than SPKI, is the idempotency key.

4. Record a baseline of the selected existing certificate's fingerprint,
   expiry, token ID/expiry, contacts, profile, and instance count. In the
   test database, these read-only queries are useful after each case:

   ```sql
   SELECT id, status, existing_certificate_id, managed_certificate_id,
          csr_der_sha256, spki_fingerprint_sha256, signed_fingerprint_sha256,
          name_additions, name_omissions, names_acknowledged_at,
          observed_instance_id, identity_conflict_instance_id,
          identity_conflict_certificate_id, confirmed_at, confirmed_by,
          confirmation_method
     FROM certificate_csr_workflows WHERE id = '<workflow-id>';

   SELECT id, managed_certificate_id, target_id,
          observed_fingerprint_sha256, observed_at
     FROM certificate_instances WHERE target_id = '<target-id>';

   SELECT id, status, fingerprint_sha256, not_after, token_id
     FROM managed_certificates WHERE id = '<certificate-id>';

   SELECT action, metadata FROM audit_events
    WHERE metadata->>'workflow_id' = '<workflow-id>' ORDER BY id;
   ```

## Happy paths

1. **New identity, manual attestation.** In CertOps Certificates, save
   `request-a.csr.pem` with a new unmonitored target. Confirm status
   `pending_signature`, export the CSR, and compare its DER digest with the
   local CSR. Save the same CSR and target again: the workflow ID must be
   unchanged. The second CSR made with the same key must create a distinct
   workflow. Import the unchanged-name signed leaf. Expect
   `signed_pending_install`, a `provisioning` managed certificate, no token
   before promotion, and no instance. Confirm installation as
   manager. Expect `completed`, `confirmation_method = manual`, manager/time
   audit fields, active public certificate, linked token with the signed
   expiry, and still no fabricated instance or observation timestamp.
2. **Existing identity rotation.** Open an active certificate's detail view
   and start a CSR workflow from it. Import the signed leaf. Before install,
   confirm that the existing certificate fingerprint, expiry, token expiry,
   contacts, profile, alerts, and instances remain as at baseline. Complete
   by manual attestation on an unmonitored target. Confirm the certificate
   ID, contacts, profile, and old instances are retained while public leaf
   and token expiry advance to the signed leaf.
3. **Observation after name review.** Use a new-certificate workflow on the
   monitored target and a leaf
   with a changed SAN. Import it; verify additions and omissions are shown.
   Acknowledge names first. Then let the normal monitor/agent/controller
   observe the matching leaf at that target. Expect a real instance with the
   observed fingerprint/time and workflow completion. Confirm no manual
   attestation fields were set.
4. **Observation before name review.** Repeat with a separate new-certificate
   CSR/leaf and target. Let the matching observation arrive before acknowledgement. The
   real instance must exist immediately, while the workflow remains
   `signed_pending_install` and the workflow has not promoted its certificate.
   After
   manager acknowledgement, expect immediate completion from the already
   recorded instance. No second observation should be necessary.

## Conflicts, security, and permissions

5. **Known leaf.** Import a leaf already known to a non-terminal certificate
   through a new-certificate CSR workflow. It should reuse that managed
   certificate ID. Repeat when the known identity is `revoked` or
   `decommissioned`: signed import must return 409 and leave it retired.
6. **A-versus-B at import.** Start a workflow from certificate A using a CSR
   whose signed leaf is already owned by B. Import must return 409. A's
   fingerprint, expiry, token, contacts, profile, and instances stay intact;
   the workflow must not silently point at B.
7. **B appears after import.** Import a new signed leaf for existing A while
   no B owns it. Have the selected monitored target observe that leaf under
   newly created managed identity B. Expect the B-owned instance to remain
   in deployment history, the workflow to remain `signed_pending_install`,
   and an `identityConflict` object naming B and the instance. Name review
   may still be acknowledged. Manual confirmation returns 409, and A is not
   promoted. The dashboard must show the conflict rather than claiming it is
   ready to complete. Review A and B explicitly; cancel the workflow if B is
   the intended identity. Do not use the CSR flow to silently rebind A to B.
8. **Input rejection.** Import a certificate signed for the second key into
   the first key's CSR: expect SPKI mismatch (422) and no signed leaf stored.
   Paste a CSR plus private-key PEM into the JSON field: expect 422 and no
   workflow or target row. Try `.key`, `.p12`, `.pfx`, and `.jks` filenames in
   the dashboard for early feedback. Submit a private-material payload
   directly to the API to verify the content-based guard, independent of
   filename. Inspect the API response, audit metadata, application logs,
   database CSR/public-certificate columns, and control-plane files for
   private-key content; none should contain it.
9. **Authorization and state.** A viewer must be unable to list/export or
   mutate CSR workflows. A manager in another workspace must not see or
   change the workflow. Verify cancellation of a pending workflow is audited
   and terminal; importing or confirming afterward returns 409. A completed
   workflow cannot be cancelled. Repeating the same signed import is
   idempotent; importing a different leaf afterward returns 409.
10. **Rollback and audit failure, disposable database only.** Temporarily
    make `audit_events` reject `CERTOPS_CSR_IMPORTED` inserts with a test
    trigger, then create a CSR with a new target. The request should fail and
    neither target nor workflow should remain. Remove the trigger. Repeat a
    B-after-import observation while rejecting only
    `CERTOPS_CSR_OBSERVED_IDENTITY_CONFLICT` audit inserts: the observation
    and visible conflict must still survive, and the log must contain only
    non-secret error metadata. Remove the trigger immediately afterward.

## Exit criteria

Record workflow IDs, screenshots of each dashboard state, API status codes,
the relevant read-only SQL output, and a log scan. The release passes when
every happy path and conflict above matches its expected state, no pending
instance is fabricated, and no private-key material appears in any Core
response, log, row, or file.

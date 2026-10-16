# Installed-agent public IIS deploy refusal

This source extends the installed Windows journey with a public standalone
`deploy` job against its genuinely issued CNG/IIS certificate. The public route
admits the job, signed dispatch attaches the real public certificate, and the
installed agent must fail with the explicit unsupported Windows IIS deploy error.
This is separate from direct executor tests and certificate dry-run plans.
The early unsupported branch emits no certificate failure evidence. Its genuine
terminal result must instead have one production `CERTOPS_JOB_FAILED` audit
record matching the actual job, claim, agent, operation and specific error.
Certificate issuance, deployment and successful validation evidence must be absent.

A uniquely owned second SNI site reuses the same issued leaf and protected key at
another port. Both endpoints must serve trusted TLS before and after refusal.
Private in-memory observations compare native certificate and CNG metadata,
endpoint bindings, configuration, credential and signing pin. The genuine ACME
launcher receipt directory and DNS observer must remain unchanged, proving that
this refusal did not invoke the configured ACME client. This is not a direct CA
request-database count claim.

The helper registers unresolved shadow ownership before native work. Parent
cleanup must call its `assertCleanupSafe` guard before certificate or key cleanup.
Unknown public dispatch, active execution or mismatched native shadow identity
preserves recovery state. Cleanup removes only the exact owned secondary site
and endpoint after rechecking their association, and verifies primary trusted TLS.

Source and pure supporting checks do not establish hosted execution. No native
IIS/service/certificate actions have run during implementation. IPv6 shadowing,
multi-target renewal and public unsupported-field admission remain separate scopes.

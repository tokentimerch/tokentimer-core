# Other-enrollment AD CS candidate refusal

A genuine CA-issued certificate can belong to the same machine requester and CA while remaining unrelated to an enrollment's CSR. This boundary differs from a missing request, a different requester denied by CA ACLs, or multiple certificates sharing one CSR.

The native reconciliation helper reuses a later owned issued fixture. A native CA fingerprint/request lookup and successful real retrieval prove that the other certificate exists, is CA signed and is accessible under the same LocalSystem machine identity. Its public SPKI must differ from the original journal's real CSR SPKI. The production explicit-candidate function must refuse that exact request without returning a candidate or making it attachment eligible. A forward bounded native search over the later request also remains unresolved.

The helper allocates no additional CA requests or keys. It independently checks unchanged native CA counts, original enrollment journal, CA watermark, protected machine CNG provider/container/usage metadata and trusted outgoing TLS. All native command/query failures fail the scenario. Public request IDs, SPKI digests and eight boolean facts form the strict `nativeForeignSpkiCandidate` proof; private key material and raw native output never enter reports.

This is read-only native candidate verification. It does not fabricate a submission-uncertain enrollment, invoke an unsupported CMC renewal, or claim completion of public operator recovery. The complete deterministic lost-response/public uncertain-enrollment journey remains separate. Offline tests exercise proof refusal and the production SPKI check using a public certificate fixture; actual native execution remains pending on the protected disposable AD CS lanes.

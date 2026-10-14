# CSR observation qualification

The authenticated API qualification runner requires both `csr-observation-api` and `csr-bound-observation-api`. These use real local TLS endpoints, independently parsed OpenSSL certificates, the public endpoint scan and CSR routes, and actual PostgreSQL state.

The first journey proves a matching served leaf can complete a CSR after required name review. The bound journey additionally starts with an existing observed certificate and a two-day token expiry, then serves a genuine five-day replacement while name review is pending. The factual observation persists, while the selected active fingerprint, management identity and token expiry remain unchanged. Public acknowledgement promotes the new identity/expiry and preserves the existing token. Replay retains the observed provenance.

Observed completion leaves manual `confirmationMethod` and `confirmedAt` unset; the harness never presents observation as operator installation attestation. These focused endpoint journeys do not establish native agent/controller/AD CS installation, remote custody or all certificate-chain/identity-conflict variants. All named cases and cleanup must execute; strict source/candidate reports and the external mandatory inventory prevent skipped prerequisites from passing.

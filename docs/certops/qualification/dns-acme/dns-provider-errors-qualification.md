# DNS provider error qualification

Run `node scripts/certops-dns-provider-errors.js`, then independently verify its report with `node scripts/certops-dns-provider-errors-report.js qualification-results/dns-provider-errors.json`. The manual trusted-main workflow `certops-dns-provider-errors.yml` runs the same commands without provider credentials.

The committed inventory requires 109 named scenarios and 192 exact adapter/shared contract tests across all eleven production providers. New or renamed contract tests require an inventory review. Missing, duplicate, skipped, failed, stale-source or incorrectly classified evidence fails verification and release collection.

PowerDNS and acme-dns fault cases use actual owned loopback HTTP servers. RFC2136 exercises actual loopback UDP response rejection and timeout. Fixed-endpoint providers use injected upstream responses and network failures; their scenarios are classified as unit evidence. Retry tests execute production retry decisions with virtual backoff delays. These fixtures do not qualify external credentials, authoritative zones, propagation or provider availability; the separate eleven-provider qualification workflow covers those prerequisites.

The matrix covers authentication/authorization failures, conflicts, throttling, transient and network failures, bounded retries, malformed lookup responses, generated OAuth bearer/assertion reflection, static-secret redaction and exact existing pagination/cleanup contracts. acme-dns acknowledges updates by HTTP status and provides no record deletion API; its successful non-JSON acknowledgement is tested without inventing deletion evidence.

Reports contain named outcomes and source hashes. Raw child output, OAuth credentials, HTTP bodies and generated private keys are not artifacts. The collector retains only committed contract names and fixed status values. A successful fixture report provides supporting unit/integration evidence; it does not promote an unexecuted live-provider lane.

Focused local execution passed all 109 scenarios and 192 contract tests. Hosted workflow and live-provider execution remain pending qualification.

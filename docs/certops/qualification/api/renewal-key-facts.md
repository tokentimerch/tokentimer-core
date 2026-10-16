# Renewal public-key metadata correctness

The `renewal-key-facts-api` suite exercises seven mandatory named scenarios against a disposable authenticated API/PostgreSQL fixture and actual OpenSSL RSA/EC public certificates. Signed agent claims, evidence and result requests exercise the production renewal completion path. Complete execution-profile and key-mode rows are explicit fixture prerequisites.

When reported renewal evidence changes the fingerprint without supplying a verified parsed leaf, the managed certificate must lose predecessor PEM, SPKI, public-key algorithm/size and signature-algorithm facts. Same-fingerprint evidence preserves those facts. Client-reported SPKI alone cannot restore them; importing the matching genuine public leaf restores independently parsed facts, and replaying the terminal result preserves them.

Independent SQL reads and public inventory responses check persistence. The central API runner invokes the producer, checks every mandatory result and verifies current source evidence; the release matrix binds all six producer/helper/parser/completion sources. Reports contain named outcomes and source fingerprints, without raw certificates, credentials or protocol bodies.

This is supporting API/protocol integration, not installed-agent, CA issuance or native key-custody qualification. Hosted execution remains pending. The existing evidence wire format is unchanged.

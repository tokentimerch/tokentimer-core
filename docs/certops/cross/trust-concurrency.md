# Trust-store recovery and concurrency

An exclusive lock lets one writer commit. The second writer fails and does not replace the store. Recovery from a partial write deletes only the owned partial file and restores the previous store bytes. An unrelated file in the same directory is left unchanged.

This suite is separate from the public signed-trust cell. `publicSignedTrustQualified` stays false. A missing trust lab fails closed.

The catalog rows `trust.bundle-concurrency` and `trust.restart-recovery` are annotated only. `trust.public-signed-lifecycle` stays separate and is not promoted.

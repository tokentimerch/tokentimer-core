# DNS propagation, cancellation, and interrupted cleanup

Propagation is not claimed. Cancellation removes one owned TXT identity and leaves every other record in place. Interrupted cleanup may drop that same owned record and must not delete an unrelated record. A blanket netsh reset or a `*` selector is refused.

`liveDnsQualified` stays false when no provider probe exists. A probe object still does not qualify live DNS. The suite level is real-host and the suite status stays pending because a live provider is required.

The catalog rows `acme.propagation`, `acme.provider-cleanup`, and `acme.txt-coexist` are annotated only. This file does not promote them and does not send a DNS query.

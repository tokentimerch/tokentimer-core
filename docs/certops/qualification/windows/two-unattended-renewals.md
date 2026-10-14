# Two successful unattended Windows renewals

`windows-two-unattended-renewals` extends each installed Windows Server/key-profile
journey from one successful unattended renewal to two. It uses the real worker
maintenance function, production scheduler SQL `NOW()`, actual signed claims and
the installed agent. It does not create jobs directly, alter expiry values,
replace a clock, or treat a failed/interrupted renewal as success.

The pinned Pebble fixture issues genuine six-day certificates. The default
renew-before window is thirty days, so a successfully renewed certificate remains
naturally due. The fixture waits for the first actual served leaf's fingerprint
and expiry to reach inventory, requires an unchanged derived execution profile
and active management period, and derives the next idempotency key from that
actual expiry. That generation must have no previous job. A real 1.1-second wait
avoids reusing the preceding certificate's second-resolution issuance instant;
the resulting actual certificate must independently have a later expiry.

The second worker sweep must create a distinct real automation renewal. Both
cycles must succeed and carry the same persisted renewal contract. Independent
trusted TLS checks require three distinct leaf fingerprints and SPKI hashes
(initial issue, first renewal, second renewal). Actual IIS and HTTP.sys bindings
must reference the newest thumbprint; all three CNG keys must have their requested
algorithm/size, machine custody, non-exportable policy and authentic accepted
ownership receipts. Claim-bound verify evidence and automatic-admission audits
must match each actual leaf, expiry and input generation. Inventory fingerprint/
expiry, profile identity and management association history must advance to the
second renewal without replacing the management period.

Actual retention rows must preserve the two cutovers `A → B` and `B → C`, including
the proper predecessor key, old expiry, cutover time and completed job reference.
Both predecessor certificates and private-key associations must remain intact
inside their real rollback/expiry windows. This case does **not** qualify eventual
expiry cleanup. Its sidecar explicitly records `expiryCleanupQualified=false` and
the limited scope `two-unattended-cycles-and-preserved-predecessors-not-expiry-cleanup`.
Separate elapsed retention and lineage safety cases govern later removal.

The parent journey then interrupts the exact next automation generation derived
from C's actual expiry. Its post-crash TLS and registration-preservation baselines
are C, rather than the older B. The helper does not change that crash fixture's
separate lease-reaper prerequisites or label them real elapsed lease expiry.

The strict sidecar is `windows-two-renewals-<key-profile>.json`. It retains bounded
boolean/count facts and source fingerprints. The parent owns jobs, certificates,
keys, service and database cleanup, including the additional successful job.
Portable negative proof tests have run; these installed native cycles remain
pending their hosted workflows. Supporting source implementation is not a native
qualification pass.

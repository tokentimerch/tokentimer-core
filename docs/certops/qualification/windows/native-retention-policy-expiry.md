# Native retention policy expiry boundaries

The native fixture exercises the production collector with the default
168-hour and maximum 720-hour retention policies. Each policy gets separate
owned CNG keys, two actual certificate cutovers, a real IIS endpoint and durable
ledger rows. The existing 24-hour short-expiry control remains separate.

The predecessors have actual short-lived certificates. Their genuine native
expiry plus the production 300-second grace period is earlier than either
configured retention deadline. The fixture verifies preservation before expiry,
waits using real wall and monotonic clocks, interrupts actual certificate
deletion before key deletion, and retries the production collector. Independent
native observations require both predecessor certificates and keys absent,
immutable history intact, and the replacement key, binding and trusted TLS
unchanged. No ledger date, native result, eligibility clock or timer interval is
substituted. Each policy wait is bounded below ten minutes; setup, native
deletion and cleanup take additional time.

The fixture invokes the collector directly. It does **not** qualify the
installed service's default six-hour timer, 168 or 720 hours of elapsed retention,
or background collection during an agent restart. Its closed proof requires
`installedServiceTimerQualified: false` and
`fullRetentionWindowQualified: false`.

The installed service starts an immediate retention sweep, then waits the
configured base interval with the production polling loop's 20% jitter, after
each sweep finishes. The default base is six hours; a timer interval can therefore
range from 4.8 to 7.2 hours before scheduling delays. A future genuine cadence
qualification must retain the same installed service process and boot across
that actual wait, distinguish the immediate sweep from a timer sweep, and
independently bind the latter to an owned ledger and native custody. The separate 24-hour resident keeper stops and
drains the agent; its direct collector calls cannot serve as timer evidence.

The four policy and interruption scenarios are mandatory in both Windows Server
2022 and 2025 host cells. Node release validation and the Python collector require
both complete bounded policy proofs and current source fingerprints. Supporting
tests have passed; native execution remains pending. The explicit 168-hour
collector argument equals the current default; this fixture does not claim that
a service loaded an omitted configuration.

Every short-expiry interruption now starts suspended inside an owned retained JobObject under the actual runner SID. An explicit child gate follows independent process identity observation; actual exit86, zero native members, closed handles and wrapper closure are mandatory bounded proof. Timeout and failure drain that exact job before any IIS, store or key cleanup. Unknown drainage preserves a durable receipt and blocks broad host cleanup. Native key presence and absence use exact machine-KSP CngKey.Exists Boolean observations.

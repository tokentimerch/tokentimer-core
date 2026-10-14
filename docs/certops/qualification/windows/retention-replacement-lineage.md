# Retention after repeated certificate rotations

An installed binding can rotate `A → B → C` before A's retention window ends.
The first ledger row remains an immutable record of `A → B`, including A's own
expiry, verified cutover time, ownership and recovery references. Looking only
for a live B binding would leave A deferred after B has also been superseded.

The production sweep follows at most 64 replacement links until it finds a
currently bound descendant. Every link must be a valid regular-file ledger row
for that exact predecessor, belong to the same certificate store, record agent
ownership, preserve chronological cutover order, have no active recovery
references and contain no future cutover time. Missing, malformed, cyclic,
unrelated or overlong history fails closed. A removed intermediate row still
records its verified cutover. History and retention clocks are never rewritten.
The reader refuses a row whose thumbprint differs from its filename with
`LEDGER_IDENTITY_MISMATCH`, before gathering native facts or deleting material.
The final descendant must pass the existing exact-thumbprint TLS probe; this
does not replace the original predecessor's ownership, binding, shared-key,
recovery-reference or actual deadline checks.

Each production row acquires the same ordered `My` → target-store mutexes used
by agent cutover and rollback. After acquiring it, the sweep reads the row again and
refuses a changed store. Native bindings, key sharing, descendant TLS,
eligibility, certificate/key deletion, issuance-record removal and the final
ledger outcome all remain inside that critical section. Native queries and TLS
receive its cancellation signal. Lost authority propagates without writing an
eligible, deferred or removed outcome. External administrators using IIS or
certificate tools directly do not participate in the agent mutex.

Focused supporting regressions reproduced the original A→B→C failure before
the fix, then removed both eligible predecessor rows while preserving the
original replacement and clocks. Safety cases cover malformed/cyclic/history
bounds, active references added before lock acquisition, store changes,
authority loss and ledger persistence before release. An actual competing store
mutex acquisition is refused during the simulated native query/deletion path.
These temporary-file/unit checks do not delete real certificates or qualify an
elapsed Windows retention window. The separate native repeated-renewal and
elapsed-retention journeys require their hosted execution evidence.

The machine-wide survivor query inspects Crypt32 certificate provider metadata
in every LocalMachine logical store, including archived contexts. It never
opens, signs with or exports private keys. Retention excludes only the exact
predecessor store and thumbprint; an identical certificate mirrored in another
store still protects the key. Startup recovery and abandoned-key cleanup exclude
no certificate. Missing helpers, malformed or incomplete enumeration and
cancellation fail closed before irreversible key deletion.

The existing native guard case now requires five bounded facts proving a
distinct WebHosting survivor, an identical old-certificate mirror, original-key
preservation, replacement trusted TLS and removal of only owned public copies.
The release collector strips raw inventories and the release verifier requires
current hashes for the fixture, adapter, resolver, primitive, Go scan and builder.
Both Server lanes and the supporting ARM64 desktop lane build the candidate
helper before the first native cleanup case. Focused proof/unit/build checks
are supporting evidence only; these native mutation variants remain unrun.
Neither these cases nor the separate short expiry/grace lane qualifies a full
24-hour elapsed retention window.

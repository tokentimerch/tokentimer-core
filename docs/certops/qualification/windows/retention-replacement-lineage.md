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
The final descendant must pass the existing exact-thumbprint TLS probe; this
does not replace the original predecessor's ownership, binding, shared-key,
recovery-reference or actual deadline checks.

Each production row is processed under the same store mutex used by agent
cutover and rollback. After acquiring it, the sweep reads the row again and
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

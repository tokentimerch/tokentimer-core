# New IIS binding before durable completion

The optional `bound-before-complete` experiment covers an actual new native IIS
binding and independently trusted TLS while the journal still says `installing /
bind`. It does **not** claim a post-bind/pre-verification durable marker: initial
installation writes `bind` before the combined native cutover/TLS operation and
has no later pre-verification journal phase. Verification or retention bookkeeping
may already have occurred before interruption.

The exact owned process tree is captured before termination. Only unchanged
captured SYSTEM identities may be stopped; later ambiguous descendants preserve
state and fail. After full drainage the observer requires the exact accepted
nonexportable CNG key to sign data verified by the new leaf public key, unchanged
issued artifact/journal identities, and the new native SNI binding. Independent
trusted TLS must serve that same actual CA-signed leaf. A missed window or already
completed journal fails; no production hooks, synthetic clocks or journal writes
manufacture the phase.

The fixture records whether the actual predecessor retention row is absent or
already present and matching. Public acknowledged recovery waits the real persisted
lease and worker grace, then must inspect/reverify the existing cutover and finish
the same leaf, CSR, key and RequestId without another CA request. Final claim-bound
verification evidence and one exact predecessor retention row are required. A row
already present at interruption must remain byte-for-byte logically unchanged;
its original cutover time is never invented or reset to manufacture eligibility.
The predecessor certificate and protected key remain present.

Reports remain explicitly experimental and not qualified, excluded from mandatory
release cells. Pure proof tests exercise report refusal only. Full native execution
and timing reliability remain pending in the isolated manual forest lane.

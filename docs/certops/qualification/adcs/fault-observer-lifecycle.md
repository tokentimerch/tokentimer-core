# AD CS fault observer lifecycle

The optional response-loss experiment observes an actual owned CA request and
interrupts the owned native submission process. Its result remains explicitly
`not-qualified`: a source implementation or successful supporting test does not
prove that the native fault window was reached.

The controller parses its bounded public receipt only after the child process
and both output streams close. Process exit alone can precede the final receipt
bytes. Malformed, oversized or incomplete evidence fails without persisting raw
native error text. The receipt must identify a positive 32-bit CA request ID and
prove both actual CA observation and owned service-tree interruption.

Cleanup awaits the exact returned observer's close event. Every observer is
registered before waiting for readiness, so an early failure cannot lose cleanup
ownership. If an observer cannot drain within its bounded stop deadline, the
parent preserves native fixtures instead of removing certificates, keys, sites
or working state while an observer could still act. Disposable infrastructure
cleanup remains the independent outer safeguard.

`scripts/certops-adcs-response-observer.test.js` uses controlled child and stream
emitters to check final bytes after exit, stop ordering, output bounds and invalid
receipts. It launches no PowerShell process and does not qualify native recovery,
deterministic response loss or a released AD CS capability.

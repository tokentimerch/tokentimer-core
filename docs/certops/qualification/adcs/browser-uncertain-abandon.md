# Browser confirmation of an uncertain AD CS abandonment

The supported dashboard action for `submission_uncertain` offers a RequestId reconciliation form and an explicit two-step Abandon action. There is no browser button for the acknowledged unknown-effect recovery API, or for an arbitrary pending issuance continuation. This fixture tests the supported Abandon journey on the existing genuine zero-request uncertain enrollment.

The actor signs in as the fixture owner, finds the exact enrollment, chooses Abandon and then Keep, and requires zero abandon mutations. It then chooses Abandon and confirms Free the key. Exactly one actual public abandon POST must return 204. No route interception, synthetic CA response or rewritten enrollment state is used.

The existing native fault fixture retains its independent assertions: the production continuation succeeds, the journal and database become abandoned, the exact unaccepted CNG key disappears, no leaf is accepted, the real CA still has zero requests, one public audit exists and the original unknown-effect job remains fenced for reconciliation. Only those measured observations can complete the additional browser proof. The default API actor remains available to other callers.

Browser sessions use the same exact locked runtime and trusted API origin as the issuer UI journey. A retained BrowserServer and its public trust receipt enter the parent's ownership registry before launch. The receipt is removed only after browser drainage; a released owner cannot remove a later session's receipt at the reused pathname. No credential storage state, browser trace or raw native configuration is uploaded.

Supporting proof and ownership tests do not execute Chromium or Windows native operations. The comprehensive parent supplies this actor at the existing native abandonment boundary, and both scenarios and their strict proof/source fingerprints are mandatory in the root and hierarchy suites. The elapsed-pending suite remains separate. Full native qualification remains pending the protected disposable domain workflow.

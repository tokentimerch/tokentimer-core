# Native IIS public-only certificate association refusal

This supporting native-host source extends the existing disposable IIS fixture.
It reuses a certificate only after the fixture has genuinely removed its original
private key, imports only its exact public DER into LocalMachine/My, and
independently requires HasPrivateKey=false and original CNG container absence.
The real production deployment must fail with binding or live verification
refusal, restore the predecessor, and preserve independently trusted primary
and sibling TLS plus their native binding observations.

The helper removes only the exact owned public store copy without DeleteKey.
Uncertain deployment, changed certificate/root/guard or failed restoration
preserves ownership and blocks broader cleanup. It never recreates a key.

The native parent now requires this scenario and closed proof in both hosted
Server2022/2025 slots, with current causal source fingerprints. No native execution has occurred. This does not
qualify an installed signed-job failure, accepted-before-bind fault barrier,
failed rollback, or any additional public deployment API.

The measured refusal code is retained as BIND_FAILED or VERIFY_FAILED; a
public-only certificate can be rejected at native add or at actual live TLS.
The stable native certificate/store and IIS coordinates are compared; the
product-generated AppId and transient candidate binding are not qualified.

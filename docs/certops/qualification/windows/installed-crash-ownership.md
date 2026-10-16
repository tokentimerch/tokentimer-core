# Installed-agent crash ownership

The installed Windows journey captures the original SYSTEM service child from the
owned SCM executable, exact native argument vectors and protected state directory.
Before interruption it creates a sticky receipt, then a single PowerShell process
retains native handles for the original process and its captured descendants.
Creation times, executable paths, command digests and SYSTEM ownership are checked
again before handle-based termination. A fresh bounded process inventory must show
no captured lineage or fixture command paths before cleanup is released.

This existing-process interruption does not retroactively contain a process tree.
Unexpected descendants, identity changes, failed drainage or altered receipts fail
qualification and preserve the fixture. Newly launched qualification subprocesses
require their separate suspended-process JobObject containment protocol.

The surrounding recovery test retains its shortened fixture lease and zero-grace
reaper settings. It does not qualify the production lease/grace duration or power
loss durability. Native installed-service execution remains pending; pure contract,
PowerShell parsing and C# compile-only checks do not provide native qualification.

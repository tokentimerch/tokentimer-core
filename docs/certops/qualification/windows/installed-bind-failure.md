# Installed public bind-failure injection and rollback

This case is separate from installed public verification failure and from the
manual failed-rollback lane. Those sources do not qualify bind failure. This
source plans an owned `BIND_FAILED` injection, restores the predecessor on
that same selector, and then removes only the resources recorded for the run.

Each run builds its own manifest. The manifest names two sites and two
`hostnameport` bindings, and both the site names and the bindings include the
run id. Ports come from that id and are distinct. The primary selector receives
the unusable hash. The sibling selector is created and later removed, and the
injection commands do not change it. A foreign binding such as `0.0.0.0:443`
is not part of the manifest and is not a cleanup target.

Cleanup is an exact `netsh http delete sslcert <owned selector>` plus an exact
site delete. The guard rejects a blanket netsh reset, a wildcard `0.0.0.0` or
`[::]` binding, a delete without a selector, and any observed binding that
shares an owned port but is not the owned selector. When that conflict appears,
the fixture is preserved.

The node tests parse `netsh http show sslcert` and `appcmd list site` text and
exercise those guards without a Windows host. The PowerShell host path checks
for netsh, appcmd, and WebAdministration before it runs a command. A missing
capability exits 1. A missing host is not a pass. Finishing the owned commands
still does not claim native qualification.

Native installed execution on Server 2022 and Server 2025 remains pending.
This script proof does not qualify verify failure, failed rollback, AppID
preservation, or expiry reclamation.

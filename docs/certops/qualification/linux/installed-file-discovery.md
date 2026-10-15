# Installed Linux file discovery

The existing manual Ubuntu 22.04/24.04 systemd workflows require a separate
`linux-installed-file-discovery` report. This source has not been executed on a
native installed host. Supporting filesystem, cleanup and report checks do not
qualify the service or public API journey.

After the genuine candidate installation and reapplication or published upgrade,
the fixture uses the same installed service and original registration. It creates
an owned self-signed public certificate and genuine private-key decoys under a
new directory within the installer's existing allowed write path. The actual
service's real/effective/saved/filesystem UID/GID must match the nonroot agent
account and its effective capabilities must be zero. The installed discovery
module must match the candidate source.

Only the discovery setting changes. A retained descriptor binds the original
mode-0600 configuration, including its identity and exact bytes. A separate
root-owned mode-0600 backup remains local to the disposable VM. No credentials,
private keys, backup files, command output or configuration bytes are artifacts.

Two distinct post-start scan timestamps must reach genuine authenticated
observation ingestion. Evidence must identify the exact public file, agent and
host, with real adjacent-key detection and no private decoy contents. The public
certificate identity inventory must contain that independently fingerprinted leaf
at its exact filesystem location; a complete inventory page is mandatory.

Restoration explicitly stops the owned unit, verifies its cgroup is empty and
checks the captured old process birth is absent. Only then are the unchanged
owned fixture files removed and original configuration bytes restored. A new
original-configuration service process must authenticate beyond an independent
database-clock cutoff with a changed real heartbeat uptime. Claim polling alone
cannot satisfy this observation. Credential and signing-pin bytes remain equal.
This does not qualify certificate deployment, a system reboot or additional
distributions.

The original installation ownership receipt immutably declares discovery
qualification mandatory and binds a fresh nonce and completion-receipt path.
Cleanup requires a closed completion receipt matching that nonce, the original
configuration identity and its restored digest, plus positive process drainage
and input removal. A missing or externally deleted active guard is never cleanup
permission. Partial setup or unknown restoration conservatively preserves the
owned host state. The independent cleanup step fails in that situation.

Both workflows retain `always()` cleanup steps. Database destruction additionally
requires a successful independent host-cleanup outcome and absence of the original
ownership receipt, including dangling links. Uninstall or live-cgroup failures
preserve private roots, accounts and agent database ownership records. Known
early setup failures can therefore leave owned resources until disposable hosted
VM disposal; this is an environment expectation, not independently measured
cleanup success. These workflows must never run on a persistent/shared host.

Run the existing `certops-linux-systemd.yml` manual workflow on trusted `main` for
the normal source-package lane. `certops-linux-published-upgrade.yml` additionally
requires its independently authenticated published predecessor inputs; the new
discovery report does not replace its upgrade report. Neither workflow provisions
Azure resources. Strict collection requires all closed native facts, the declared
Ubuntu host and current causal source fingerprints.

Supporting checks:

```powershell
node --test scripts/certops-linux-installed-discovery.test.js scripts/certops-linux-installed-discovery-release.test.js
python scripts/certops-linux-installed-discovery-collector.test.py
```

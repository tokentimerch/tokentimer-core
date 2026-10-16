# Native consuming-daemon coordinator rollback

This source extends the actual nginx, Apache and HAProxy fixtures. After a genuine
trusted cutover to certificate B, it appends an invalid directive to the owned
configuration and invokes production `runDeployReloadVerify` with certificate A
and its matching staging key. Actual production command profiles run the daemon's
native configuration validator and reload command; neither is substituted.

A side-effect-free local evidence recorder independently reads the actual A
certificate/key files at `deployment.updated` while a fresh trusted TLS
connection still serves B. Native validation must fail before reload. Production
paired rollback must restore B and emit `restored: true` for failed step `reload`.
Independent observations require original B bytes, ownership and modes, correct
private-key/DNS correspondence and trusted served B. Replaced target file inodes
are not claimed to remain unchanged.

The original configuration is restored only if its original inode and exact
owned invalid append still match. A genuine subsequent native validation/reload
must succeed and preserve trusted B before the guard clears. Both original
private staging files remain exact. Private bytes, paths and raw command output
never enter the public proof.

Any uncertain mutation retains a durable guard. The parent drains its retained
consuming process and listening port, then refuses recursive private-file cleanup
while that guard remains. This is native coordinator behavior observed through a
local recorder; it does not qualify signed dispatch or public API evidence
ingestion. Source and pure controls are implemented; mandatory collection and release verification require the full proof and twelve
critical source fingerprints in all six service/distribution slots. Protected
native execution remains pending.

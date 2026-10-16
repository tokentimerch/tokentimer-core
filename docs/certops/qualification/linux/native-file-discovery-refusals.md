# Native file discovery refusals

This mandatory source is integrated into the dedicated Ubuntu native browser
lifecycle qualification as `real-native-unprivileged-file-discovery-refusals`.
No native Linux execution has been performed for this addition.

The intended lane uses the actual foreground production agent under an explicit
unprivileged hosted-runner identity. The fixture reads all four native UID and
GID fields and requires zero effective capabilities, both for the fixture and
the retained agent process. It refuses root execution rather than treating a
root-readable file as a successful permission refusal.

Only public certificate bytes enter these negative fixtures. An owned regular
certificate is made unreadable, and file and directory symlinks point to an
owned public certificate outside the discovery directory. An independent OS
read must fail with `EACCES` before the agent starts. The existing regular-file
positive control must be ingested through the genuine authenticated agent
protocol and appear in the public certificate identity inventory. Two distinct
post-setup scan timestamps are required; absence of a negative observation alone
does not prove that a scan ran.

The negative certificate has a different fingerprint from the regular positive
control. Its fingerprint must be absent from both persisted agent observation
evidence and the public inventory. Original file identities, permissions,
symlink targets and outside public bytes remain unchanged through observation.

The caller registers the sticky cleanup resource before creating any fixture.
The unreadable file remains unreadable until the exact retained agent child has
closed. Cleanup then verifies the owned identities before removing the inputs.
Partial setup, ownership changes or unknown agent drainage preserve the fixture
and prevent database and private-root cleanup. This scope does not qualify an
installed service, Windows discovery or arbitrary remote filesystem behavior.

Supporting parser/oracle checks run with:

```powershell
node --test scripts/certops-native-file-discovery.test.js
```

These checks validate refusal contracts using controlled inputs. They do not
substitute for the eventual native agent/API qualification.

Run the existing trusted-main manual workflow
`.github/workflows/certops-acme-browser-lifecycle.yml` for qualification. It checks
the selected hosted UID/GID before launching Node, and the runner and fixture
independently verify native identities and effective capabilities. The final
`acme-browser-lifecycle.json` report requires the separate closed
`nativeFileDiscoveryRefusals` proof, both lifecycle and discovery scenarios, and
current source fingerprints. Missing scans, incomplete inventory pagination,
unknown drainage or a missing discovery sidecar fail qualification. No extra
provider credentials or Azure lab is required for this local-CA lane.

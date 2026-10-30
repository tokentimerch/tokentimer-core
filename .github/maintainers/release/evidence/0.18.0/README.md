# Core 0.18.0 evidence index

Read the [release decision](../../0.18.0-release-preparation.md) and
[canonical manifest](manifest.json). The current directory contains references
and one shared package descriptor. Original generated evidence is retained in
one [archived Git snapshot](https://github.com/tokentimerch/tokentimer-core/tree/85e724eec0b37bc03c22252e7b7bcbef53515281/docs/release/evidence/0.18.0).

## Archive and integrity

The snapshot is commit `85e724eec0b37bc03c22252e7b7bcbef53515281`, directory
`docs/release/evidence/0.18.0`, Git tree `8aec8331a310f778627db5c5c20b1f937120fb32`.
The retention branch is `archive/core-0.18.0-evidence`. **Keep that archive ref** when
merging or deleting the preparation branch, including after a squash merge.
It retains existing Git objects without uploading another copy of their bytes.
This is an audit archive reference, not a release tag or publication.

The original 71-file snapshot is `aa31ae175ed8348c09be9941e337b3a2be85504d`. Every original file was compared with that snapshot and all 70 entries
in its [original checksum manifest](https://github.com/tokentimerch/tokentimer-core/blob/85e724eec0b37bc03c22252e7b7bcbef53515281/docs/release/evidence/0.18.0/SHA256SUMS) verified before
consolidation. Four new review receipts were verified against their Actions artifact digests and tested source, then retained once in the same archive. Archived reports retain their original sources, labels and
results, including failed attempts. The archive also retains historical
redundancy; the current manifest uses references instead of embedding those
reports again.

`archive.blobBaseUrl + archivePath` resolves each archived object in
[manifest.json](manifest.json). Its `canonicalArchivedReports` map stores each
named report reference once; `executions` records the six lab-specific receipts
and screenshots without copying their payloads. [SHA256SUMS](SHA256SUMS) checks
the three other files in this current directory.

## Distribution executions

All six executions ran at `fd4417653d40d4241f1cdecf310676a62e22fc55` in
[run 40149240400](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400). Each mode's matrix job
ran its source lab and package lab separately. Each execution passed its 15
mandatory scenarios and nine owner reset/reuse assertions, with zero browser
errors or unexpected writes. The manifest retains their distinct timestamps,
lab UUIDs, artifact IDs, ZIP hashes, report hashes and screenshot hashes.

| Certificate mode | Matrix job | Source lab | Package lab |
|---|---|---|---|
| Ordinary | [job 121037055261](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400/job/121037055261) | [artifact 12581968385](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400/artifacts/12581968385) | [artifact 12581613539](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400/artifacts/12581613539) |
| SAN | [job 121037055063](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400/job/121037055063) | [artifact 12582484536](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400/artifacts/12582484536) | [artifact 12581438730](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400/artifacts/12581438730) |
| Wildcard | [job 121037055336](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400/job/121037055336) | [artifact 12582845016](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400/artifacts/12582845016) | [artifact 12582039976](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400/artifacts/12582039976) |

The seven supporting cohorts comprise three source labs, three PostgreSQL
suites and one Vault adapter. The three package labs are additional gates.
Their repeated scenario occurrences are not counted as unique product
features. The canonical [aggregate report](https://github.com/tokentimerch/tokentimer-core/blob/85e724eec0b37bc03c22252e7b7bcbef53515281/docs/release/evidence/0.18.0/distribution-functional-summary.json)
is referenced once rather than embedded in a new rollup.

The screenshot helper used the same filename in every execution. The six
archived images have distinct hashes and show the same final UI checkpoint;
the run-specific assertions establish the reset/reuse sequence. Copying or
displaying the images again adds no execution coverage.

## Shared package identity

[qualification-package.json](qualification-package.json) is the one shared
descriptor for the three package modes. Its bytes match all three original
descriptors. The package is explicitly `qualification-only-not-release`, with
SHA256 `82769c419b45407011424dc004b75ef7a061663bec37c46180dbaa66c5fd5adb`. It is distinct from the prepared release archive
`062f48b1960685b247b0114b2f7086b7accda23f8788895078da627f8844507c`.
The public lab ZIPs contain receipts, not the qualification-only tgz; no local
rehash of that tgz is claimed.

## Follow-up validation

The manifest's `followupValidation` records the completed TLS-helper review at
`927507196afe4b19ec887b30dfd61149dfac9b66`: nine tests passed on both Linux and
Windows, the actual packaged IIS rehearsal passed five checks and owned cleanup,
and CodeQL passed. The probe now verifies its explicit fixture certificate and
hostname while retaining the exact fingerprint and owned-content checks.
The four new raw reports are stored once in the archive and referenced by the
manifest. Original receipts remain attributed to their original tested commits.

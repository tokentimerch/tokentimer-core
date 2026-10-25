# Core 0.18.0 artifact security scope

This record accompanies the [release preparation](../../0.18.0-release-preparation.md).
The exact package and image identities are in [candidate-artifacts.json](candidate-artifacts.json).
It records the observed policy and source-based applicability analysis; it does
not certify arbitrary operator configuration or unscanned architectures.

## Rejected and replacement agent packages

The earlier archive, SHA256
`01c7f78e50f0c54b7ece509137492b16bcb1ddf27018f34b03682e5b3d47a4b5`,
contains four Go 1.24.13 AD CS helpers and two Go 1.25.0 service hosts.
Its actual extracted bytes fail Grype 0.112.0 with
`--fail-on high --only-fixed` (exit 2). The 646 raw matches include aliases
and matches across six binaries; there are 35 distinct Go High/Critical
advisory IDs, not 646 distinct demonstrated exploits.

The CMC helper's [certificate verification fallback](https://github.com/tokentimerch/tokentimer-core/blob/69387d85231f242d00f653bbde94ead373fefe1e/packages/agent/reference/adcs-cmc/cmccore/decode.go)
can invoke `pkcs7.VerifyWithChain`. The pinned library's
[implementation](https://github.com/mozilla-services/pkcs7/blob/v0.10.0/verify.go)
calls `x509.Certificate.Verify` with response certificates in the intermediate
pool. This establishes an affected API for [GO-2026-4947](https://vuln.go.dev/ID/GO-2026-4947.json)
in that path; it does not demonstrate an exploitable denial of service.
Unix, cgo, HTTP-server and other package-version matches were not assumed to
be reachable merely because their metadata appeared in a Windows executable.

The replacement archive, SHA256
`062f48b1960685b247b0114b2f7086b7accda23f8788895078da627f8844507c`,
contains six Go 1.26.10 executables. It has zero High/Critical matches and
passes the same policy both in the hosted build and independent inspection.
Two Low matches remain for the same `golang.org/x/sys v0.28.0` advisory,
GO-2026-5024, in the two chain-helper architectures; the scanner records a
fix at v0.44.0. See [the actual archive verification](agent-verification.json).
The [official Go 1.26.10 release](https://go.dev/doc/devel/release#go1.26.10)
also includes an x509 security change beyond 1.26.9. No findings were
suppressed and no VEX exemption was added.

## Corrected production dashboard

The workspace fix supersedes the original dashboard image. The actual
production Dockerfile was rebuilt at `fd441765`, with reviewed product source
`b1b92cb3`, in [job 121037055389](https://github.com/tokentimerch/tokentimer-core/actions/runs/40149240400/job/121037055389).
Its owned-container HTML/JavaScript smoke and fixed High/Critical scan passed.
The unfiltered scan retains eight matches, including two High and one Critical;
the fixed-policy report has zero matches. The residual applicability analysis
below remains relevant to its unchanged production NGINX configuration.

The unpublished Docker archive has SHA256
`25e4412822c9e50604c0e3258cb2401eadc5d4d6a590e4a9e10180f7d4b592b0`.
Independent inspection verifies the image configuration, all 14 layer hashes,
production NGINX/entrypoint bytes and the exact assets returned by the smoke
test. The built page's source map contains the exact reviewed workspace fix,
and its compiled chunk is referenced by the served entry asset. The hosted
Grype report binds the same image configuration digest. An optional local
archive-provider attempt did not produce a catalog and is not counted as a
scan result. See [the verification receipt](corrected-dashboard-verification.json).
The configuration digest is not a registry manifest digest; no registry
publication or image signature is claimed for this preparation archive.

The [complete current normal-CI receipt](corrected-normal-ci.json) additionally
records fresh API, dashboard, worker and controller builds at `fd441765`, their
defined boot checks and successful fixed High/Critical gates. It preserves
all SARIF findings and separates those unpublished CI image identities from
the prepared archive and original registry images. In particular, an unscored
Go advisory rendered as a SARIF note is not reclassified as a scored Low
finding merely because of the generated note's wording.

## Original image policy results

All four original immutable image indexes were resolved to their **linux/amd64**
children. Grype 0.112.0 used the same frozen, valid v6.1.10 database, built
2026-10-24T17:45:29Z. Unfiltered findings and the separate policy invocation
are recorded in [image-scan-summary.json](image-scan-summary.json).

| Image | All matches | High | Critical | Fixed High/Critical gate exit |
|---|---:|---:|---:|---:|
| API | 7 | 0 | 0 | 0 |
| Worker | 7 | 1 | 0 | 0 |
| Dashboard | 8 | 2 | 1 | 0 |
| Kubernetes controller | 5 | 0 | 0 | 0 |

A policy pass does not mean an empty vulnerability report. These residuals
remain visible:

- **musl 1.2.5-r23:** CVE-2026-107891 is Unknown severity in this database;
  Alpine 3.23 has a fix at r24. The
  [maintainer advisory](https://www.openwall.com/lists/oss-security/2026/10/21/18)
  concerns untrusted regular-expression compilation through libc `regcomp`.
  Application reachability was not established.
- **API subfinder:** its embedded Go 1.26.9 runtime matches Unknown-severity
  GO-2026-6809. The native agent replacement does not change this separate
  image binary. Refresh its build to Go 1.26.10 in a subsequent image rebuild.
- **curl 8.22.0:** CVE-2026-92392 is High, without a fixed package recorded for
  the scanned distribution. The [upstream advisory](https://curl.se/docs/CVE-2026-92392.html)
  supplies fixes in 8.23.0 and maintained branches. Its prerequisite is an
  HTTP/2 upload to a malicious server. No worker application upload call was
  found in the reviewed source. This is an applicability observation, not a
  claim that the installed curl package is fixed.
- **NGINX 1.28.3-r7:** CVE-2026-15176 (Critical), CVE-2026-97629 (High) and
  CVE-2026-95101 (Medium) have
  [upstream fixes](https://nginx.org/en/security_advisories.html) in 1.30.6 and
  1.31.7. [Alpine's CVE record](https://security.alpinelinux.org/vuln/CVE-2026-15176)
  lists fixes for 3.24/edge, not the scanned 3.23 branch. The shipped
  [production configuration](https://github.com/tokentimerch/tokentimer-core/blob/69387d85231f242d00f653bbde94ead373fefe1e/deploy/compose/nginx.conf)
  uses plain HTTP 8080, has `alias` only for `env.js`, and lacks the reviewed
  rewrite, `$request_filename`, SSL-session-cache and HTTP/3 prerequisites.
  This source/configuration inference does not cover operator overrides.

Retain these findings when deciding final image rebuild and support scope.
A fresh release build must record and scan its own digests; neither these
policy results nor the prepared agent checksum may be copied onto different
bytes. No additional image architecture is claimed by this inspection.

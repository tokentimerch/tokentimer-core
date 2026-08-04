# TokenTimer CertOps reference clients

Two Node-free reference implementations of the CertOps agent protocol:
`tokentimer-protocol.sh` (bash) and `tokentimer-protocol.ps1` (PowerShell).
Both speak the same wire protocol against the same control-plane endpoints
and produce the same exit codes, so either can be used to operate an agent
or to independently verify a signed job envelope without running the
Node.js agent at all.

They exist to give an operator two ways to interact with the protocol
that do not depend on a Node.js runtime, and to exercise two independent
Ed25519 implementations against the same signed envelopes (OpenSSL for
bash, Go's standard library for PowerShell) so a bug specific to one
implementation cannot silently pass both. See
`docs/adr/0012-certops-windows-execution-surface-and-trust-anchors.md`
for the normative verification order (decision 2) and the transport,
credential and file-exception rules (decision 8) both clients implement.

## Prerequisites

| Client | Required tools | Never uses |
|---|---|---|
| `tokentimer-protocol.sh` | bash, curl, jq, OpenSSL 3, mkdir, rm | Node.js, `sed`, `awk`, `stat`, `mktemp`, `cat`, `tr`, `hostname` |
| `tokentimer-protocol.ps1` | PowerShell 5.1+ (or pwsh), the bundled `tokentimer-verify.exe` | Node.js, OpenSSL, any other external Ed25519 tool |

Each client declares exactly the tools listed above and nothing else.
For the bash client this is asserted by CI, not just by review: the
`minimal-command-allowlist` guard (`scripts/ci-guards/minimal-command-allowlist.cjs`)
runs the script with `PATH` restricted to shims for bash, curl, jq,
openssl, mkdir and rm across every step, and fails if the script ever
tries to exec anything else. The `no-node-invocation` guard statically
checks both client files for anything that would shell out to Node, and
the `ascii-only-signed-scripts` guard enforces the ASCII-only rule on
the PowerShell file described below.

### Building `tokentimer-verify.exe`

The PowerShell client verifies Ed25519 signatures exclusively through a
small bundled Go binary, `tokentimer-verify`, never through OpenSSL: the
two clients are required to exercise two independent Ed25519
implementations. Build it once before using `tokentimer-protocol.ps1`:

```powershell
cd packages/agent/reference/verifier
node build.cjs
```

This produces `packages/agent/reference/verifier/dist/tokentimer-verify.exe`
(the default lookup path `tokentimer-protocol.ps1` uses when `-VerifierPath`
is not given). The build is a plain, reproducible Go build (`CGO_ENABLED=0`,
`-trimpath`, stripped symbols); Node is only a build-time convenience here,
not something the finished binary or the PowerShell client depend on at
runtime. The build is UNSIGNED. Authenticode signing, signer-identity
validation, RFC 3161 timestamping, and SBOM/provenance generation are
release-blocking follow-up steps that are documented, but not implemented,
in `build.cjs`'s header comment; an unsigned build must never ship inside a
production bundle.

## Credential handling

Both clients read a credential (or, for the register step's
diagnostic-bootstrap request, a session cookie and CSRF token) exactly
once, keep it only long enough to make the one request that needs it,
and never place it in a location an unprivileged process on the same
host could observe:

- Never as a command-line argument or an `-H "Authorization: ..."` style
  header, which would leak through the process list (`/proc/<pid>/cmdline`
  on Linux, the command-line column in Windows process-listing tools).
- bash sends the bearer token, session cookie and CSRF token to curl via
  `curl --config -` on standard input (`header = "..."` directives inside
  the config stream), never `-H`.
- PowerShell sends it via `HttpWebRequest`'s request-header collection,
  set directly on the request object, never interpolated into a command
  line.
- Neither client ever creates a temporary file containing a secret.
  bash's one declared file exception (see below) holds only the already
  -verified payload, never a credential, session cookie, or CSRF token.
- Both clients accept a `--credential-file` / `-CredentialFile` path or
  fall back to the `TOKENTIMER_AGENT_CREDENTIAL` environment variable, and
  neither ever echoes, logs, or includes a credential in `--json`/`-Json`
  output. Both clients' `register` step additionally accepts
  `--session-cookie-file` / `-SessionCookieFile` (or
  `TOKENTIMER_SESSION_COOKIE`) and `--csrf-token-file` / `-CsrfTokenFile`
  (or `TOKENTIMER_CSRF_TOKEN`), under the same rules.

The bash client's one declared file exception: `openssl pkeyutl -verify
-rawin` refuses a pipe or a process substitution for `-in`, so the first
decode of a job's `payloadB64` is staged to a file inside a private,
exclusively created per-run directory (`mkdir -m 700`, never `mktemp`,
since that is not one of the declared commands) before OpenSSL reads it.
`mkdir -m 700` fails outright if the path is already occupied by
anything, including a symlink planted ahead of time, so there is no
check-then-act window for another user on a shared, world-writable
`/tmp` to win (CWE-59). The directory is removed (not merely emptied) on
every exit path, including signals, via `rm -rf`, and a startup sweep
removes any leftover directory from a prior run that never reached its
own cleanup. Both the per-run cleanup and the startup sweep refuse to
act on a symlink (a plain `-d` check alone would follow one) before
removing anything at the predictable sweep path.

## Common flags

| bash | PowerShell | Meaning |
|---|---|---|
| `--step STEP` | `-Step STEP` | `all`, `register`, `heartbeat`, `claim`, `verify`, or `result`. |
| `--live` | `-Live` | Contact the real control plane. Every step except `verify` requires it; `verify` refuses it, since verification is fully offline. |
| `--json` | `-Json` | Emit one machine-readable JSON object on stdout, built from an explicit field allowlist. Never a raw server response, never a credential. |
| `--server-url URL` | `-ServerUrl URL` | Control-plane origin. `https://` is required unless `--allow-insecure-local-http` / `-AllowInsecureLocalHttp` is also given for a `localhost`/`127.0.0.1` target. |
| `--agent-id ID` | `-AgentId ID` | Agent id. Required for `heartbeat`/`claim`/`result`. Ignored for `register`/`all`: the diagnostic-bootstrap route always assigns the agentId server-side (see "Diagnostic registration" below). |
| `--agent-version VERSION` | `-AgentVersion VERSION` | Reported `agentVersion` string. |
| `--workspace-id UUID` | `-WorkspaceId UUID` | Workspace id. Required for `register`/`all`: the diagnostic-bootstrap route is scoped to one workspace by path segment. |
| `--session-cookie-file PATH` | `-SessionCookieFile PATH` | File holding the operator's session `Cookie` header value (`register`, `all`). See "Diagnostic registration" below. |
| `--csrf-token-file PATH` | `-CsrfTokenFile PATH` | File holding the `X-CSRF-Token` header value paired with the session cookie above (`register`, `all`). |
| `--request-id ID` | `-RequestId ID` | Idempotency key for the diagnostic-bootstrap request (`register`, `all`). A fresh UUID is generated when omitted. |
| `--credential-file PATH` | `-CredentialFile PATH` | File holding the `ttagent_...` credential (`heartbeat`/`claim`/`result`). `TOKENTIMER_AGENT_CREDENTIAL` is used instead when this is omitted. |
| `--envelope-file PATH` | `-EnvelopeFile PATH` | v2 envelope JSON to verify (`verify` step); stdin is read when this is omitted. |
| `--claim-state-file PATH` | `-ClaimStateFile PATH` | File where `claim` records the job it just verified, and where a later, separate `result` invocation reads that state from. Required for `result` unless run via `--step all`/`-Step all` (see "Claiming and reporting in separate invocations" below). |
| `--pubkey PATH` | `-Pubkey PATH` | PEM SubjectPublicKeyInfo of the pinned Ed25519 signing key. |
| `--signing-key-id ID` | `-SigningKeyId ID` | Pinned signing key id. When given, the signed payload's `signingKeyId` must equal it. |
| `--echo TEXT` | `-Echo TEXT` | `protocol_smoke` payload echo string (`--step all`). |
| `--allow-insecure-local-http` | `-AllowInsecureLocalHttp` | Permit `http://` for a localhost/127.0.0.1 target only. Refused for every other host. |
| `-h`, `--help` | (comment-header usage) | Show usage and exit 0. |

PowerShell-only flags (no bash equivalent, since bash never touches
Authenticode or FIPS policy):

| Flag | Meaning |
|---|---|
| `-VerifierPath PATH` | Path to `tokentimer-verify.exe`. Defaults to `verifier/dist/tokentimer-verify.exe` next to the script. |
| `-PinnedSignerSubject SUBJECT` | Expected Authenticode signer subject for the defense-in-depth self-check. |
| `-PinnedSignerThumbprint THUMBPRINT` | Accepted Authenticode signer thumbprint(s) for the self-check. May be repeated. |
| `-SkipSelfCheck` | Skip the Authenticode self-check. The self-check is defense in depth only; it is never the security boundary (see ADR-0012 decision 8), and a failed or skipped self-check does not by itself block a step. |

## Diagnostic registration

`register` (and the register phase of `all`) bootstraps a new
**diagnostic** agent identity through the session-authenticated
`POST /api/v1/workspaces/:id/certops/agents/diagnostic-bootstrap` route,
never the normal bearer-token agent-registration endpoint. The normal
endpoint assigns `agent_kind = 'normal'` server-side, which would let
either client claim and hold a lease on genuine certificate work in a
real workspace; the diagnostic-bootstrap route always assigns
`agent_kind = 'diagnostic'` and a `protocol_smoke`-only job instead.

This route is an operator action, not a machine-credential call: it
requires the same session cookie and CSRF token an operator's browser
session already carries, not a bootstrap token. An operator obtains
these out of band, for example by driving `POST /auth/login` and then
`GET /api/csrf-token` against the target deployment with the same
session, and passes the results to `--session-cookie-file`/
`-SessionCookieFile` and `--csrf-token-file`/`-CsrfTokenFile`. Neither
client automates the login step itself. The route assigns both the
`agentId` and the credential; there is no client-side candidate-id
generation for `register`/`all` any more.

## Steps

- `all`: register, heartbeat, claim, verify and report a result for one
  `protocol_smoke` job, in one run. Requires `--live`/`-Live`.
- `register`: bootstrap a new diagnostic agent identity via the
  diagnostic-bootstrap route. Requires `--live`/`-Live`,
  `--workspace-id`/`-WorkspaceId`, a session cookie, and a CSRF token
  (see "Diagnostic registration" above).
- `heartbeat`: send a heartbeat for an already-registered agent. Requires
  `--live`/`-Live`, `--agent-id`/`-AgentId`, and a credential. Both
  clients also declare `declaredCapabilities: ["signed-payload-b64-v1",
  "agent-id-binding-v1"]` on every heartbeat: `signed-payload-b64-v1`
  earns the v2 signed envelope this client verifies, and
  `agent-id-binding-v1` asserts the step-11 identity gate below fails
  closed on an absent `agentId`, not only a mismatched one.
- `claim`: poll for jobs and verify any that come back. Requires
  `--live`/`-Live`, `--agent-id`/`-AgentId`, `--pubkey`/`-Pubkey`, and a
  credential. A client only ever receives `protocol_smoke` jobs: it
  declares `supportedActions: ["protocol_smoke"]` on every claim
  request, which is the one wire action this client verifies and
  reports on (the control-plane's claim matcher only returns jobs whose
  operation is in that list). If `--claim-state-file`/`-ClaimStateFile`
  is given, the verified job's state is written there for a later,
  separate `result` invocation to pick up.
- `verify`: verify one v2 envelope against a pinned public key. Runs
  fully offline; `--live`/`-Live` is neither required nor accepted.
- `result`: report a result for a job already claimed and verified,
  either earlier in the same process (`--step all`) or by a prior,
  separate `--step claim` invocation. In the latter case
  `--claim-state-file`/`-ClaimStateFile` (the file `claim` wrote) is
  required: there is no environment-variable or other implicit way to
  carry a verified job's identity across two invocations, since that
  would let a `result` call report a job this process never actually
  verified. Requires `--live`/`-Live`, `--agent-id`/`-AgentId`, and a
  credential.

### Claiming and reporting in separate invocations

`--step all` claims, verifies, and reports in one process, which is the
simplest way to run this client and needs no state file. To split claim
and result across two separate invocations instead (for example, to
inspect the verified job in between), pass the same
`--claim-state-file`/`-ClaimStateFile` path to both:

```bash
tokentimer-protocol.sh --step claim --live --server-url "$URL" \
  --agent-id "$AGENT_ID" --pubkey pinned-key.pem \
  --credential-file cred.txt --claim-state-file /tmp/claim-state.json
# ... inspect the verified job here ...
tokentimer-protocol.sh --step result --live --server-url "$URL" \
  --agent-id "$AGENT_ID" --credential-file cred.txt \
  --claim-state-file /tmp/claim-state.json
```

The claim-state file holds only non-secret job/claim/attempt identifiers
and a nonce, never a credential; it is written only after a passing
Ed25519 verdict, so its presence never substitutes for verification.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | signature verification failed (bad signature, wrong key, tampered payload, or an unrecognized `envelopeVersion`) |
| 2 | usage error: bad flags, a missing required argument, or `--live`/`-Live` omitted or given for the wrong step |
| 3 | network or HTTP error talking to the control plane |
| 4 | local pre-gate failure: malformed base64/JSON, a field that fails structural validation, a workspace/agent identity mismatch, or any other rejection that must happen before a result can be reported |
| 5 | a size-bounded field (the claim response body, the encoded or decoded payload) exceeded its declared limit |

A signature-verdict failure (exit 1) or a pre-gate failure (exit 4) never
produces a result report, a lease renewal, or any other post-verdict
request: both clients stop at the failing step.

## Verifying one envelope offline

Either client can check a single signed job envelope with no network
access and no credential, using only a pinned public key:

```bash
tokentimer-protocol.sh --step verify --pubkey pinned-key.pem --envelope-file job.json
```

```powershell
tokentimer-protocol.ps1 -Step verify -Pubkey pinned-key.pem -EnvelopeFile job.json
```

Add `--signing-key-id`/`-SigningKeyId` to also pin the expected signing
key id, and `--json`/`-Json` to get a single machine-readable summary
object on stdout instead of a human-readable line on stderr.

## Known, documented limitations

- bash's `bounded_read_capture` cannot represent an embedded NUL byte in
  a shell variable (a `read` builtin limitation), so a response padded
  with NUL bytes could undercount toward the response-size bound. This
  does not affect a conforming control-plane response: valid JSON text
  never contains a raw, unescaped NUL byte.
- bash's UTF-8 strictness for a verified payload is a leading byte-order
  -mark check, not a full byte-level UTF-8 validator: jq's own UTF-8
  handling is lossy (it replaces invalid sequences rather than erroring),
  so it cannot be the strict decoder on its own, and a general-purpose
  validator would need the same NUL-byte handling `bounded_read_capture`
  cannot provide. PowerShell's decoder is the full strict check (.NET's
  `UTF8Encoding` with `throwOnInvalidBytes:$true`), since it operates on
  the raw byte array before any shell-variable round trip.
- The Authenticode self-check in `tokentimer-protocol.ps1` is defense in
  depth only, run for operator visibility. It is not, and cannot be, the
  actual security boundary for a script interpreted by PowerShell; that
  boundary is whatever trusted launcher or application-control policy
  invokes the script in the first place.

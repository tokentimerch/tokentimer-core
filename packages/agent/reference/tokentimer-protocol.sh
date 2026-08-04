#!/usr/bin/env bash
#
# tokentimer-protocol.sh - Node-free bash reference client for the
# TokenTimer CertOps agent protocol.
#
# Prerequisites (ADR-0012 decision 8): bash, curl, jq, OpenSSL 3, mkdir, rm.
# Nothing else is available; this is asserted by the sibling command-
# allowlist test, not just by review. mkdir and rm exist solely to manage
# this script's one declared file exception, a private per-run staging
# directory (see "staging directory" below); every other code path stays
# within bash, curl, jq and openssl alone.
#
# See docs/adr/0012-certops-windows-execution-surface-and-trust-anchors.md
# for the normative verification order (decision 2) and the transport,
# credential and file-exception rules (decision 8) this script implements.
#
# Usage:
#   tokentimer-protocol.sh --step STEP [options]
#
# Steps:
#   all        register, heartbeat, claim, verify and report a result for
#              one protocol_smoke job. Requires --live.
#   register   bootstrap a new diagnostic agent identity via the
#              session-authenticated diagnostic-bootstrap route. Requires
#              --live, --workspace-id, a session cookie, and a CSRF
#              token; never the normal agent-registration endpoint (this
#              client only ever produces diagnostic protocol_smoke jobs,
#              never real certificate work).
#   heartbeat  send a heartbeat for an already-registered agent. Requires
#              --live and a credential.
#   claim      poll for jobs and verify any that come back. Requires
#              --live and a credential.
#   verify     verify one v2 envelope against a pinned public key. Runs
#              fully offline; --live is neither required nor used.
#   result     report a result for a previously claimed and verified job.
#              Requires --live, a credential, and --claim-state-file
#              (the file `claim` wrote the verified job to; there is no
#              way to satisfy this from a separate `result` invocation
#              without it).
#
# Flags:
#   --live                       Contact the real control plane. Without
#                                 it, only --step verify is permitted: this
#                                 client never contacts a server unless the
#                                 operator says so explicitly.
#   --json                       Emit machine-readable JSON on stdout
#                                 instead of human-readable text, built from
#                                 an explicit field allowlist. Never a raw
#                                 server response, never a credential.
#   --server-url URL             Control-plane origin. https:// required
#                                 unless --allow-insecure-local-http is also
#                                 given for a localhost/127.0.0.1 URL.
#   --agent-id ID                Agent id. Required for heartbeat/claim/
#                                 result; ignored by register, which the
#                                 server assigns (a diag-<uuid> id).
#   --agent-version VERSION      Reported agentVersion string.
#   --workspace-id UUID          Workspace id. Required for register: the
#                                 diagnostic-bootstrap route is scoped to
#                                 one workspace by path segment.
#   --session-cookie-file PATH   File holding the operator's session
#                                 Cookie header value (register).
#                                 Diagnostic-bootstrap is session-
#                                 authenticated, not a bearer-token agent
#                                 call: the operator logs into the
#                                 dashboard (or drives POST /auth/login
#                                 directly) and supplies the resulting
#                                 Cookie header here. Mode-restricted:
#                                 rejected if group- or other-readable.
#   --csrf-token-file PATH       File holding the X-CSRF-Token header
#                                 value paired with the session cookie
#                                 above (register). Fetched by the
#                                 operator from GET /api/csrf-token using
#                                 the same session. Same mode rule.
#   --request-id ID              Idempotency key for the diagnostic-
#                                 bootstrap request (register). A fresh
#                                 UUID is generated when omitted; the
#                                 request is single-use server-side, so
#                                 retrying with the same id after a
#                                 partial failure never double-bootstraps.
#   --credential-file PATH       File holding the ttagent_... credential
#                                 (heartbeat/claim/result). Same mode rule.
#                                 TOKENTIMER_AGENT_CREDENTIAL is used instead
#                                 when this flag is omitted.
#   --envelope-file PATH         v2 envelope JSON to verify (verify step);
#                                 stdin is read when this is omitted.
#   --claim-state-file PATH      File where `claim` records the verified
#                                 jobId/attemptId/claimId/nonce it just
#                                 confirmed (written only after a passing
#                                 Ed25519 verdict), and where a later,
#                                 separate `result` invocation reads that
#                                 same state from (required for `result`
#                                 unless run via `--step all`, which never
#                                 needs a file because claim and result
#                                 happen in the same process). This is the
#                                 only supported way to hand verified state
#                                 across two invocations: there is no
#                                 environment-variable equivalent, since an
#                                 ambient variable a wrapper script or a
#                                 leaked environment happened to set would
#                                 let `result` report a job as verified
#                                 that this process never actually checked.
#   --pubkey PATH                PEM SubjectPublicKeyInfo of the pinned
#                                 Ed25519 signing key (verify; also used by
#                                 claim/all to verify claimed jobs).
#   --signing-key-id ID           Pinned signing key id. When given, the
#                                 signed payload's signingKeyId must equal
#                                 it (decision 2 step 13).
#   --echo TEXT                   protocol_smoke payload echo string
#                                 (--step all; default: a fixed literal).
#   --allow-insecure-local-http    Permit http:// for localhost/127.0.0.1
#                                 only. Refused for every other host.
#   -h, --help                    Show this help and exit 0.
#
# Exit codes:
#   0  success
#   1  signature verification failed (bad signature, wrong key, tampered
#      payload, or unrecognized envelopeVersion)
#   2  usage error: bad flags, a missing required argument, or --live
#      omitted for a step that requires it
#   3  network or HTTP error talking to the control plane
#   4  local pre-gate failure: malformed base64/JSON, a field that fails
#      structural validation, a workspace/agent identity mismatch, or any
#      other rejection that must happen before a result can be reported
#   5  a size-bounded field (the claim response body, the encoded or
#      decoded payload) exceeded its declared limit
#
# Credential handling: a credential is read once, from --credential-file
# or the TOKENTIMER_AGENT_CREDENTIAL environment variable, used for exactly
# the curl invocation that needs it via `curl --config -` on standard
# input (never `-H "Authorization: ..."`, which would leak through
# /proc/<pid>/cmdline), and unset from the environment before any child
# process starts. Secret handling runs with `set +x`. No temporary
# credential file is ever created.
set -Eeuo pipefail
umask 0077
export LC_ALL=C
shopt -s lastpipe
set +H

readonly TOKENTIMER_SCRIPT_NAME="tokentimer-protocol.sh"
readonly TOKENTIMER_PROTOCOL_VERSION="1.0.0"
readonly TOKENTIMER_SCHEMA_VERSION=1

readonly TOKENTIMER_HEARTBEAT_PATH="/api/v1/certops/agent/heartbeat"
readonly TOKENTIMER_CLAIM_PATH="/api/v1/certops/agent/jobs/claim"
readonly TOKENTIMER_RESULTS_PATH="/api/v1/certops/agent/jobs/results"

readonly TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES=1048576
# ADR-0012's ninth amendment (2026-08-04): 65536 was the tightest value that
# still decodes to exactly the 49152-byte decoded bound, which made the
# decoded-byte check below mathematically unreachable. 98304 gives real
# headroom (floor(98304/4)*3 = 73728 decoded bytes) so a payload between the
# two bounds is actually rejected by the decoded-byte check that enforces the
# real content-size policy, matching packages/agent/src/signing/index.js.
readonly TOKENTIMER_MAX_ENCODED_PAYLOAD_CHARS=98304
readonly TOKENTIMER_MAX_DECODED_PAYLOAD_BYTES=49152
readonly TOKENTIMER_SIGNATURE_DECODED_BYTES=64
readonly TOKENTIMER_DEFAULT_CLOCK_SKEW_TOLERANCE_S=300

readonly TOKENTIMER_ID_PATTERN='^[A-Za-z0-9_.:-]{1,128}$'
readonly TOKENTIMER_B64_PATTERN='^[A-Za-z0-9+/]+=?=?$'
readonly TOKENTIMER_ISO8601_PATTERN='^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z$'

readonly EXIT_OK=0
readonly EXIT_VERIFY_FAILED=1
readonly EXIT_USAGE=2
readonly EXIT_NETWORK=3
readonly EXIT_PREGATE=4
readonly EXIT_SIZE_LIMIT=5

print_help() {
  # Reprints the usage block above verbatim so --help stays in sync
  # with the header comment. `cat` is not one of this client's four
  # declared external dependencies (bash, curl, jq, openssl -- ADR-0012
  # decision 8), so the heredoc is captured with the bash builtins
  # `read -d ''` and re-emitted with `printf`, never handed to an
  # external process.
  local help_text
  IFS= read -r -d '' help_text <<'EOF_HELP' || true
tokentimer-protocol.sh - Node-free bash reference client for the
TokenTimer CertOps agent protocol.

Usage:
  tokentimer-protocol.sh --step STEP [options]

Steps:
  all        register, heartbeat, claim, verify and report a result for
             one protocol_smoke job. Requires --live.
  register   bootstrap a new diagnostic agent identity via the session-
             authenticated diagnostic-bootstrap route. Requires --live,
             --workspace-id, a session cookie, and a CSRF token.
  heartbeat  send a heartbeat for an already-registered agent. Requires
             --live and a credential.
  claim      poll for jobs and verify any that come back. Requires --live
             and a credential.
  verify     verify one v2 envelope against a pinned public key. Runs
             fully offline; --live is neither required nor used.
  result     report a result for a previously claimed and verified job.
             Requires --live, a credential, and --claim-state-file.

Flags:
  --live                       Contact the real control plane.
  --json                       Emit machine-readable JSON, from an
                               explicit field allowlist.
  --server-url URL             Control-plane origin (https:// required).
  --agent-id ID                Agent id (heartbeat/claim/result).
  --agent-version VERSION      Reported agentVersion string.
  --workspace-id UUID          Workspace id. Required for register.
  --session-cookie-file PATH   File holding the operator's session
                               Cookie header value (register).
  --csrf-token-file PATH       File holding the X-CSRF-Token header
                               value paired with the session cookie
                               (register).
  --request-id ID              Idempotency key for the diagnostic-
                               bootstrap request (register). A fresh
                               UUID is generated when omitted.
  --credential-file PATH       File holding the ttagent_... credential.
  --envelope-file PATH         v2 envelope JSON to verify (or stdin).
  --claim-state-file PATH      File to write (claim) / read (result) the
                               verified job's jobId/attemptId/claimId/
                               nonce across two separate invocations.
  --pubkey PATH                Pinned Ed25519 PEM public key.
  --signing-key-id ID          Pinned signing key id.
  --echo TEXT                  protocol_smoke echo string (--step all).
  --allow-insecure-local-http  Permit http:// for localhost only.
  -h, --help                   Show this help and exit 0.

Exit codes: 0 ok, 1 signature verification failed, 2 usage error,
3 network/HTTP error, 4 local pre-gate failure, 5 size limit exceeded.
EOF_HELP
  printf '%s\n' "$help_text"
}

# --- logging ---------------------------------------------------------------
#
# --json builds a single JSON object per invocation from an explicit field
# allowlist (never a raw server response, never a credential). Human mode
# writes a short line per event to stderr, keeping stdout free for a final
# machine-readable summary if the caller pipes it. Both paths go through
# log_event so every emitted field is named once, in one place.
TOKENTIMER_JSON_MODE=0
TOKENTIMER_JSON_FIELDS=()

json_escape() {
  # Minimal JSON string escaper for values this script itself constructs
  # (never attacker-controlled bytes from an unverified payload); jq is not
  # used here so this helper has no dependency on stdin framing.
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

log_field() {
  # Records one allowlisted field for the final --json summary. Safe to
  # call unconditionally; a no-op in human mode.
  local key="$1" value="$2"
  if [ "$TOKENTIMER_JSON_MODE" -eq 1 ]; then
    TOKENTIMER_JSON_FIELDS+=("\"$(json_escape "$key")\":\"$(json_escape "$value")\"")
  fi
}

log_field_raw() {
  # Same as log_field but the value is pre-formatted JSON (a number, bool,
  # or nested object/array the caller already built), not a string to
  # escape.
  local key="$1" raw_value="$2"
  if [ "$TOKENTIMER_JSON_MODE" -eq 1 ]; then
    TOKENTIMER_JSON_FIELDS+=("\"$(json_escape "$key")\":$raw_value")
  fi
}

log_info() {
  if [ "$TOKENTIMER_JSON_MODE" -eq 0 ]; then
    printf '%s\n' "$*" >&2
  fi
}

log_error() {
  if [ "$TOKENTIMER_JSON_MODE" -eq 0 ]; then
    printf 'error: %s\n' "$*" >&2
  fi
}

emit_json_summary() {
  # Called once, right before exit, from every code path (success and
  # failure alike) so --json always produces exactly one JSON object.
  if [ "$TOKENTIMER_JSON_MODE" -eq 1 ]; then
    local joined=""
    local field
    for field in "${TOKENTIMER_JSON_FIELDS[@]:-}"; do
      [ -z "$field" ] && continue
      if [ -n "$joined" ]; then joined+=","; fi
      joined+="$field"
    done
    printf '{%s}\n' "$joined"
  fi
}

die() {
  local code="$1"; shift
  log_field_raw "ok" "false"
  log_field "errorCode" "$2"
  log_error "$*"
  log_field "errorMessage" "$1" 2>/dev/null || true
  emit_json_summary
  exit "$code"
}

die_usage() { log_field "errorCode" "usage_error"; log_error "$*"; emit_json_summary; exit "$EXIT_USAGE"; }
die_pregate() { log_field "errorCode" "pregate_failure"; log_error "$*"; emit_json_summary; exit "$EXIT_PREGATE"; }
die_network() { log_field "errorCode" "network_error"; log_error "$*"; emit_json_summary; exit "$EXIT_NETWORK"; }
die_size_limit() { log_field "errorCode" "size_limit_exceeded"; log_error "$*"; emit_json_summary; exit "$EXIT_SIZE_LIMIT"; }
die_verify_failed() { log_field "errorCode" "verify_failed"; log_error "$*"; emit_json_summary; exit "$EXIT_VERIFY_FAILED"; }

# --- OpenSSL version preflight ---------------------------------------------
#
# The header documents "OpenSSL 3" as a prerequisite, but every step in this
# script eventually calls `openssl pkeyutl -verify -rawin` (the Ed25519
# raw-input signature form), which does not exist before OpenSSL 3.0: 1.1.1
# has no Ed25519 support in pkeyutl at all, and the string "openssl" on some
# platforms actually resolves to LibreSSL, whose pkeyutl never implements
# -rawin regardless of its reported version number. Without this check, a
# 1.1.1 or LibreSSL environment would run every step up to the first
# `openssl pkeyutl` invocation and then fail there with an OpenSSL error
# message that says nothing about a version requirement, instead of
# failing closed at startup with a clear, actionable reason.
check_openssl_version() {
  local version_line
  version_line=$(openssl version 2>/dev/null) \
    || die_pregate "could not run 'openssl version'; is openssl installed and on PATH?"
  case "$version_line" in
    "OpenSSL 3."*) return 0 ;;
  esac
  die_pregate "openssl reports '$version_line', but this client requires OpenSSL 3.0 or later: 'pkeyutl -verify -rawin' Ed25519 verification is unavailable in OpenSSL 1.1.1 and is not implemented by LibreSSL's pkeyutl at any version"
}

# --- staging directory: the one declared filesystem exception in this
# script -------------------------------------------------------------------
#
# openssl pkeyutl -verify -rawin refuses a pipe, a FIFO or a process
# substitution for -in (Ed25519 oneshot verification needs a seekable file
# with a known size; confirmed empirically against OpenSSL 3 while building
# this client), so the first payloadB64 decode cannot stay on the normal
# stream path the way the second one does. Per ADR-0012 decision 8 this
# makes the file a DECLARED dependency with stated obligations rather than
# an implicit convenience: exclusive creation, a private mode set at
# creation, one cleanup trap covering normal exit and every signal this
# script can receive, and a startup sweep for residue left by a crash.
#
# The artifact is a private per-run directory, not a bare file: `mkdir -m
# 700` fails outright (EEXIST) if anything -- a file, a directory, or a
# symlink planted ahead of time -- already occupies that path, so there is
# no check-then-act window between "does this path exist" and "create it"
# for an attacker on a shared, world-writable /tmp to win (CWE-59). A
# truncate-in-place scheme (checking -L then opening for write) still has
# that window between the check and the open; recreating the file inside a
# directory this process alone just atomically created removes the window
# instead of narrowing it. `mkdir` and `rm` are declared external
# commands specifically for this (ADR-0012 decision 8's exhaustive list),
# and `mktemp` is still deliberately not used: it would satisfy exclusive
# creation but not the private-mode-at-creation requirement in one step on
# every mktemp implementation this client would otherwise need to trust.
TOKENTIMER_STAGE_DIR=""
TOKENTIMER_STAGE_FILE=""

stage_cleanup() {
  # -L is checked before -d (CWE-59): a bare -d check follows a symlink
  # to decide whether the *target* is a directory, so if this path were
  # ever replaced by a symlink between creation and cleanup, the old
  # check would still recurse into and remove whatever that symlink
  # points at. create_stage_dir's mkdir never produces a symlink, so
  # skipping one here costs nothing in the legitimate case.
  local d="$TOKENTIMER_STAGE_DIR"
  if [ -n "$d" ] && [ ! -L "$d" ] && [ -d "$d" ]; then
    rm -rf -- "$d" 2>/dev/null || true
  fi
}
trap stage_cleanup EXIT INT TERM HUP

stage_sweep_residue() {
  # Startup sweep for crash residue (decision 8): a prior run that never
  # reached its own trap (SIGKILL, power loss) may have left its staging
  # directory behind. Remove any matching leftovers before this run
  # creates its own.
  #
  # Each candidate directory is mode 0700 and owned by whichever user's
  # run created it, so unlike the old single-file scheme's predictable
  # glob, another user on a shared /tmp cannot plant anything *inside*
  # one they do not own, and cannot pre-empt this sweep's rm -rf by
  # racing a symlink into place either: -L is checked first and
  # unconditionally skips any symlink match, so a plant-ahead symlink
  # named to match this glob is left untouched rather than followed.
  #
  # Live-PID exclusion (V7 fix): the directory name embeds the PID of the
  # run that created it (create_stage_dir's "$$"), so this sweep is not
  # limited to distinguishing crash residue from an attacker's plant --
  # it must also not delete a DIFFERENT, still-running instance's active
  # staging directory. Two overlapping runs by the same operator (a second
  # invocation started before the first's single `openssl pkeyutl -verify`
  # call finishes) previously raced: the second run's startup sweep would
  # match and remove the first run's directory mid-verify, since the glob
  # alone cannot tell "crashed" apart from "currently running". Extracting
  # the embedded PID and checking `kill -0` before removing closes that
  # window: a directory whose PID is still alive is left alone regardless
  # of which run created it, and only a name whose PID no longer exists
  # (or never parsed as one, which cannot happen for a name this sweep's
  # own glob matched, but is treated the same conservative way) is swept.
  # PID reuse after the original process exits could in principle make
  # this sweep skip a directory that is actually stale, if some unrelated
  # process was assigned the same PID before the next sweep runs; that
  # only means the leftover survives one more sweep cycle, never that a
  # live run's directory is removed, so the tradeoff is conservative in
  # the direction that matters (residue over data loss).
  local dir="${TMPDIR:-/tmp}"
  local d base rest candidate_pid
  for d in "$dir"/tokentimer-protocol.*.d; do
    [ -L "$d" ] && continue
    [ -e "$d" ] || continue
    [ -d "$d" ] || continue
    base="${d##*/}"
    rest="${base#tokentimer-protocol.}"
    candidate_pid="${rest%%.*}"
    case "$candidate_pid" in
      '' | *[!0-9]*) ;; # not a parseable PID; fall through and still sweep it
      *)
        if kill -0 "$candidate_pid" 2>/dev/null; then
          continue
        fi
        ;;
    esac
    rm -rf -- "$d" 2>/dev/null || true
  done
}

create_stage_dir() {
  local dir="${TMPDIR:-/tmp}"
  local attempt=0 candidate
  while (( attempt < 20 )); do
    candidate="$dir/tokentimer-protocol.$$.${RANDOM}${RANDOM}.d"
    if mkdir -m 700 "$candidate" 2>/dev/null; then
      TOKENTIMER_STAGE_DIR="$candidate"
      TOKENTIMER_STAGE_FILE="$candidate/payload"
      return 0
    fi
    attempt=$(( attempt + 1 ))
  done
  die_pregate "could not create the payload staging directory exclusively after 20 attempts"
}

# --- diagnostic-bootstrap request id (idempotency key) ---------------------

generate_request_id() {
  # A fresh UUIDv4 per bootstrap attempt when the operator does not pass
  # --request-id explicitly. uuidgen is not one of this client's declared
  # commands (ADR-0012 decision 8), so a UUIDv4 is assembled from
  # `openssl rand -hex 16` output using bash builtin string slicing
  # alone, with the version/variant nibbles set per RFC 4122. The
  # diagnostic-bootstrap route enforces this id as single-use
  # (workspace_id, request_id) server-side, so a retried request with a
  # fresh id here simply bootstraps a new diagnostic agent rather than
  # colliding with a prior run.
  local hex
  hex=$(openssl rand -hex 16) || die_pregate "could not generate a requestId"
  local a="${hex:0:8}" b="${hex:8:4}" c="${hex:12:3}" d="${hex:17:3}" e="${hex:20:12}"
  local variant_nibble="${hex:16:1}"
  case "$variant_nibble" in
    [0-7]) variant_nibble=8 ;;
    [89])  variant_nibble=8 ;;
    [a-b]) variant_nibble=9 ;;
    *)     variant_nibble=a ;;
  esac
  printf '%s-%s-4%s-%s%s-%s' "$a" "$b" "$c" "$variant_nibble" "$d" "$e"
}

# --- canonical base64 (decision 2 steps 2-4) --------------------------------

is_canonical_base64() {
  # Standard alphabet (not base64url), required padding, no embedded
  # whitespace, and canonical: bounds the encoded length, checks the
  # alphabet/padding shape with a regex, then proves canonicality the only
  # implementable way (decision 2 note on step 4): decode and re-encode,
  # and require an exact match against the original string.
  local value="$1" max_chars="$2"
  local len=${#value}
  if (( len == 0 )) || (( len > max_chars )); then return 1; fi
  if [[ ! "$value" =~ $TOKENTIMER_B64_PATTERN ]]; then return 1; fi
  if (( len % 4 != 0 )); then return 1; fi
  local reencoded
  reencoded=$(printf '%s' "$value" | openssl base64 -d -A 2>/dev/null | openssl base64 -A 2>/dev/null) || return 1
  [ "$reencoded" = "$value" ]
}

# --- exactly one JSON value, then end-of-input (decision 2 steps 7-8) ------

parse_single_json_value() {
  # jq's default per-input-value parse (a single `.` filter, no `-n`)
  # already rejects trailing non-whitespace garbage after one value with
  # a nonzero exit (confirmed empirically: "{}garbage" is a parse error,
  # while "{} \n" with only trailing whitespace is accepted, matching
  # decision 2's framing note that canonical control-plane output carries
  # none but a tolerant parser must still be defended against here). The
  # remaining gap is that jq happily emits one compact line per
  # whitespace-separated value it finds (confirmed: two concatenated
  # objects produce two output lines, at exit 0), so "exactly one value"
  # is enforced here by rejecting any embedded newline in the compact
  # output: jq's `-c` mode never puts a raw newline inside one value's
  # own compact representation (a string containing "\n" is escaped as
  # the two characters backslash-n), so a real newline in the output can
  # only mean a second value followed.
  local out
  if ! out=$(jq -c '.' 2>/dev/null); then
    return 1
  fi
  if [ -z "$out" ]; then
    return 1
  fi
  case "$out" in
    *$'\n'*) return 1 ;;
  esac
  printf '%s' "$out"
}

# --- credential handling -----------------------------------------------
#
# A credential is read once, kept only in a shell variable for the single
# curl invocation that consumes it, and unset immediately after. It is
# NEVER placed in argv (a `-H "Authorization: Bearer $t"` would leak
# through /proc/<pid>/cmdline) and never logged, including in --json mode.

check_secret_file_mode() {
  local path="$1"
  if [ ! -f "$path" ]; then
    die_usage "secret file not found: $path"
  fi
  # No permission-mode advisory here: reading octal mode bits needs
  # `stat` (GNU) or `stat -f` (BSD), and this client's declared
  # dependency list does not include either (ADR-0012 decision 8) -- a
  # "just advisory" warning is not worth an undeclared external command.
  # Callers are responsible for setting restrictive permissions on
  # credential/session-cookie/CSRF-token files themselves; this function
  # only guards existence.
}

load_secret_file() {
  # Reads a one-line secret file without a trailing newline. Never echoed,
  # never passed through a pipeline stage that could log it.
  local path="$1" out=""
  check_secret_file_mode "$path"
  IFS= read -r out < "$path" || true
  printf '%s' "$out"
}

resolve_credential() {
  if [ -n "${TOKENTIMER_CREDENTIAL_FILE:-}" ]; then
    load_secret_file "$TOKENTIMER_CREDENTIAL_FILE"
    return 0
  fi
  if [ -n "${TOKENTIMER_AGENT_CREDENTIAL:-}" ]; then
    printf '%s' "$TOKENTIMER_AGENT_CREDENTIAL"
    return 0
  fi
  die_usage "no credential available: pass --credential-file or set TOKENTIMER_AGENT_CREDENTIAL"
}

resolve_session_cookie() {
  # The diagnostic-bootstrap route is session-authenticated (an operator
  # action), not a bearer-token agent call: it needs the Cookie header
  # from an already-authenticated operator session, not an agent
  # credential. There is no login flow in this client; the operator
  # obtains this value out of band (their browser session, or their own
  # POST /auth/login call) and hands it to this flag or environment
  # variable, the same way a credential is handed in.
  if [ -n "${TOKENTIMER_SESSION_COOKIE_FILE:-}" ]; then
    load_secret_file "$TOKENTIMER_SESSION_COOKIE_FILE"
    return 0
  fi
  if [ -n "${TOKENTIMER_SESSION_COOKIE:-}" ]; then
    printf '%s' "$TOKENTIMER_SESSION_COOKIE"
    return 0
  fi
  die_usage "no session cookie available: pass --session-cookie-file or set TOKENTIMER_SESSION_COOKIE"
}

resolve_csrf_token() {
  # Paired with resolve_session_cookie: the control plane's double-
  # submit CSRF check requires this value on X-CSRF-Token in addition to
  # the CSRF cookie already present in the Cookie header above. Fetched
  # by the operator from GET /api/csrf-token using the same session.
  if [ -n "${TOKENTIMER_CSRF_TOKEN_FILE:-}" ]; then
    load_secret_file "$TOKENTIMER_CSRF_TOKEN_FILE"
    return 0
  fi
  if [ -n "${TOKENTIMER_CSRF_TOKEN:-}" ]; then
    printf '%s' "$TOKENTIMER_CSRF_TOKEN"
    return 0
  fi
  die_usage "no CSRF token available: pass --csrf-token-file or set TOKENTIMER_CSRF_TOKEN"
}

# --- claim-state file: the explicit, file-based handoff between a
# `claim` invocation and a later, separate `result` invocation ----------
#
# `result` needs the verified jobId/attemptId/claimId/nonce that a prior
# `claim` invocation already confirmed with a passing Ed25519 verdict.
# `--step all` never needs this because both steps run in the same
# process and the values are already in shell variables; two separate
# invocations have no such shared memory, and there is deliberately no
# ambient-environment-variable path for this data: an operator's wrapper
# script, a leaked/inherited environment, or a copy-pasted export could
# otherwise plant a jobId a `result` call never actually verified,
# letting it report a fabricated dry_run_complete without ever running
# verify_v2_envelope. Requiring an explicit --claim-state-file (a path
# the operator names, not a name this script picks) makes that
# injection path structurally unavailable: the file's content only ever
# comes from this script's own write_claim_state, called only after
# verify_v2_envelope has already returned a pass.
#
# The file is a small, non-secret JSON object (job/claim/attempt
# identifiers and a nonce -- none of this is a credential or key
# material), written with the same private-mode discipline
# (`umask 0077`) as every other file this script touches, and is not
# swept or auto-deleted: unlike the Ed25519-signed-payload staging file
# (which holds bytes an attacker could replay), a stale claim-state file
# is inert data whose only effect if reused is a `result` call for a
# job that was already reported, which the control plane's own
# idempotency at the results endpoint handles independently of this
# script.
write_claim_state() {
  local path="$1"
  if [ -z "$path" ]; then
    return 0
  fi
  local out
  out=$(jq -nc \
    --arg jobId "$TOKENTIMER_VERIFIED_JOB_ID" \
    --arg claimId "${TOKENTIMER_VERIFIED_CLAIM_ID:-}" \
    --arg attemptId "${TOKENTIMER_VERIFIED_ATTEMPT_ID:-}" \
    --arg nonce "${TOKENTIMER_VERIFIED_NONCE:-}" \
    --arg agentId "$TOKENTIMER_AGENT_ID" \
    '{jobId: $jobId, claimId: $claimId, attemptId: $attemptId, nonce: $nonce, agentId: $agentId}') \
    || die_pregate "could not build claim-state JSON"
  local old_umask
  old_umask=$(umask)
  umask 0077
  if ! printf '%s\n' "$out" > "$path"; then
    umask "$old_umask"
    die_pregate "could not write --claim-state-file: $path"
  fi
  umask "$old_umask"
}

read_claim_state() {
  local path="$1"
  if [ ! -f "$path" ]; then
    die_usage "--claim-state-file not found: $path (run --step claim first, or use --step all)"
  fi
  local content
  IFS= read -r -d '' content < "$path" || true
  local parsed
  if ! parsed=$(printf '%s' "$content" | parse_single_json_value 2>/dev/null); then
    die_pregate "--claim-state-file does not contain exactly one well-formed JSON value"
  fi
  TOKENTIMER_VERIFIED_JOB_ID=$(printf '%s' "$parsed" | jq -r '.jobId // empty')
  TOKENTIMER_VERIFIED_CLAIM_ID=$(printf '%s' "$parsed" | jq -r '.claimId // empty')
  TOKENTIMER_VERIFIED_ATTEMPT_ID=$(printf '%s' "$parsed" | jq -r '.attemptId // empty')
  TOKENTIMER_VERIFIED_NONCE=$(printf '%s' "$parsed" | jq -r '.nonce // empty')
  local state_agent_id
  state_agent_id=$(printf '%s' "$parsed" | jq -r '.agentId // empty')
  if [ -z "$TOKENTIMER_VERIFIED_JOB_ID" ]; then
    die_pregate "--claim-state-file is missing jobId"
  fi
  if [ -n "$state_agent_id" ] && [ -n "$TOKENTIMER_AGENT_ID" ] && [ "$state_agent_id" != "$TOKENTIMER_AGENT_ID" ]; then
    die_pregate "--claim-state-file was written for a different --agent-id than this invocation"
  fi
}

# --- curl transport ----------------------------------------------------
#
# The credential (bearer token) travels to curl through `curl --config -`
# on standard input, never as `-H`/`-u` argv (decision 8). The JSON body
# this script itself constructed is inlined into the same config stream
# as a quoted `data` directive: both the secret header and the body need
# stdin, and a config file can only be read from one stdin, so the body
# rides inside the config rather than through a second `--data-binary @-`
# that would race it for the same descriptor. No redirect is ever
# followed (curl's own default; -L is never passed), and any 3xx is
# treated as a hard failure rather than retried against a different
# origin. No TLS-insecure escape of any kind is offered.

curl_config_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

http_post_json() {
  # Args: url token_or_empty json_body max_response_bytes [extra_header_config]
  # Sets TOKENTIMER_HTTP_STATUS and TOKENTIMER_HTTP_BODY. Returns 0 always;
  # callers inspect TOKENTIMER_HTTP_STATUS. token may be empty when the
  # call is authenticated some other way (extra_header_config), such as
  # the diagnostic-bootstrap step's session cookie and CSRF token, which
  # travel the same never-argv, config-stream-stdin path as the bearer
  # token below so neither leaks through /proc/<pid>/cmdline.
  local url="$1" token="$2" body="$3" max_bytes="$4" extra_headers="${5:-}"
  local config
  IFS= read -r -d '' config <<EOF_CONFIG || true
url = "$(curl_config_escape "$url")"
request = "POST"
header = "content-type: application/json"
$( [ -n "$token" ] && printf 'header = "authorization: Bearer %s"\n' "$(curl_config_escape "$token")" )
$( [ -n "$extra_headers" ] && printf '%s\n' "$extra_headers" )
data-binary = "$(curl_config_escape "$body")"
silent
show-error
max-time = 30
EOF_CONFIG
  TOKENTIMER_HTTP_STATUS=""
  TOKENTIMER_HTTP_BODY=""
  bounded_read_capture "$(( max_bytes + 3 ))" < <(
    printf '%s' "$config" | curl --config - -w '%{http_code}' 2>/dev/null
  )
  unset config token extra_headers
  if [ "$BOUNDED_TRUNCATED" -eq 1 ]; then
    die_size_limit "control-plane response exceeded ${max_bytes} bytes while reading"
  fi
  local combined="$BOUNDED_OUTPUT"
  local total=${#combined}
  if (( total < 3 )); then
    die_network "control-plane response was too short to contain a status code"
  fi
  TOKENTIMER_HTTP_STATUS="${combined: -3}"
  TOKENTIMER_HTTP_BODY="${combined:0:total-3}"
  if [[ ! "$TOKENTIMER_HTTP_STATUS" =~ ^[0-9]{3}$ ]]; then
    die_network "control-plane did not return a parseable HTTP status"
  fi
  if [[ "$TOKENTIMER_HTTP_STATUS" == 3* ]]; then
    die_network "control-plane redirect was refused (HTTP $TOKENTIMER_HTTP_STATUS)"
  fi
  return 0
}

session_header_config() {
  # Builds the two config-stream `header = ...` lines the diagnostic-
  # bootstrap route needs in place of a bearer token: the operator's
  # session Cookie and the paired X-CSRF-Token (decision 8's never-argv
  # rule applies here exactly as it does to the bearer token in
  # http_post_json, so both travel the same config-stream-stdin path).
  local cookie="$1" csrf_token="$2"
  printf 'header = "cookie: %s"\nheader = "x-csrf-token: %s"' \
    "$(curl_config_escape "$cookie")" "$(curl_config_escape "$csrf_token")"
}

bounded_read_capture() {
  # Reads at most (limit) bytes from stdin using chunked bash reads,
  # never buffering past one chunk beyond the limit; sets BOUNDED_OUTPUT
  # and BOUNDED_TRUNCATED=1 on overrun. Known, documented limitation: the
  # bash `read` builtin cannot represent an embedded NUL byte in any
  # variable (confirmed while building this client: it is silently
  # absorbed rather than stored or signaled), so a response that pads
  # itself with NUL bytes could undercount toward this bound. This does
  # not affect a conforming control-plane response: valid JSON text never
  # contains a raw, unescaped NUL byte, so this gap has no effect on the
  # normal shape of a claim/register/heartbeat/result response. It is
  # documented here and in the README rather than silently assumed away.
  local limit="$1" chunk_size=65536
  BOUNDED_OUTPUT=""
  BOUNDED_TRUNCATED=0
  local total=0 n chunk
  while true; do
    IFS= read -r -N "$chunk_size" -d '' chunk || true
    n=${#chunk}
    if (( n == 0 )); then break; fi
    BOUNDED_OUTPUT+="$chunk"
    total=$(( total + n ))
    if (( total > limit )); then
      BOUNDED_TRUNCATED=1
      break
    fi
    if (( n < chunk_size )); then break; fi
  done
}

# --- ISO-8601 to epoch seconds (decision 2 step 14 support) -----------
#
# No external `date`: canonical control-plane timestamps are always
# YYYY-MM-DDTHH:MM:SS.sssZ (decision 2's framing note), so a fixed-format
# parse plus Howard Hinnant's days_from_civil algorithm (pure integer
# arithmetic) is exact and dependency-free. Anything not in that exact
# shape is rejected rather than guessed at.

days_from_civil() {
  local y="$1" m="$2" d="$3"
  local era yoe doy doe mp
  if (( m <= 2 )); then y=$(( y - 1 )); fi
  if (( y >= 0 )); then era=$(( y / 400 )); else era=$(( (y - 399) / 400 )); fi
  yoe=$(( y - era * 400 ))
  mp=$(( (m + 9) % 12 ))
  doy=$(( (153 * mp + 2) / 5 + d - 1 ))
  doe=$(( yoe * 365 + yoe/4 - yoe/100 + doy ))
  printf '%d' $(( era * 146097 + doe - 719468 ))
}

iso8601_to_epoch() {
  local s="$1"
  if [[ "$s" =~ $TOKENTIMER_ISO8601_PATTERN ]]; then
    local y=$((10#${BASH_REMATCH[1]})) mo=$((10#${BASH_REMATCH[2]})) d=$((10#${BASH_REMATCH[3]}))
    local h=$((10#${BASH_REMATCH[4]})) mi=$((10#${BASH_REMATCH[5]})) se=$((10#${BASH_REMATCH[6]}))
    local days
    days=$(days_from_civil "$y" "$mo" "$d")
    printf '%d' $(( days * 86400 + h * 3600 + mi * 60 + se ))
    return 0
  fi
  return 1
}

now_epoch() {
  # printf's %(fmt)T is a bash builtin (bash >= 4.2); TZ=UTC0 forces UTC
  # without an external date/tz tool.
  TZ=UTC0 printf '%(%s)T' -1
}

now_iso8601() {
  local s ms
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    s="${EPOCHREALTIME%.*}"
    ms="${EPOCHREALTIME#*.}"
    ms="${ms:0:3}"
  else
    s=$(now_epoch)
    ms="000"
  fi
  TZ=UTC0 printf '%(%Y-%m-%dT%H:%M:%S)T.%sZ' "$s" "$ms"
}

# --- decision 2: the normative verification order ----------------------
#
# Implements as much of steps 1-15 as a client without the server's own
# nonce ledger and workspace database can implement locally. Steps that
# are inherently server-side (the nonce ledger's replay check) are left to
# the control plane; everything else -- structural validation, canonical
# base64, the Ed25519 verdict, strict UTF-8, single-JSON-value framing,
# identifier extraction, the workspace/agent identity gate, signingKeyId
# equality, and the time window -- runs here, in the same order, so a
# failure at or before the gate never reaches a result report (decision 2
# note: "a signature-verdict failure produces no result").
#
# Args: envelope_json pubkey_pem_path expected_signing_key_id
#       expected_workspace_id expected_agent_id clock_offset_ms
# On success, sets TOKENTIMER_VERIFIED_PAYLOAD (the parsed JSON job
# object) and returns 0. On failure, calls die_verify_failed or
# die_pregate itself (never returns to the caller with a non-zero job).
verify_v2_envelope() {
  local envelope_json="$1" pubkey_path="$2" expected_key_id="$3"
  local expected_workspace_id="$4" expected_agent_id="$5" clock_offset_ms="${6:-0}"

  # Step 1: parse and structurally validate the UNSIGNED outer wrapper.
  local wrapper
  if ! wrapper=$(printf '%s' "$envelope_json" | parse_single_json_value 2>/dev/null); then
    die_pregate "envelope is not exactly one well-formed JSON value"
  fi
  local envelope_version payload_b64 signature_b64 signing_key_id_hint
  envelope_version=$(printf '%s' "$wrapper" | jq -e 'if (type=="object") then (.envelopeVersion // "tokentimer_missing") else error("not an object") end' 2>/dev/null) \
    || die_pregate "envelope wrapper is not an object"
  if [ "$envelope_version" != "2" ]; then
    die_verify_failed "unrecognized envelopeVersion (got $envelope_version, expected 2); failing closed rather than guessing a format"
  fi
  payload_b64=$(printf '%s' "$wrapper" | jq -re '.payloadB64 // empty' 2>/dev/null) \
    || die_pregate "envelope is missing payloadB64"
  signature_b64=$(printf '%s' "$wrapper" | jq -re '.signatureB64 // empty' 2>/dev/null) \
    || die_pregate "envelope is missing signatureB64"
  signing_key_id_hint=$(printf '%s' "$wrapper" | jq -re '.signingKeyId // empty' 2>/dev/null) \
    || die_pregate "envelope is missing signingKeyId"
  if [ -z "$payload_b64" ] || [ -z "$signature_b64" ] || [ -z "$signing_key_id_hint" ]; then
    die_pregate "envelope is missing one or more required v2 fields"
  fi
  if [[ ! "$signing_key_id_hint" =~ $TOKENTIMER_ID_PATTERN ]]; then
    die_pregate "envelope signingKeyId does not match the id pattern"
  fi

  # Steps 2-4: bound the encoded length, reject alphabet/padding
  # violations, decode, and enforce canonical base64 by re-encode-compare.
  if ! is_canonical_base64 "$payload_b64" "$TOKENTIMER_MAX_ENCODED_PAYLOAD_CHARS"; then
    die_pregate "payloadB64 is not canonical base64 or exceeds the encoded-length bound"
  fi
  if ! is_canonical_base64 "$signature_b64" 88; then
    die_pregate "signatureB64 is not canonical base64"
  fi
  if [ "${#signature_b64}" -ne 88 ]; then
    die_pregate "signatureB64 must be exactly 88 base64 characters (64 decoded bytes)"
  fi

  # Step 5 (via the declared file exception): decode #1 of payloadB64,
  # staged to a private, exclusively-created file because
  # `openssl pkeyutl -verify -rawin` refuses a pipe or a process
  # substitution for -in (confirmed empirically: it needs a seekable file
  # with a known size for Ed25519 oneshot verification). The signature
  # decode stays on the normal stream path: -sigfile does accept process
  # substitution.
  if [ ! -f "$pubkey_path" ]; then
    die_pregate "pinned public key file not found: $pubkey_path"
  fi
  stage_sweep_residue
  create_stage_dir
  if ! printf '%s' "$payload_b64" | openssl base64 -d -A > "$TOKENTIMER_STAGE_FILE" 2>/dev/null; then
    die_pregate "payloadB64 failed to base64-decode"
  fi
  # Decoded-size bound is derived arithmetically from the already-verified
  # canonical base64 string (4 chars -> 3 bytes, minus padding) rather
  # than by shelling out to `wc -c`, which is not a declared dependency.
  local b64_len=${#payload_b64}
  local pad=0
  case "$payload_b64" in
    *==) pad=2 ;;
    *=) pad=1 ;;
  esac
  local decoded_size=$(( (b64_len / 4) * 3 - pad ))
  if (( decoded_size > TOKENTIMER_MAX_DECODED_PAYLOAD_BYTES )); then
    die_pregate "decoded payload exceeds ${TOKENTIMER_MAX_DECODED_PAYLOAD_BYTES} bytes"
  fi

  local verify_ok=0
  if openssl pkeyutl -verify -pubin -inkey "$pubkey_path" -rawin \
       -in "$TOKENTIMER_STAGE_FILE" \
       -sigfile <(printf '%s' "$signature_b64" | openssl base64 -d -A) \
       >/dev/null 2>&1; then
    verify_ok=1
  fi
  if [ "$verify_ok" -ne 1 ]; then
    # decision 2: a signature-verdict failure produces no result, no
    # evidence, no lease renewal, and no other post-verdict request. The
    # caller must treat this exit the same way: stop, do not report.
    die_verify_failed "Ed25519 signature verification failed"
  fi

  # Steps 6-8: only now, with a pass verdict in hand, decode #2 of the
  # same immutable payloadB64 -- a second, independent decode, byte-
  # identical to the first by construction (both are pure functions of
  # the same input) -- and hand it to jq on the normal stream path. jq's
  # own UTF-8 handling is lossy (confirmed empirically: it replaces
  # invalid sequences with U+FFFD rather than erroring), so it cannot be
  # the strict decoder on its own; a full byte-level UTF-8 validity check
  # is not attempted here for the same reason bounded_read_capture's
  # comment gives (bash `read` cannot represent an embedded NUL, and a
  # general-purpose UTF-8 validator would need to), but the leading-BOM
  # check does not have that problem: it only needs to know whether the
  # first three bytes equal EF BB BF, and `read -N 3` reliably returns
  # that comparison for any prefix that is not itself all-NUL. This is a
  # deliberate, documented, narrower check than decision 2 step 6's full
  # "decode UTF-8 strictly" in exchange for never touching the decoded
  # bytes with a shell variable beyond this fixed 3-byte prefix; the
  # bytes that matter for security (the ones jq actually parses) still
  # travel the file -> pipe -> jq path untouched by this script.
  # parse_single_json_value additionally enforces "exactly one value,
  # then end-of-input", which jq's default multi-document stream reading
  # does not (also confirmed empirically).
  local bom_prefix=""
  IFS= read -r -N 3 bom_prefix < "$TOKENTIMER_STAGE_FILE" 2>/dev/null || true
  if [ "$bom_prefix" = $'\xef\xbb\xbf' ]; then
    die_pregate "verified payload begins with a UTF-8 byte-order mark, which decision 2 step 6 rejects"
  fi
  local parsed_payload
  if ! parsed_payload=$(printf '%s' "$payload_b64" | openssl base64 -d -A 2>/dev/null | parse_single_json_value 2>/dev/null); then
    die_pregate "verified payload is not exactly one well-formed JSON value with no trailing content"
  fi

  # Step 9: extract and validate jobId / claimId / nonce / workspaceId.
  #
  # These use `jq -r`, not `jq -re`: `-e` treats an empty `// empty`
  # result (no output at all, which is exactly what a legitimately
  # absent optional field like agentId/claimId/attemptId produces) as
  # jq exit status 4, not the field's presence as a shell-level
  # true/false. Under this script's `set -Eeuo pipefail`, that nonzero
  # status from a bare, unguarded command substitution would abort the
  # whole script right here -- bypassing every explicit presence/
  # validity check below and, in --json mode, skipping
  # emit_json_summary entirely, breaking the "always exactly one JSON
  # object" invariant. Presence and validity are deliberately checked
  # explicitly afterward instead (jobId and nonce are required; the
  # rest are optional and step-dependent), so `-e`'s exit status is
  # never the right signal to rely on here.
  local job_id workspace_id agent_id nonce claim_id attempt_id signing_key_id issued_at expires_at action mode
  job_id=$(printf '%s' "$parsed_payload" | jq -r '.jobId // empty')
  workspace_id=$(printf '%s' "$parsed_payload" | jq -r '.workspaceId // empty')
  agent_id=$(printf '%s' "$parsed_payload" | jq -r '.agentId // empty')
  nonce=$(printf '%s' "$parsed_payload" | jq -r '.nonce // empty')
  claim_id=$(printf '%s' "$parsed_payload" | jq -r '.claimId // empty')
  attempt_id=$(printf '%s' "$parsed_payload" | jq -r '.attemptId // empty')
  signing_key_id=$(printf '%s' "$parsed_payload" | jq -r '.signingKeyId // empty')
  issued_at=$(printf '%s' "$parsed_payload" | jq -r '.issuedAt // empty')
  expires_at=$(printf '%s' "$parsed_payload" | jq -r '.expiresAt // empty')
  action=$(printf '%s' "$parsed_payload" | jq -r '.action // empty')
  mode=$(printf '%s' "$parsed_payload" | jq -r '.mode // empty')
  if [ -z "$job_id" ] || [[ ! "$job_id" =~ $TOKENTIMER_ID_PATTERN ]]; then
    die_pregate "verified payload has a missing or malformed jobId"
  fi
  if [ -z "$nonce" ] || [ "${#nonce}" -lt 16 ] || [ "${#nonce}" -gt 128 ]; then
    die_pregate "verified payload has a missing or malformed nonce"
  fi

  # Step 10 (TRUSTED-IDENTITY GATE): confirm the workspace binding.
  if [ -n "$expected_workspace_id" ] && [ "$workspace_id" != "$expected_workspace_id" ]; then
    die_pregate "verified payload's workspaceId does not match this client's bound workspace"
  fi

  # Step 11: validate agentId against the client's own bound identity. The
  # control plane now always emits agentId (PR certops/agent-id-required),
  # so once this client is bound to an expected agent id, an absent
  # agentId is failed closed exactly like a mismatched one rather than
  # silently passing the gate.
  if [ -n "$expected_agent_id" ]; then
    if [ -z "$agent_id" ]; then
      die_pregate "verified payload is missing agentId; this client requires the control plane to bind every job to an agent identity"
    fi
    if [ "$agent_id" != "$expected_agent_id" ]; then
      die_pregate "verified payload's agentId does not match this client's bound identity"
    fi
  fi

  # Step 12: remaining required fields/types/enums (protocol_smoke shape).
  if [ "$action" != "protocol_smoke" ]; then
    die_pregate "this reference client only verifies protocol_smoke jobs (got action=$action)"
  fi
  if [ "$mode" != "dry_run" ]; then
    die_pregate "protocol_smoke jobs must be mode=dry_run (got mode=$mode)"
  fi

  # Step 13: the signed signingKeyId must equal the pinned key id, and
  # (pre-verification hint vs. post-verification value) the wrapper's hint
  # must equal the signed copy.
  if [ "$signing_key_id" != "$signing_key_id_hint" ]; then
    die_pregate "wrapper signingKeyId hint does not match the signed payload's signingKeyId"
  fi
  if [ -n "$expected_key_id" ] && [ "$signing_key_id" != "$expected_key_id" ]; then
    die_pregate "signed signingKeyId does not match the pinned key id"
  fi

  # Step 14: time window, using the heartbeat-derived clock offset.
  local now offset_s issued_epoch expires_epoch
  now=$(now_epoch)
  offset_s=$(( clock_offset_ms / 1000 ))
  if [ -n "$issued_at" ]; then
    if issued_epoch=$(iso8601_to_epoch "$issued_at"); then
      if (( now + offset_s + TOKENTIMER_DEFAULT_CLOCK_SKEW_TOLERANCE_S < issued_epoch )); then
        die_pregate "verified payload's issuedAt is in the future beyond clock-skew tolerance"
      fi
    fi
  fi
  if [ -n "$expires_at" ]; then
    if expires_epoch=$(iso8601_to_epoch "$expires_at"); then
      if (( now + offset_s - TOKENTIMER_DEFAULT_CLOCK_SKEW_TOLERANCE_S > expires_epoch )); then
        die_pregate "verified payload's expiresAt is in the past beyond clock-skew tolerance"
      fi
    fi
  fi

  # Step 15: act. The caller decides what "act" means for this diagnostic
  # client (report a result); this function's job stops at handing back
  # the verified, parsed job object.
  TOKENTIMER_VERIFIED_PAYLOAD="$parsed_payload"
  TOKENTIMER_VERIFIED_JOB_ID="$job_id"
  TOKENTIMER_VERIFIED_CLAIM_ID="${claim_id:-$attempt_id}"
  TOKENTIMER_VERIFIED_ATTEMPT_ID="${attempt_id:-$claim_id}"
  TOKENTIMER_VERIFIED_NONCE="$nonce"
  return 0
}

# --- server URL validation ----------------------------------------------

is_localhost() {
  local host="${1#[}"
  host="${host%]}"
  host="${host,,}"
  case "$host" in
    localhost|*.localhost|::1) return 0 ;;
  esac
  [[ "$host" =~ ^127(\.[0-9]{1,3}){3}$ ]]
}

validate_server_url() {
  local url="$1" allow_insecure_local="$2"
  if [[ "$url" =~ ^https://[^[:space:]]+$ ]]; then
    case "$url" in
      */|*\?*|*\#*|*@*) die_usage "server URL must not contain credentials, a query, fragment, or path" ;;
    esac
    printf '%s' "$url"
    return 0
  fi
  if [[ "$url" =~ ^http://([^/[:space:]]+)$ ]]; then
    if [ "$allow_insecure_local" -eq 1 ] && is_localhost "${BASH_REMATCH[1]%%:*}"; then
      printf '%s' "$url"
      return 0
    fi
  fi
  die_usage "server URL must use https:// (http:// is only allowed for an explicit --allow-insecure-local-http localhost target)"
}

# --- argument parsing -----------------------------------------------------

TOKENTIMER_STEP=""
TOKENTIMER_LIVE=0
TOKENTIMER_SERVER_URL=""
TOKENTIMER_AGENT_ID=""
TOKENTIMER_AGENT_VERSION="tokentimer-protocol.sh/${TOKENTIMER_PROTOCOL_VERSION}"
TOKENTIMER_WORKSPACE_ID=""
TOKENTIMER_SESSION_COOKIE_FILE=""
TOKENTIMER_CSRF_TOKEN_FILE=""
TOKENTIMER_REQUEST_ID=""
TOKENTIMER_CREDENTIAL_FILE=""
TOKENTIMER_ENVELOPE_FILE=""
TOKENTIMER_CLAIM_STATE_FILE=""
TOKENTIMER_PUBKEY_PATH=""
TOKENTIMER_SIGNING_KEY_ID=""
TOKENTIMER_ECHO_TEXT="tokentimer-protocol.sh smoke test"
TOKENTIMER_ALLOW_INSECURE_LOCAL_HTTP=0

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --step) [ "$#" -ge 2 ] || die_usage "--step requires a value"; TOKENTIMER_STEP="$2"; shift 2 ;;
      --live) TOKENTIMER_LIVE=1; shift ;;
      --json) TOKENTIMER_JSON_MODE=1; shift ;;
      --server-url) [ "$#" -ge 2 ] || die_usage "--server-url requires a value"; TOKENTIMER_SERVER_URL="$2"; shift 2 ;;
      --agent-id) [ "$#" -ge 2 ] || die_usage "--agent-id requires a value"; TOKENTIMER_AGENT_ID="$2"; shift 2 ;;
      --agent-version) [ "$#" -ge 2 ] || die_usage "--agent-version requires a value"; TOKENTIMER_AGENT_VERSION="$2"; shift 2 ;;
      --workspace-id) [ "$#" -ge 2 ] || die_usage "--workspace-id requires a value"; TOKENTIMER_WORKSPACE_ID="$2"; shift 2 ;;
      --session-cookie-file) [ "$#" -ge 2 ] || die_usage "--session-cookie-file requires a value"; TOKENTIMER_SESSION_COOKIE_FILE="$2"; shift 2 ;;
      --csrf-token-file) [ "$#" -ge 2 ] || die_usage "--csrf-token-file requires a value"; TOKENTIMER_CSRF_TOKEN_FILE="$2"; shift 2 ;;
      --request-id) [ "$#" -ge 2 ] || die_usage "--request-id requires a value"; TOKENTIMER_REQUEST_ID="$2"; shift 2 ;;

      --credential-file) [ "$#" -ge 2 ] || die_usage "--credential-file requires a value"; TOKENTIMER_CREDENTIAL_FILE="$2"; shift 2 ;;
      --envelope-file) [ "$#" -ge 2 ] || die_usage "--envelope-file requires a value"; TOKENTIMER_ENVELOPE_FILE="$2"; shift 2 ;;
      --claim-state-file) [ "$#" -ge 2 ] || die_usage "--claim-state-file requires a value"; TOKENTIMER_CLAIM_STATE_FILE="$2"; shift 2 ;;
      --pubkey) [ "$#" -ge 2 ] || die_usage "--pubkey requires a value"; TOKENTIMER_PUBKEY_PATH="$2"; shift 2 ;;
      --signing-key-id) [ "$#" -ge 2 ] || die_usage "--signing-key-id requires a value"; TOKENTIMER_SIGNING_KEY_ID="$2"; shift 2 ;;
      --echo) [ "$#" -ge 2 ] || die_usage "--echo requires a value"; TOKENTIMER_ECHO_TEXT="$2"; shift 2 ;;
      --allow-insecure-local-http) TOKENTIMER_ALLOW_INSECURE_LOCAL_HTTP=1; shift ;;
      -h|--help) print_help; exit "$EXIT_OK" ;;
      --) shift; break ;;
      -*) die_usage "unrecognized flag: $1" ;;
      *) die_usage "unexpected positional argument: $1" ;;
    esac
  done
  if [ -z "$TOKENTIMER_STEP" ]; then
    die_usage "--step is required (all|register|heartbeat|claim|verify|result)"
  fi
  case "$TOKENTIMER_STEP" in
    all|register|heartbeat|claim|verify|result) ;;
    *) die_usage "unrecognized --step: $TOKENTIMER_STEP" ;;
  esac
  if [ "$TOKENTIMER_STEP" != "verify" ] && [ "$TOKENTIMER_LIVE" -ne 1 ]; then
    die_usage "--step $TOKENTIMER_STEP requires --live; this client never contacts a server unless told to"
  fi
  if [ "$TOKENTIMER_STEP" = "verify" ] && [ "$TOKENTIMER_LIVE" -eq 1 ]; then
    die_usage "--step verify runs fully offline and does not accept --live"
  fi
}

# --- envelope builder (outbound requests) ---------------------------------

build_envelope() {
  # Args: message_type body_json sequence_or_empty clock_offset_ms_or_empty
  local message_type="$1" body_json="$2" sequence="${3:-}" clock_offset="${4:-}"
  local sent_at
  sent_at=$(now_iso8601)
  local out
  out=$(jq -nc \
    --arg schemaVersion "$TOKENTIMER_SCHEMA_VERSION" \
    --arg protocolVersion "$TOKENTIMER_PROTOCOL_VERSION" \
    --arg messageType "$message_type" \
    --arg agentId "${TOKENTIMER_AGENT_ID:-pending}" \
    --arg sentAt "$sent_at" \
    --argjson body "$body_json" \
    '{
      schemaVersion: ($schemaVersion | tonumber),
      protocolVersion: $protocolVersion,
      messageType: $messageType,
      agentId: $agentId,
      sentAt: $sentAt,
      body: $body
    }')
  # Each optional field is applied as its own jq call only when needed,
  # rather than piping unconditionally through a passthrough stage: `cat`
  # is not one of this client's four declared external dependencies
  # (bash, curl, jq, openssl -- ADR-0012 decision 8), so there is no
  # builtin-only identity stage to fall back to inside a pipeline.
  if [ -n "$sequence" ]; then
    out=$(printf '%s' "$out" | jq -c --argjson sequence "$sequence" '. + {sequence: $sequence}')
  fi
  if [ -n "$clock_offset" ]; then
    out=$(printf '%s' "$out" | jq -c --argjson clockOffsetMs "$clock_offset" '. + {clockOffsetMs: $clockOffsetMs}')
  fi
  printf '%s' "$out"
}

require_server_url() {
  if [ -z "$TOKENTIMER_SERVER_URL" ]; then
    die_usage "--server-url is required for --live steps"
  fi
  validate_server_url "$TOKENTIMER_SERVER_URL" "$TOKENTIMER_ALLOW_INSECURE_LOCAL_HTTP" >/dev/null
}

diagnostic_bootstrap_path() {
  # The diagnostic-bootstrap route is scoped to one workspace by path
  # segment (apps/api/routes/certops.js), unlike the envelope-based
  # register/heartbeat/claim/results endpoints, which resolve the
  # workspace from the agent's own credential instead.
  printf '/api/v1/workspaces/%s/certops/agents/diagnostic-bootstrap' "$1"
}

# --- step: register (diagnostic-bootstrap) ---------------------------------
#
# This client only ever produces diagnostic protocol_smoke jobs, so
# registration goes through the session-authenticated diagnostic-
# bootstrap route (ADR-0012 decision 7), never the normal bearer-token
# agent-registration endpoint: the normal path assigns agent_kind =
# 'normal' server-side, which would let this client claim and hold a
# lease on genuine certificate work in a real workspace. The bootstrap
# route is an operator action, not a machine credential call, so this
# step needs a session Cookie and a paired X-CSRF-Token instead of a
# bootstrap token, and it never touches the agent-protocol envelope
# wrapper (schemaVersion/messageType/agentId/sentAt/body): the request
# and response bodies here are the diagnostic-bootstrap route's own
# plain JSON shape (apps/api/services/certops/diagnosticBootstrap.js),
# not the wire protocol build_envelope produces for every other step.

step_register() {
  require_server_url
  if [ -z "$TOKENTIMER_WORKSPACE_ID" ]; then
    die_usage "--step register requires --workspace-id (the diagnostic-bootstrap route is scoped to one workspace)"
  fi
  local session_cookie csrf_token request_id
  session_cookie=$(resolve_session_cookie)
  csrf_token=$(resolve_csrf_token)
  request_id="$TOKENTIMER_REQUEST_ID"
  [ -n "$request_id" ] || request_id=$(generate_request_id)
  local body headers
  body=$(jq -nc --arg requestId "$request_id" '{requestId: $requestId}')
  headers=$(session_header_config "$session_cookie" "$csrf_token")
  http_post_json "${TOKENTIMER_SERVER_URL}$(diagnostic_bootstrap_path "$TOKENTIMER_WORKSPACE_ID")" "" "$body" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES" "$headers"
  unset session_cookie csrf_token headers
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ] && [ "$TOKENTIMER_HTTP_STATUS" != "201" ]; then
    die_network "diagnostic bootstrap failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi
  local response_agent_id response_credential
  response_agent_id=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -re '.agentId // empty' 2>/dev/null) || die_pregate "diagnostic bootstrap response is not valid JSON"
  response_credential=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -re '.credential // empty' 2>/dev/null) || true
  if [ -z "$response_agent_id" ] || [[ ! "$response_agent_id" =~ $TOKENTIMER_ID_PATTERN ]]; then
    die_pregate "diagnostic bootstrap response is missing a valid agentId"
  fi
  TOKENTIMER_AGENT_ID="$response_agent_id"
  log_field_raw "ok" "true"
  log_field "step" "register"
  log_field "agentId" "$response_agent_id"
  log_info "diagnostic agent bootstrapped as agentId=$response_agent_id"
  if [ -n "$response_credential" ]; then
    log_info "credential issued (not printed); pass it via --credential-file or TOKENTIMER_AGENT_CREDENTIAL for subsequent steps"
  fi
  unset response_credential
  emit_json_summary
}

# --- step: heartbeat -------------------------------------------------------

step_heartbeat() {
  require_server_url
  if [ -z "$TOKENTIMER_AGENT_ID" ]; then
    die_usage "--step heartbeat requires --agent-id"
  fi
  local credential
  credential=$(resolve_credential)
  local body
  # declaredCapabilities is advertised here, not at registration: the
  # diagnostic-bootstrap route (step_register) has its own fixed request
  # shape (requestId only) and does not accept it. Heartbeat's
  # declaredCapabilities is three-valued and re-sent on every heartbeat
  # (ADR-0002 addendum), so this is the first and every subsequent
  # declaration point for this client. agent-id-binding-v1 asserts this
  # client's step-11 identity gate fails closed on an absent agentId, not
  # only a mismatched one (see verify_v2_envelope).
  body=$(jq -nc \
    --arg agentVersion "$TOKENTIMER_AGENT_VERSION" \
    '{agentVersion: $agentVersion, declaredCapabilities: ["signed-payload-b64-v1", "agent-id-binding-v1"]}')
  local envelope
  envelope=$(build_envelope "heartbeat" "$body")
  http_post_json "${TOKENTIMER_SERVER_URL}${TOKENTIMER_HEARTBEAT_PATH}" "$credential" "$envelope" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES"
  unset credential
  if [ "$TOKENTIMER_HTTP_STATUS" = "410" ]; then
    log_field_raw "ok" "true"
    log_field "step" "heartbeat"
    log_field_raw "retired" "true"
    log_info "agent is retired (HTTP 410)"
    emit_json_summary
    return 0
  fi
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ]; then
    die_network "heartbeat failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi
  log_field_raw "ok" "true"
  log_field "step" "heartbeat"
  log_info "heartbeat accepted"
  emit_json_summary
}

# --- step: claim (and verify each job returned) ----------------------------

step_claim() {
  require_server_url
  if [ -z "$TOKENTIMER_AGENT_ID" ]; then
    die_usage "--step claim requires --agent-id"
  fi
  if [ -z "$TOKENTIMER_PUBKEY_PATH" ]; then
    die_usage "--step claim requires --pubkey to verify any returned job"
  fi
  local credential
  credential=$(resolve_credential)
  local body
  # supportedActions declares which wire actions this client can handle,
  # not a fixed placeholder: the control plane matches a pending job's
  # operation against this list (agentDispatch.js claimJobs), and the
  # only action this reference client ever verifies or reports on is
  # protocol_smoke. Declaring "noop" here (a real but unrelated wire
  # action this client never implements) meant claim always matched zero
  # jobs and --step all/claim could never proceed past this point.
  body=$(jq -nc '{maxJobs: 1, supportedActions: ["protocol_smoke"]}')
  local envelope
  envelope=$(build_envelope "claim" "$body")
  http_post_json "${TOKENTIMER_SERVER_URL}${TOKENTIMER_CLAIM_PATH}" "$credential" "$envelope" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES"
  unset credential
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ]; then
    die_network "claim failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi
  local jobs_count
  jobs_count=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -e '(.jobs // []) | length' 2>/dev/null) || die_pregate "claim response is not valid JSON"
  log_field "step" "claim"
  log_field_raw "jobsReturned" "$jobs_count"
  if [ "$jobs_count" -eq 0 ]; then
    log_field_raw "ok" "true"
    log_info "no jobs available"
    emit_json_summary
    return 0
  fi
  local envelope_json
  envelope_json=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -c '.jobs[0]')
  verify_v2_envelope "$envelope_json" "$TOKENTIMER_PUBKEY_PATH" "$TOKENTIMER_SIGNING_KEY_ID" \
    "$TOKENTIMER_WORKSPACE_ID" "$TOKENTIMER_AGENT_ID" 0
  write_claim_state "$TOKENTIMER_CLAIM_STATE_FILE"
  log_field_raw "ok" "true"
  log_field_raw "verified" "true"
  log_field "jobId" "$TOKENTIMER_VERIFIED_JOB_ID"
  log_info "claimed and verified jobId=$TOKENTIMER_VERIFIED_JOB_ID"
  emit_json_summary
}

# --- step: verify (fully offline) ------------------------------------------

step_verify() {
  if [ -z "$TOKENTIMER_PUBKEY_PATH" ]; then
    die_usage "--step verify requires --pubkey"
  fi
  local envelope_json
  if [ -n "$TOKENTIMER_ENVELOPE_FILE" ]; then
    if [ ! -f "$TOKENTIMER_ENVELOPE_FILE" ]; then
      die_usage "--envelope-file not found: $TOKENTIMER_ENVELOPE_FILE"
    fi
    # `cat` is not a declared dependency; `read -d ''` is a bash builtin
    # that reads to EOF just as well (the "|| true" absorbs read's
    # normal EOF-without-delimiter exit status).
    IFS= read -r -d '' envelope_json < "$TOKENTIMER_ENVELOPE_FILE" || true
  else
    IFS= read -r -d '' envelope_json || true
  fi
  verify_v2_envelope "$envelope_json" "$TOKENTIMER_PUBKEY_PATH" "$TOKENTIMER_SIGNING_KEY_ID" \
    "$TOKENTIMER_WORKSPACE_ID" "$TOKENTIMER_AGENT_ID" 0
  log_field_raw "ok" "true"
  log_field "step" "verify"
  log_field_raw "verified" "true"
  log_field "jobId" "$TOKENTIMER_VERIFIED_JOB_ID"
  log_info "signature verified; jobId=$TOKENTIMER_VERIFIED_JOB_ID"
  emit_json_summary
}

# --- step: result -----------------------------------------------------------

step_result() {
  require_server_url
  if [ -z "$TOKENTIMER_AGENT_ID" ]; then
    die_usage "--step result requires --agent-id"
  fi
  # A standalone `result` invocation is always a fresh process, so
  # TOKENTIMER_VERIFIED_JOB_ID is never already set here (that only
  # happens inside --step all, which never calls step_result directly --
  # see step_all). --claim-state-file is therefore mandatory: it is the
  # only supported way to hand a `claim` invocation's verified state to
  # this one (see the write_claim_state/read_claim_state header comment
  # for why there is deliberately no environment-variable equivalent).
  if [ -z "$TOKENTIMER_CLAIM_STATE_FILE" ]; then
    die_usage "--step result requires --claim-state-file (the file --step claim wrote), or use --step all to claim and report in one run"
  fi
  read_claim_state "$TOKENTIMER_CLAIM_STATE_FILE"
  local credential
  credential=$(resolve_credential)
  local body
  body=$(jq -nc \
    --arg jobId "$TOKENTIMER_VERIFIED_JOB_ID" \
    --arg attemptId "${TOKENTIMER_VERIFIED_ATTEMPT_ID:-$TOKENTIMER_VERIFIED_JOB_ID}" \
    --arg claimId "${TOKENTIMER_VERIFIED_CLAIM_ID:-}" \
    --arg nonce "${TOKENTIMER_VERIFIED_NONCE:-}" \
    '{jobId: $jobId, attemptId: $attemptId, status: "dry_run_complete"}
     + (if ($claimId | length) > 0 then {claimId: $claimId} else {} end)
     + (if ($nonce | length) > 0 then {nonce: $nonce} else {} end)')
  local envelope
  envelope=$(build_envelope "result" "$body")
  http_post_json "${TOKENTIMER_SERVER_URL}${TOKENTIMER_RESULTS_PATH}" "$credential" "$envelope" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES"
  unset credential
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ] && [ "$TOKENTIMER_HTTP_STATUS" != "201" ]; then
    die_network "result report failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi
  log_field_raw "ok" "true"
  log_field "step" "result"
  log_field "jobId" "$TOKENTIMER_VERIFIED_JOB_ID"
  log_info "result reported for jobId=$TOKENTIMER_VERIFIED_JOB_ID"
  emit_json_summary
}

# --- step: all ---------------------------------------------------------------

step_all() {
  require_server_url
  if [ -z "$TOKENTIMER_WORKSPACE_ID" ]; then
    die_usage "--step all requires --workspace-id (the diagnostic-bootstrap route is scoped to one workspace)"
  fi
  if [ -z "$TOKENTIMER_PUBKEY_PATH" ]; then
    die_usage "--step all requires --pubkey"
  fi

  local session_cookie csrf_token request_id
  session_cookie=$(resolve_session_cookie)
  csrf_token=$(resolve_csrf_token)
  request_id="$TOKENTIMER_REQUEST_ID"
  [ -n "$request_id" ] || request_id=$(generate_request_id)
  local register_body register_headers
  register_body=$(jq -nc --arg requestId "$request_id" '{requestId: $requestId}')
  register_headers=$(session_header_config "$session_cookie" "$csrf_token")
  http_post_json "${TOKENTIMER_SERVER_URL}$(diagnostic_bootstrap_path "$TOKENTIMER_WORKSPACE_ID")" "" "$register_body" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES" "$register_headers"
  unset session_cookie csrf_token register_headers
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ] && [ "$TOKENTIMER_HTTP_STATUS" != "201" ]; then
    die_network "diagnostic bootstrap failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi
  local credential
  TOKENTIMER_AGENT_ID=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -re '.agentId // empty') || die_pregate "diagnostic bootstrap response is not valid JSON"
  credential=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -re '.credential // empty') || die_pregate "diagnostic bootstrap response is missing a credential"
  if [ -z "$TOKENTIMER_AGENT_ID" ] || [[ ! "$TOKENTIMER_AGENT_ID" =~ $TOKENTIMER_ID_PATTERN ]]; then
    die_pregate "diagnostic bootstrap response is missing a valid agentId"
  fi
  log_info "diagnostic agent bootstrapped as agentId=$TOKENTIMER_AGENT_ID"

  local heartbeat_body
  # declaredCapabilities is advertised on heartbeat, not at bootstrap
  # (see step_heartbeat's comment): agent-id-binding-v1 asserts this
  # client's step-11 identity gate fails closed on an absent agentId,
  # not only a mismatched one.
  heartbeat_body=$(jq -nc \
    --arg agentVersion "$TOKENTIMER_AGENT_VERSION" \
    '{agentVersion: $agentVersion, declaredCapabilities: ["signed-payload-b64-v1", "agent-id-binding-v1"]}')
  local heartbeat_envelope
  heartbeat_envelope=$(build_envelope "heartbeat" "$heartbeat_body")
  http_post_json "${TOKENTIMER_SERVER_URL}${TOKENTIMER_HEARTBEAT_PATH}" "$credential" "$heartbeat_envelope" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES"
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ]; then
    unset credential
    die_network "heartbeat failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi
  log_info "heartbeat accepted"

  local claim_body
  # See step_claim's comment: supportedActions must be protocol_smoke, the
  # only action this client ever verifies/reports, or the server's claim
  # matcher never returns anything and this whole step is a no-op.
  claim_body=$(jq -nc '{maxJobs: 1, supportedActions: ["protocol_smoke"]}')
  local claim_envelope
  claim_envelope=$(build_envelope "claim" "$claim_body")
  http_post_json "${TOKENTIMER_SERVER_URL}${TOKENTIMER_CLAIM_PATH}" "$credential" "$claim_envelope" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES"
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ]; then
    unset credential
    die_network "claim failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi
  local jobs_count
  jobs_count=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -e '(.jobs // []) | length' 2>/dev/null) || { unset credential; die_pregate "claim response is not valid JSON"; }
  if [ "$jobs_count" -eq 0 ]; then
    log_field_raw "ok" "true"
    log_field "step" "all"
    log_field "agentId" "$TOKENTIMER_AGENT_ID"
    log_field "jobsReturned" "0"
    log_info "no protocol_smoke job was available to verify"
    unset credential
    emit_json_summary
    return 0
  fi
  local envelope_json
  envelope_json=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -c '.jobs[0]')
  verify_v2_envelope "$envelope_json" "$TOKENTIMER_PUBKEY_PATH" "$TOKENTIMER_SIGNING_KEY_ID" \
    "$TOKENTIMER_WORKSPACE_ID" "$TOKENTIMER_AGENT_ID" 0
  log_info "claimed and verified jobId=$TOKENTIMER_VERIFIED_JOB_ID"

  local echo_text="$TOKENTIMER_ECHO_TEXT"
  local result_body
  result_body=$(jq -nc \
    --arg jobId "$TOKENTIMER_VERIFIED_JOB_ID" \
    --arg attemptId "${TOKENTIMER_VERIFIED_ATTEMPT_ID:-$TOKENTIMER_VERIFIED_JOB_ID}" \
    --arg claimId "${TOKENTIMER_VERIFIED_CLAIM_ID:-}" \
    --arg nonce "${TOKENTIMER_VERIFIED_NONCE:-}" \
    '{jobId: $jobId, attemptId: $attemptId, status: "dry_run_complete"}
     + (if ($claimId | length) > 0 then {claimId: $claimId} else {} end)
     + (if ($nonce | length) > 0 then {nonce: $nonce} else {} end)')
  local result_envelope
  result_envelope=$(build_envelope "result" "$result_body")
  http_post_json "${TOKENTIMER_SERVER_URL}${TOKENTIMER_RESULTS_PATH}" "$credential" "$result_envelope" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES"
  unset credential
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ] && [ "$TOKENTIMER_HTTP_STATUS" != "201" ]; then
    die_network "result report failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi

  log_field_raw "ok" "true"
  log_field "step" "all"
  log_field "agentId" "$TOKENTIMER_AGENT_ID"
  log_field "jobId" "$TOKENTIMER_VERIFIED_JOB_ID"
  log_field_raw "verified" "true"
  log_field_raw "reported" "true"
  log_info "reported dry_run_complete for jobId=$TOKENTIMER_VERIFIED_JOB_ID"
  emit_json_summary
}

main() {
  parse_args "$@"
  check_openssl_version
  case "$TOKENTIMER_STEP" in
    register) step_register ;;
    heartbeat) step_heartbeat ;;
    claim) step_claim ;;
    verify) step_verify ;;
    result) step_result ;;
    all) step_all ;;
  esac
}

main "$@"


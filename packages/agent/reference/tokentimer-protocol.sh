#!/usr/bin/env bash
#
# tokentimer-protocol.sh - Node-free bash reference client for the
# TokenTimer CertOps agent protocol.
#
# Prerequisites (ADR-0012 decision 8): bash, curl, jq, OpenSSL 3. Nothing
# else is available; this is asserted by the sibling command-allowlist
# test, not just by review.
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
#   register   register a new agent identity. Requires --live.
#   heartbeat  send a heartbeat for an already-registered agent. Requires
#              --live and a credential.
#   claim      poll for jobs and verify any that come back. Requires
#              --live and a credential.
#   verify     verify one v2 envelope against a pinned public key. Runs
#              fully offline; --live is neither required nor used.
#   result     report a result for a previously claimed and verified job.
#              Requires --live and a credential.
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
#                                 server assigns.
#   --agent-version VERSION      Reported agentVersion string.
#   --workspace-id UUID          Workspace id, when the deployment expects
#                                 the client to bind to one.
#   --bootstrap-token-file PATH  File holding the bootstrap token
#                                 (register). Mode-restricted: rejected if
#                                 group- or other-readable.
#   --credential-file PATH       File holding the ttagent_... credential
#                                 (heartbeat/claim/result). Same mode rule.
#                                 TOKENTIMER_AGENT_CREDENTIAL is used instead
#                                 when this flag is omitted.
#   --envelope-file PATH         v2 envelope JSON to verify (verify step);
#                                 stdin is read when this is omitted.
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

readonly TOKENTIMER_REGISTER_PATH="/api/v1/certops/agent/register"
readonly TOKENTIMER_HEARTBEAT_PATH="/api/v1/certops/agent/heartbeat"
readonly TOKENTIMER_CLAIM_PATH="/api/v1/certops/agent/jobs/claim"
readonly TOKENTIMER_RESULTS_PATH="/api/v1/certops/agent/jobs/results"

readonly TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES=1048576
readonly TOKENTIMER_MAX_ENCODED_PAYLOAD_CHARS=65536
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
  # Reprints the usage block above verbatim so --help stays in sync with
  # the header comment: sed/awk are not declared dependencies, so this is
  # a plain heredoc rather than an extraction from the comment block.
  cat <<'EOF_HELP'
tokentimer-protocol.sh - Node-free bash reference client for the
TokenTimer CertOps agent protocol.

Usage:
  tokentimer-protocol.sh --step STEP [options]

Steps:
  all        register, heartbeat, claim, verify and report a result for
             one protocol_smoke job. Requires --live.
  register   register a new agent identity. Requires --live.
  heartbeat  send a heartbeat for an already-registered agent. Requires
             --live and a credential.
  claim      poll for jobs and verify any that come back. Requires --live
             and a credential.
  verify     verify one v2 envelope against a pinned public key. Runs
             fully offline; --live is neither required nor used.
  result     report a result for a previously claimed and verified job.
             Requires --live and a credential.

Flags:
  --live                       Contact the real control plane.
  --json                       Emit machine-readable JSON, from an
                               explicit field allowlist.
  --server-url URL             Control-plane origin (https:// required).
  --agent-id ID                Agent id (heartbeat/claim/result).
  --agent-version VERSION      Reported agentVersion string.
  --workspace-id UUID          Workspace id, if required.
  --bootstrap-token-file PATH  File holding the bootstrap token.
  --credential-file PATH       File holding the ttagent_... credential.
  --envelope-file PATH         v2 envelope JSON to verify (or stdin).
  --pubkey PATH                Pinned Ed25519 PEM public key.
  --signing-key-id ID          Pinned signing key id.
  --echo TEXT                  protocol_smoke echo string (--step all).
  --allow-insecure-local-http  Permit http:// for localhost only.
  -h, --help                   Show this help and exit 0.

Exit codes: 0 ok, 1 signature verification failed, 2 usage error,
3 network/HTTP error, 4 local pre-gate failure, 5 size limit exceeded.
EOF_HELP
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

# --- staging file: the one declared file-exception in this script ---------
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
# `mktemp` is deliberately not used: it is not one of the four declared
# commands (bash, curl, jq, openssl), so exclusive creation and the private
# mode both come from bash builtins alone (`set -C` / noclobber for
# O_EXCL-equivalent behavior, `umask` for the mode at creation).
TOKENTIMER_STAGE_FILE=""

stage_cleanup() {
  # rm is also not a declared command, so cleanup zeroes the file's
  # content in place instead of unlinking it. The security property this
  # script owes is "no residual payload bytes survive", not "no residual
  # filename survives": a zero-length file left behind on a tmpfs-backed
  # /tmp (the common default) disappears on its own at the next reboot,
  # and even where it does not, it carries nothing sensitive.
  local f="$TOKENTIMER_STAGE_FILE"
  if [ -n "$f" ] && [ -f "$f" ]; then
    { set +C; : >| "$f"; } 2>/dev/null || true
  fi
}
trap stage_cleanup EXIT INT TERM HUP

stage_sweep_residue() {
  # Startup sweep for crash residue (decision 8): a prior run that never
  # reached its own trap (SIGKILL, power loss) may have left a non-empty
  # staging file behind. Zero any matching leftovers before this run
  # creates its own, for the same reason stage_cleanup zeroes rather than
  # unlinks.
  local dir="${TMPDIR:-/tmp}"
  local f
  for f in "$dir"/tokentimer-protocol.*.payload; do
    [ -e "$f" ] || continue
    { set +C; : >| "$f"; } 2>/dev/null || true
  done
}

create_stage_file() {
  local dir="${TMPDIR:-/tmp}"
  local old_umask attempt=0 candidate
  old_umask=$(umask)
  umask 0077
  while (( attempt < 20 )); do
    candidate="$dir/tokentimer-protocol.$$.${RANDOM}${RANDOM}.payload"
    if ( set -C; : > "$candidate" ) 2>/dev/null; then
      TOKENTIMER_STAGE_FILE="$candidate"
      umask "$old_umask"
      return 0
    fi
    attempt=$(( attempt + 1 ))
  done
  umask "$old_umask"
  die_pregate "could not create the payload staging file exclusively after 20 attempts"
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
    die_usage "credential/bootstrap-token file not found: $path"
  fi
  local perms
  perms=$(TZ=UTC0 stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null || echo "")
  if [ -n "$perms" ]; then
    local other_group="${perms: -2}"
    if [ "$other_group" != "00" ]; then
      log_info "warning: $path is readable by group or other (mode $perms); tighten it to 600"
    fi
  fi
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
  # Args: url token_or_empty json_body max_response_bytes
  # Sets TOKENTIMER_HTTP_STATUS and TOKENTIMER_HTTP_BODY. Returns 0 always;
  # callers inspect TOKENTIMER_HTTP_STATUS. token may be empty for
  # bootstrap-token-free calls (there are none in this protocol, but the
  # parameter stays uniform).
  local url="$1" token="$2" body="$3" max_bytes="$4"
  local config
  config=$(cat <<EOF_CONFIG
url = "$(curl_config_escape "$url")"
request = "POST"
header = "content-type: application/json"
$( [ -n "$token" ] && printf 'header = "authorization: Bearer %s"\n' "$(curl_config_escape "$token")" )
data-binary = "$(curl_config_escape "$body")"
silent
show-error
max-time = 30
EOF_CONFIG
)
  TOKENTIMER_HTTP_STATUS=""
  TOKENTIMER_HTTP_BODY=""
  bounded_read_capture "$(( max_bytes + 3 ))" < <(
    printf '%s' "$config" | curl --config - -w '%{http_code}' 2>/dev/null
  )
  unset config token
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
  create_stage_file
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
  local job_id workspace_id agent_id nonce claim_id attempt_id signing_key_id issued_at expires_at action mode
  job_id=$(printf '%s' "$parsed_payload" | jq -re '.jobId // empty')
  workspace_id=$(printf '%s' "$parsed_payload" | jq -re '.workspaceId // empty')
  agent_id=$(printf '%s' "$parsed_payload" | jq -re '.agentId // empty')
  nonce=$(printf '%s' "$parsed_payload" | jq -re '.nonce // empty')
  claim_id=$(printf '%s' "$parsed_payload" | jq -re '.claimId // empty')
  attempt_id=$(printf '%s' "$parsed_payload" | jq -re '.attemptId // empty')
  signing_key_id=$(printf '%s' "$parsed_payload" | jq -re '.signingKeyId // empty')
  issued_at=$(printf '%s' "$parsed_payload" | jq -re '.issuedAt // empty')
  expires_at=$(printf '%s' "$parsed_payload" | jq -re '.expiresAt // empty')
  action=$(printf '%s' "$parsed_payload" | jq -re '.action // empty')
  mode=$(printf '%s' "$parsed_payload" | jq -re '.mode // empty')
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

  # Step 11: validate agentId against the client's own bound identity.
  if [ -n "$expected_agent_id" ] && [ -n "$agent_id" ] && [ "$agent_id" != "$expected_agent_id" ]; then
    die_pregate "verified payload's agentId does not match this client's bound identity"
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
TOKENTIMER_BOOTSTRAP_TOKEN_FILE=""
TOKENTIMER_CREDENTIAL_FILE=""
TOKENTIMER_ENVELOPE_FILE=""
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
      --bootstrap-token-file) [ "$#" -ge 2 ] || die_usage "--bootstrap-token-file requires a value"; TOKENTIMER_BOOTSTRAP_TOKEN_FILE="$2"; shift 2 ;;
      --credential-file) [ "$#" -ge 2 ] || die_usage "--credential-file requires a value"; TOKENTIMER_CREDENTIAL_FILE="$2"; shift 2 ;;
      --envelope-file) [ "$#" -ge 2 ] || die_usage "--envelope-file requires a value"; TOKENTIMER_ENVELOPE_FILE="$2"; shift 2 ;;
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
  jq -nc \
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
    }' \
    | if [ -n "$sequence" ]; then jq -c --argjson sequence "$sequence" '. + {sequence: $sequence}'; else cat; fi \
    | if [ -n "$clock_offset" ]; then jq -c --argjson clockOffsetMs "$clock_offset" '. + {clockOffsetMs: $clockOffsetMs}'; else cat; fi
}

require_server_url() {
  if [ -z "$TOKENTIMER_SERVER_URL" ]; then
    die_usage "--server-url is required for --live steps"
  fi
  validate_server_url "$TOKENTIMER_SERVER_URL" "$TOKENTIMER_ALLOW_INSECURE_LOCAL_HTTP" >/dev/null
}

# --- step: register --------------------------------------------------------

step_register() {
  require_server_url
  if [ -z "$TOKENTIMER_BOOTSTRAP_TOKEN_FILE" ]; then
    die_usage "--step register requires --bootstrap-token-file"
  fi
  local bootstrap_token
  bootstrap_token=$(load_secret_file "$TOKENTIMER_BOOTSTRAP_TOKEN_FILE")
  local body
  body=$(jq -nc --arg agentVersion "$TOKENTIMER_AGENT_VERSION" '{agentVersion: $agentVersion, declaredTargetSelectors: [], declaredCommandProfileNames: [], declaredCapabilities: []}')
  local envelope
  envelope=$(build_envelope "register" "$body")
  http_post_json "${TOKENTIMER_SERVER_URL}${TOKENTIMER_REGISTER_PATH}" "$bootstrap_token" "$envelope" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES"
  unset bootstrap_token
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ] && [ "$TOKENTIMER_HTTP_STATUS" != "201" ]; then
    die_network "registration failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi
  local response_agent_id response_credential
  response_agent_id=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -re '.agentId // empty' 2>/dev/null) || die_pregate "registration response is not valid JSON"
  response_credential=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -re '.credential // empty' 2>/dev/null) || true
  if [ -z "$response_agent_id" ] || [[ ! "$response_agent_id" =~ $TOKENTIMER_ID_PATTERN ]]; then
    die_pregate "registration response is missing a valid agentId"
  fi
  TOKENTIMER_AGENT_ID="$response_agent_id"
  log_field_raw "ok" "true"
  log_field "step" "register"
  log_field "agentId" "$response_agent_id"
  log_info "registered as agentId=$response_agent_id"
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
  body=$(jq -nc --arg agentVersion "$TOKENTIMER_AGENT_VERSION" '{agentVersion: $agentVersion}')
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
  body=$(jq -nc '{maxJobs: 1, supportedActions: ["noop"]}')
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
    envelope_json=$(cat "$TOKENTIMER_ENVELOPE_FILE")
  else
    envelope_json=$(cat)
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
  if [ -z "${TOKENTIMER_VERIFIED_JOB_ID:-}" ]; then
    die_usage "--step result requires a job already verified in this run (use --step all, or --step claim then --step result in the same process)"
  fi
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
  if [ -z "$TOKENTIMER_BOOTSTRAP_TOKEN_FILE" ]; then
    die_usage "--step all requires --bootstrap-token-file"
  fi
  if [ -z "$TOKENTIMER_PUBKEY_PATH" ]; then
    die_usage "--step all requires --pubkey"
  fi

  local bootstrap_token
  bootstrap_token=$(load_secret_file "$TOKENTIMER_BOOTSTRAP_TOKEN_FILE")
  local register_body
  register_body=$(jq -nc --arg agentVersion "$TOKENTIMER_AGENT_VERSION" '{agentVersion: $agentVersion, declaredTargetSelectors: [], declaredCommandProfileNames: [], declaredCapabilities: []}')
  local register_envelope
  register_envelope=$(build_envelope "register" "$register_body")
  http_post_json "${TOKENTIMER_SERVER_URL}${TOKENTIMER_REGISTER_PATH}" "$bootstrap_token" "$register_envelope" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES"
  unset bootstrap_token
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ] && [ "$TOKENTIMER_HTTP_STATUS" != "201" ]; then
    die_network "registration failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi
  local credential
  TOKENTIMER_AGENT_ID=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -re '.agentId // empty') || die_pregate "registration response is not valid JSON"
  credential=$(printf '%s' "$TOKENTIMER_HTTP_BODY" | jq -re '.credential // empty') || die_pregate "registration response is missing a credential"
  if [ -z "$TOKENTIMER_AGENT_ID" ] || [[ ! "$TOKENTIMER_AGENT_ID" =~ $TOKENTIMER_ID_PATTERN ]]; then
    die_pregate "registration response is missing a valid agentId"
  fi
  log_info "registered as agentId=$TOKENTIMER_AGENT_ID"

  local heartbeat_body
  heartbeat_body=$(jq -nc --arg agentVersion "$TOKENTIMER_AGENT_VERSION" '{agentVersion: $agentVersion}')
  local heartbeat_envelope
  heartbeat_envelope=$(build_envelope "heartbeat" "$heartbeat_body")
  http_post_json "${TOKENTIMER_SERVER_URL}${TOKENTIMER_HEARTBEAT_PATH}" "$credential" "$heartbeat_envelope" "$TOKENTIMER_MAX_CLAIM_RESPONSE_BYTES"
  if [ "$TOKENTIMER_HTTP_STATUS" != "200" ]; then
    unset credential
    die_network "heartbeat failed with HTTP $TOKENTIMER_HTTP_STATUS"
  fi
  log_info "heartbeat accepted"

  local claim_body
  claim_body=$(jq -nc '{maxJobs: 1, supportedActions: ["noop"]}')
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


#!/usr/bin/env bash
# tokentimer-protocol.sh - Bash/curl/OpenSSL reference client for the
# CertOps agent protocol (ADR-0002/0003). See docs/certops/agent.md and
# docs/adr/0002-certops-agent-protocol.md for the wire contract this script
# implements a minimal, dependency-light walkthrough of.
#
# Purpose: a portable, auditable reference implementation that any integrator
# (or a support engineer debugging a live agent) can read top to bottom
# without a Node/PowerShell runtime, to see exactly what an agent sends and
# receives at each protocol step and how the Ed25519 signed job dispatch is
# verified. It is NOT a production agent replacement: no retry policy, no
# persistent claim/lease loop, no execution engine.
#
# Mandatory Ed25519 verification: this script never ships an --insecure escape
# that skips signature verification. If OpenSSL 3.x is not on PATH, the script
# fails closed with a clear error instead of silently accepting an unverified job.
#
# Credentials: read from the TOKENTIMER_AGENT_BOOTSTRAP_TOKEN /
# TOKENTIMER_AGENT_CREDENTIAL environment variables, or from a file via
# --bootstrap-token-file / --credential-file (mode 0600 enforced). Never
# accepted as plain argv token values: argv is visible in process listings.
#
# Usage:
#   tokentimer-protocol.sh --mode agent --step register  --api-url URL [options]
#   tokentimer-protocol.sh --mode agent --step heartbeat --api-url URL --agent-id ID [options]
#   tokentimer-protocol.sh --mode agent --step claim     --api-url URL --agent-id ID [options]
#   tokentimer-protocol.sh --mode agent --step result    --api-url URL --agent-id ID --job-id ID --attempt-id ID --result-status STATUS [options]
#   tokentimer-protocol.sh --mode agent --step verify    --job-file JOB.json --pubkey-file PUB.pem --signing-key-id ID [options]
#   tokentimer-protocol.sh --mode agent --step all       --api-url URL [options]
#
# --mode is required and must be "agent". --step selects the protocol message,
# or "all" to walk register -> heartbeat -> claim -> verify (claimed jobs when
# --execute) -> result in sequence. --execute performs the HTTP call; without it
# the script prints the request it would send (method, URL, redacted auth, body)
# and exits 0. --json prints machine-readable JSON on stdout.

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CANONICALIZE_JS="$SCRIPT_DIR/lib/canonicalize.cjs"

MODE=""
STEP=""
API_URL=""
AGENT_ID=""
PROTOCOL_VERSION="1.0.0"
BOOTSTRAP_TOKEN_FILE=""
CREDENTIAL_FILE=""
JOB_FILE=""
PUBKEY_FILE=""
SIGNING_KEY_ID=""
JOB_ID=""
ATTEMPT_ID=""
RESULT_STATUS=""
REJECTION_REASON=""
KEY_ROTATED=""
ERROR_MESSAGE=""
EXECUTE=0
JSON_OUTPUT=0
CA_BUNDLE=""
SKIP_TIME_WINDOW=0

LAST_HTTP_STATUS=""
LAST_RESPONSE_BODY=""
# Identity obtained from a register response during 'all --execute'. The
# credential is held in this process's memory only: never logged, never
# written to disk, and never passed as an argv value to a child process.
REGISTERED_AGENT_ID=""
REGISTERED_CREDENTIAL=""
# Result-envelope fields copied out of the verified claimed job.
JOB_NONCE=""
JOB_CLAIM_ID=""
JOB_MODE=""

usage() {
  cat <<'EOF'
Usage:
  tokentimer-protocol.sh --mode agent --step STEP [options]

Required:
  --mode agent           Agent protocol mode (required; only value accepted).
  --step STEP            all | register | heartbeat | claim | result | verify
                          (verify is local-only: no network call. "all" walks
                          register -> heartbeat -> claim -> verify -> result;
                          with --execute, claimed jobs are verified before any
                          result is submitted.)
  --api-url URL          Control plane base URL (required for all steps but verify).

Options:
  --agent-id ID          Stable agent id (required for heartbeat/claim/result;
                          register generates one if omitted).
  --protocol-version V   Agent protocol semver this script speaks (default 1.0.0).
  --bootstrap-token-file FILE   Raw bootstrap token file (mode 0600 enforced).
                                 Alternative to TOKENTIMER_AGENT_BOOTSTRAP_TOKEN.
  --credential-file FILE        Raw agent credential file (mode 0600 enforced).
                                 Alternative to TOKENTIMER_AGENT_CREDENTIAL.
  --job-file FILE        Signed job payload JSON (verify; optional preview on
                          dry-run "all"; not required when --execute claims jobs).
  --pubkey-file FILE     Pinned Ed25519 public key PEM (verify; required for
                          "all --execute" verified pipeline).
  --signing-key-id ID    Pinned signing key id checked against each job (verify;
                          required for "all --execute").
  --job-id ID            Job id being reported on (result).
  --attempt-id ID        Attempt id being reported on (result).
  --result-status STATUS succeeded | failed | rejected | dry_run_complete |
                           orphaned_unknown_effect (result).
  --rejection-reason R   Set alongside --result-status rejected/failed (result).
  --key-rotated true|false  Whether this attempt rotated the key (result).
  --error-message MSG    Human-readable failure detail (result).
  --ca-bundle FILE       Extra CA bundle passed to curl --cacert.
  --skip-time-window     Skip issuedAt/expiresAt validation (fixture tests only).
  --execute              Actually perform the HTTP call. Without this flag,
                          the script only prints the request it would send.
  --json                 Machine-readable JSON output instead of narration.
  -h, --help             Show this help.

Security:
  Ed25519 signature verification is mandatory for verify and for "all --execute".
  Requires OpenSSL 3.x on PATH and Node.js major version >=22 and <25 for
  canonical JSON handling via reference/lib/canonicalize.cjs.
  Plain http:// is accepted only for loopback hosts (localhost, 127.0.0.1, ::1).
EOF
}

log() {
  if [ "$JSON_OUTPUT" -eq 0 ]; then
    printf '%s\n' "tokentimer-protocol: $*" >&2
  fi
}

fail() {
  printf '%s\n' "tokentimer-protocol: ERROR: $*" >&2
  exit 1
}

require_openssl3() {
  command -v openssl >/dev/null 2>&1 || fail "OpenSSL 3.x is required on PATH for mandatory Ed25519 signature verification; none found"
  local version_line major
  version_line=$(openssl version 2>/dev/null || true)
  major=$(printf '%s' "$version_line" | sed -n 's/^OpenSSL \([0-9]\+\)\..*/\1/p')
  [ -n "$major" ] || fail "could not parse OpenSSL version from '$version_line'; refusing to proceed without a confirmed OpenSSL 3.x"
  if [ "$major" -lt 3 ]; then
    fail "OpenSSL 3.x required for Ed25519 (raw) signature verification, found: $version_line"
  fi
  log "OpenSSL check ok: $version_line"
}

require_node() {
  command -v node >/dev/null 2>&1 || fail "node is required for canonical-JSON handling (reference/lib/canonicalize.cjs); none found on PATH"
  local version_line major
  version_line=$(node -v 2>/dev/null || true)
  major=$(printf '%s' "$version_line" | sed -n 's/^v\([0-9]\+\).*/\1/p')
  [ -n "$major" ] || fail "could not parse Node.js version from '$version_line'"
  if [ "$major" -lt 22 ] || [ "$major" -ge 25 ]; then
    fail "Node.js $version_line is outside the required range >=22 and <25 (see packages/agent/package.json engines.node)"
  fi
}

validate_api_url() {
  case "$API_URL" in
    *\"*|*\'*|*[\ \	]*|*\\*) fail "--api-url must not contain quotes, backslashes, or whitespace" ;;
  esac
  case "$API_URL" in
    https://*) ;;
    http://*)
      local authority host
      authority="${API_URL#http://}"
      authority="${authority%%/*}"
      if [[ "$authority" == \[*\]* ]]; then
        host="${authority%\]*}"
        host="${host#\[}"
      else
        host="${authority%%:*}"
      fi
      case "$host" in
        localhost|127.0.0.1|::1) ;;
        *) fail "plain http:// is only permitted for loopback hosts (localhost, 127.0.0.1, ::1); use https:// for remote control planes" ;;
      esac
      ;;
    *) fail "--api-url must start with http:// or https://" ;;
  esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --mode=*) MODE="${1#--mode=}"; shift ;;
    --step) STEP="${2:-}"; shift 2 ;;
    --step=*) STEP="${1#--step=}"; shift ;;
    --api-url) API_URL="${2:-}"; shift 2 ;;
    --api-url=*) API_URL="${1#--api-url=}"; shift ;;
    --agent-id) AGENT_ID="${2:-}"; shift 2 ;;
    --agent-id=*) AGENT_ID="${1#--agent-id=}"; shift ;;
    --protocol-version) PROTOCOL_VERSION="${2:-}"; shift 2 ;;
    --protocol-version=*) PROTOCOL_VERSION="${1#--protocol-version=}"; shift ;;
    --bootstrap-token-file) BOOTSTRAP_TOKEN_FILE="${2:-}"; shift 2 ;;
    --bootstrap-token-file=*) BOOTSTRAP_TOKEN_FILE="${1#--bootstrap-token-file=}"; shift ;;
    --credential-file) CREDENTIAL_FILE="${2:-}"; shift 2 ;;
    --credential-file=*) CREDENTIAL_FILE="${1#--credential-file=}"; shift ;;
    --job-file) JOB_FILE="${2:-}"; shift 2 ;;
    --job-file=*) JOB_FILE="${1#--job-file=}"; shift ;;
    --pubkey-file) PUBKEY_FILE="${2:-}"; shift 2 ;;
    --pubkey-file=*) PUBKEY_FILE="${1#--pubkey-file=}"; shift ;;
    --signing-key-id) SIGNING_KEY_ID="${2:-}"; shift 2 ;;
    --signing-key-id=*) SIGNING_KEY_ID="${1#--signing-key-id=}"; shift ;;
    --job-id) JOB_ID="${2:-}"; shift 2 ;;
    --job-id=*) JOB_ID="${1#--job-id=}"; shift ;;
    --attempt-id) ATTEMPT_ID="${2:-}"; shift 2 ;;
    --attempt-id=*) ATTEMPT_ID="${1#--attempt-id=}"; shift ;;
    --result-status) RESULT_STATUS="${2:-}"; shift 2 ;;
    --result-status=*) RESULT_STATUS="${1#--result-status=}"; shift ;;
    --rejection-reason) REJECTION_REASON="${2:-}"; shift 2 ;;
    --rejection-reason=*) REJECTION_REASON="${1#--rejection-reason=}"; shift ;;
    --key-rotated) KEY_ROTATED="${2:-}"; shift 2 ;;
    --key-rotated=*) KEY_ROTATED="${1#--key-rotated=}"; shift ;;
    --error-message) ERROR_MESSAGE="${2:-}"; shift 2 ;;
    --error-message=*) ERROR_MESSAGE="${1#--error-message=}"; shift ;;
    --ca-bundle) CA_BUNDLE="${2:-}"; shift 2 ;;
    --ca-bundle=*) CA_BUNDLE="${1#--ca-bundle=}"; shift ;;
    --skip-time-window) SKIP_TIME_WINDOW=1; shift ;;
    --execute) EXECUTE=1; shift ;;
    --json) JSON_OUTPUT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1 (see --help)" ;;
  esac
done

[ -n "$MODE" ] || fail "--mode is required (must be agent)"
[ "$MODE" = "agent" ] || fail "--mode must be 'agent', got '$MODE'"
[ -n "$STEP" ] || fail "--step is required (all|register|heartbeat|claim|result|verify)"

case "$STEP" in
  all|register|heartbeat|claim|result|verify) ;;
  *) fail "--step must be one of all|register|heartbeat|claim|result|verify, got '$STEP'" ;;
esac

if [ "$STEP" != "verify" ]; then
  [ -n "$API_URL" ] || fail "--api-url is required for step '$STEP'"
  validate_api_url
fi

read_secret_file() {
  local file="$1" label="$2"
  [ -f "$file" ] || fail "$label file not found: $file"
  local mode
  mode=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null || true)
  if [ -z "$mode" ]; then
    fail "could not determine permissions for $label file $file; refusing to read credentials without a confirmed mode 0600"
  fi
  if [ "$mode" != "600" ]; then
    fail "$label file $file must be mode 0600 (found $mode); chmod 600 it before use"
  fi
  local value
  value=$(cat "$file")
  [ -n "$value" ] || fail "$label file $file is empty"
  printf '%s' "$value"
}

resolve_bootstrap_token() {
  if [ -n "$BOOTSTRAP_TOKEN_FILE" ]; then
    read_secret_file "$BOOTSTRAP_TOKEN_FILE" "bootstrap token"
    return
  fi
  if [ -n "${TOKENTIMER_AGENT_BOOTSTRAP_TOKEN:-}" ]; then
    printf '%s' "$TOKENTIMER_AGENT_BOOTSTRAP_TOKEN"
    return
  fi
  if [ "$EXECUTE" -eq 0 ]; then
    log "no bootstrap token supplied; dry-run preview only (a real --execute run requires TOKENTIMER_AGENT_BOOTSTRAP_TOKEN or --bootstrap-token-file)"
    printf '%s' '<no-bootstrap-token-dry-run-only>'
    return
  fi
  fail "no bootstrap token: set TOKENTIMER_AGENT_BOOTSTRAP_TOKEN or pass --bootstrap-token-file (never as a plain argv value)"
}

resolve_credential() {
  # A credential minted by this run's own register step wins: 'all --execute'
  # must speak as the identity it just enrolled, not as a separately supplied
  # one, or heartbeat/claim/result act on the wrong agent.
  if [ -n "$REGISTERED_CREDENTIAL" ]; then
    printf '%s' "$REGISTERED_CREDENTIAL"
    return
  fi
  if [ -n "$CREDENTIAL_FILE" ]; then
    read_secret_file "$CREDENTIAL_FILE" "credential"
    return
  fi
  if [ -n "${TOKENTIMER_AGENT_CREDENTIAL:-}" ]; then
    printf '%s' "$TOKENTIMER_AGENT_CREDENTIAL"
    return
  fi
  if [ "$EXECUTE" -eq 0 ]; then
    log "no credential supplied; dry-run preview only (a real --execute run requires TOKENTIMER_AGENT_CREDENTIAL or --credential-file)"
    printf '%s' '<no-credential-dry-run-only>'
    return
  fi
  fail "no credential: set TOKENTIMER_AGENT_CREDENTIAL or pass --credential-file (never as a plain argv value)"
}

random_id() {
  openssl rand -hex 16
}

iso_now() {
  date -u +"%Y-%m-%dT%H:%M:%S.000Z"
}

curl_common_args() {
  local args=(--silent --show-error --fail-with-body -H "Content-Type: application/json")
  if [ -n "$CA_BUNDLE" ]; then
    args+=(--cacert "$CA_BUNDLE")
  fi
  printf '%s\n' "${args[@]}"
}

# verify: Ed25519 via OpenSSL pkeyutl on the canonical payload, then
# issuedAt/expiresAt (and signingKeyId parity) via canonicalize.cjs verify.
# Returns 0 when allowed, 1 when rejected; prints {"allowed":...} when --json.
cmd_verify() {
  [ -n "$JOB_FILE" ] || fail "--job-file is required for verify"
  [ -n "$PUBKEY_FILE" ] || fail "--pubkey-file is required for verify"
  [ -n "$SIGNING_KEY_ID" ] || fail "--signing-key-id is required for verify"
  [ -f "$JOB_FILE" ] || fail "job file not found: $JOB_FILE"
  [ -f "$PUBKEY_FILE" ] || fail "public key file not found: $PUBKEY_FILE"
  require_openssl3
  require_node

  local canonical_file signature_file verify_args verify_out verify_status
  canonical_file=$(mktemp)
  signature_file=$(mktemp)
  trap 'rm -f "$canonical_file" "$signature_file"; trap - RETURN' RETURN

  local job_signing_key_id
  job_signing_key_id=$(node "$CANONICALIZE_JS" extract-field "$JOB_FILE" signingKeyId)
  if [ "$job_signing_key_id" != "$SIGNING_KEY_ID" ]; then
    if [ "$JSON_OUTPUT" -eq 1 ]; then
      printf '{"allowed":false,"rejectionReason":"job_integrity_failed","detail":"signingKeyId mismatch"}\n'
    else
      log "REJECTED: job signingKeyId ($job_signing_key_id) does not match pinned key id ($SIGNING_KEY_ID)"
    fi
    return 1
  fi

  node "$CANONICALIZE_JS" canonicalize "$JOB_FILE" > "$canonical_file"

  local job_signature
  job_signature=$(node "$CANONICALIZE_JS" extract-field "$JOB_FILE" signature)
  printf '%s' "$job_signature" | openssl base64 -d -A > "$signature_file" \
    || fail "job signature is not valid base64"

  if ! openssl pkeyutl -verify -pubin -inkey "$PUBKEY_FILE" -rawin -in "$canonical_file" -sigfile "$signature_file" >/dev/null 2>&1; then
    if [ "$JSON_OUTPUT" -eq 1 ]; then
      printf '{"allowed":false,"rejectionReason":"job_integrity_failed","detail":"Ed25519 verification failed"}\n'
    else
      log "REJECTED: Ed25519 signature verification failed (job_integrity_failed)."
    fi
    return 1
  fi

  verify_args=("$CANONICALIZE_JS" verify "$JOB_FILE" "$PUBKEY_FILE" "$SIGNING_KEY_ID")
  if [ "$SKIP_TIME_WINDOW" -eq 1 ]; then
    verify_args+=(--skip-time-window)
  fi
  set +e
  verify_out=$(node "${verify_args[@]}" 2>&1)
  verify_status=$?
  set -e
  if [ "$verify_status" -ne 0 ]; then
    if [ "$JSON_OUTPUT" -eq 1 ]; then
      printf '%s\n' "$verify_out"
    else
      log "REJECTED: canonicalize.cjs verify failed (time window or payload integrity)."
      log "$verify_out"
    fi
    return 1
  fi

  if [ "$JSON_OUTPUT" -eq 1 ]; then
    printf '%s\n' "$verify_out"
  else
    log "Signature and validity window OK for pinned key ($SIGNING_KEY_ID)."
  fi
  return 0
}

build_agent_register_body() {
  local registration_id
  registration_id="ref-$(random_id)"
  cat <<JSON
{"schemaVersion":1,"protocolVersion":"$PROTOCOL_VERSION","messageType":"register","agentId":"${AGENT_ID:-ref-agent-$(random_id)}","sentAt":"$(iso_now)","body":{"bootstrapTokenId":"reference-client-demo","agentVersion":"reference-client","registrationId":"$registration_id"}}
JSON
}

build_agent_heartbeat_body() {
  [ -n "$AGENT_ID" ] || fail "--agent-id is required for heartbeat"
  cat <<JSON
{"schemaVersion":1,"protocolVersion":"$PROTOCOL_VERSION","messageType":"heartbeat","agentId":"$AGENT_ID","sentAt":"$(iso_now)","body":{"agentVersion":"reference-client"}}
JSON
}

build_agent_claim_body() {
  [ -n "$AGENT_ID" ] || fail "--agent-id is required for claim"
  cat <<JSON
{"schemaVersion":1,"protocolVersion":"$PROTOCOL_VERSION","messageType":"claim","agentId":"$AGENT_ID","sentAt":"$(iso_now)","body":{"maxJobs":1}}
JSON
}

json_escape() {
  printf '%s' "$1" | node -e 'process.stdout.write(JSON.stringify(require("fs").readFileSync(0,"utf8")))'
}

build_agent_result_body() {
  [ -n "$AGENT_ID" ] || fail "--agent-id is required for result"
  [ -n "$JOB_ID" ] || fail "--job-id is required for result"
  [ -n "$ATTEMPT_ID" ] || fail "--attempt-id is required for result"
  [ -n "$RESULT_STATUS" ] || fail "--result-status is required for result"
  case "$RESULT_STATUS" in
    succeeded|failed|rejected|dry_run_complete|orphaned_unknown_effect) ;;
    *) fail "--result-status must be one of succeeded|failed|rejected|dry_run_complete|orphaned_unknown_effect, got '$RESULT_STATUS'" ;;
  esac
  local rejection_json key_rotated_json error_message_json
  rejection_json=$([ -n "$REJECTION_REASON" ] && json_escape "$REJECTION_REASON" || echo null)
  error_message_json=$([ -n "$ERROR_MESSAGE" ] && json_escape "$ERROR_MESSAGE" || echo null)
  case "$KEY_ROTATED" in
    true) key_rotated_json=true ;;
    false) key_rotated_json=false ;;
    "") key_rotated_json=null ;;
    *) fail "--key-rotated must be 'true' or 'false', got '$KEY_ROTATED'" ;;
  esac
  # nonce and claimId come from the signed dispatch: the control plane consumes
  # the nonce in its replay ledger at result ingestion, so a real submission
  # without it is rejected. Both are omitted (as JSON null) only when this run
  # never claimed a signed job, i.e. a dry-run walkthrough.
  local nonce_json claim_id_json
  nonce_json=$([ -n "$JOB_NONCE" ] && json_escape "$JOB_NONCE" || echo null)
  claim_id_json=$([ -n "$JOB_CLAIM_ID" ] && json_escape "$JOB_CLAIM_ID" || echo null)
  cat <<JSON
{"schemaVersion":1,"protocolVersion":"$PROTOCOL_VERSION","messageType":"result","agentId":"$AGENT_ID","sentAt":"$(iso_now)","body":{"jobId":"$JOB_ID","attemptId":"$ATTEMPT_ID","status":"$RESULT_STATUS","rejectionReason":$rejection_json,"keyRotated":$key_rotated_json,"errorMessage":$error_message_json,"claimId":$claim_id_json,"nonce":$nonce_json}}
JSON
}

route_for_step() {
  local step="$1"
  case "$step" in
    register) echo "/api/v1/certops/agent/register" ;;
    heartbeat) echo "/api/v1/certops/agent/heartbeat" ;;
    claim) echo "/api/v1/certops/agent/jobs/claim" ;;
    result) echo "/api/v1/certops/agent/jobs/results" ;;
    *) fail "no known route for step '$step'" ;;
  esac
}

perform_request() {
  local step="$1" body="$2" auth_header="$3" route url response status payload
  route=$(route_for_step "$step")
  url="${API_URL%/}$route"

  if [ "$EXECUTE" -eq 0 ]; then
    if [ "$JSON_OUTPUT" -eq 1 ]; then
      printf '{"dryRun":true,"method":"POST","url":"%s","body":%s}\n' "$url" "$body"
    else
      log "[dry-run] POST $url"
      log "[dry-run] Authorization: Bearer <redacted>"
      log "[dry-run] body: $body"
    fi
    LAST_HTTP_STATUS="000"
    LAST_RESPONSE_BODY=""
    return 0
  fi

  mapfile -t common_args < <(curl_common_args)
  response=$(curl "${common_args[@]}" -H "Authorization: Bearer $auth_header" -X POST -d "$body" -w '\n%{http_code}' "$url") \
    || fail "request to $url failed"
  status="${response##*$'\n'}"
  payload="${response%$'\n'*}"
  LAST_HTTP_STATUS="$status"
  LAST_RESPONSE_BODY="$payload"

  if [ "$JSON_OUTPUT" -eq 1 ]; then
    printf '%s\n' "$payload"
  else
    log "HTTP $status"
    log "$payload"
  fi
  case "$status" in
    2*) return 0 ;;
    *) return 1 ;;
  esac
}

run_step() {
  local step="$1" body auth_header
  case "$step" in
    register)
      auth_header=$(resolve_bootstrap_token)
      body=$(build_agent_register_body)
      ;;
    heartbeat)
      auth_header=$(resolve_credential)
      body=$(build_agent_heartbeat_body)
      ;;
    claim)
      auth_header=$(resolve_credential)
      body=$(build_agent_claim_body)
      ;;
    result)
      auth_header=$(resolve_credential)
      body=$(build_agent_result_body)
      ;;
    *)
      fail "unsupported step: $step"
      ;;
  esac
  perform_request "$step" "$body" "$auth_header"
}

require_execute_verify_materials() {
  [ -n "$PUBKEY_FILE" ] || fail "--pubkey-file is required for 'all --execute' (verified claim pipeline)"
  [ -n "$SIGNING_KEY_ID" ] || fail "--signing-key-id is required for 'all --execute' (verified claim pipeline)"
  [ -f "$PUBKEY_FILE" ] || fail "public key file not found: $PUBKEY_FILE"
}

verify_and_submit_claimed_jobs() {
  local job_count i job_file job_signing_key_id result_fields
  require_node
  job_count=$(node -e '
    const input = process.argv[1];
    let parsed;
    try { parsed = JSON.parse(input); } catch { process.exit(3); }
    if (!Array.isArray(parsed.jobs)) process.exit(3);
    process.stdout.write(String(parsed.jobs.length));
  ' "$LAST_RESPONSE_BODY") || fail "claim response is not valid JSON with a jobs array (expected { jobs: [ signedJob, ... ] })"

  if [ "$job_count" -eq 0 ]; then
    log "claim returned zero jobs; nothing to verify or report"
    return 0
  fi

  for i in $(seq 0 $((job_count - 1))); do
    job_file=$(mktemp)
    node -e '
      const parsed = JSON.parse(process.argv[1]);
      const job = parsed.jobs[Number(process.argv[2])];
      if (!job || typeof job !== "object") process.exit(4);
      require("fs").writeFileSync(process.argv[3], JSON.stringify(job));
    ' "$LAST_RESPONSE_BODY" "$i" "$job_file"

    JOB_FILE="$job_file"
    job_signing_key_id=$(node "$CANONICALIZE_JS" extract-field "$JOB_FILE" signingKeyId)
    if [ "$job_signing_key_id" != "$SIGNING_KEY_ID" ]; then
      rm -f "$job_file"
      fail "claimed job signingKeyId ($job_signing_key_id) does not match pinned --signing-key-id ($SIGNING_KEY_ID)"
    fi

    log "=== verify claimed job $((i + 1))/$job_count (jobId $(node "$CANONICALIZE_JS" extract-field "$JOB_FILE" jobId)) ==="
    if ! cmd_verify; then
      rm -f "$job_file"
      fail "verification failed for claimed job; aborting before result submission"
    fi

    # jobId / attemptId / claimId / nonce / mode all come out of the signed
    # payload in one pass; the helper fails closed if any required id is absent.
    result_fields=$(node "$CANONICALIZE_JS" result-fields "$job_file") \
      || { rm -f "$job_file"; fail "claimed job is missing ids required for result submission"; }
    JOB_ID=$(printf '%s\n' "$result_fields" | sed -n 's/^JOB_ID=//p')
    ATTEMPT_ID=$(printf '%s\n' "$result_fields" | sed -n 's/^ATTEMPT_ID=//p')
    JOB_CLAIM_ID=$(printf '%s\n' "$result_fields" | sed -n 's/^CLAIM_ID=//p')
    JOB_NONCE=$(printf '%s\n' "$result_fields" | sed -n 's/^NONCE=//p')
    JOB_MODE=$(printf '%s\n' "$result_fields" | sed -n 's/^MODE=//p')

    # Status is decided by the job's immutable mode, not by a convenient
    # default. dry_run_complete is only legal for mode:"dry_run"; the control
    # plane rejects it for a real job. This client performs no certificate
    # work at all, so it must never claim a real job succeeded: it refuses the
    # job outright and leaves it to a real agent.
    if [ -z "$RESULT_STATUS" ]; then
      case "$JOB_MODE" in
        dry_run)
          RESULT_STATUS="dry_run_complete"
          ;;
        real)
          rm -f "$job_file"
          fail "claimed job $JOB_ID has mode 'real' but this reference client performs no certificate operations; it will not report a terminal status for it. Use --result-status explicitly only if you are reporting on work done elsewhere, or claim with an agent that can execute."
          ;;
        "")
          rm -f "$job_file"
          fail "claimed job $JOB_ID carries no execution mode; refusing to guess a terminal status"
          ;;
        *)
          rm -f "$job_file"
          fail "claimed job $JOB_ID has unrecognized mode '$JOB_MODE'; refusing to guess a terminal status"
          ;;
      esac
    fi
    log "=== result for job $((i + 1))/$job_count ==="
    run_step result || { rm -f "$job_file"; return 1; }
    rm -f "$job_file"
  done
}

# Parses { agentId, credential, protocolVersion, signingKeyId?,
# signingPublicKeyPem? } out of a register response and adopts that identity
# for the rest of the run. Fails closed: a register response we cannot read
# means we do not know who we are, so continuing would report against the
# wrong agent id.
adopt_registered_identity() {
  local parsed
  require_node
  parsed=$(node -e '
    let parsed;
    try { parsed = JSON.parse(process.argv[1]); } catch { process.exit(3); }
    if (!parsed || typeof parsed !== "object") process.exit(3);
    const agentId = parsed.agentId;
    const credential = parsed.credential;
    if (typeof agentId !== "string" || agentId.length === 0) process.exit(4);
    if (typeof credential !== "string" || credential.length === 0) process.exit(5);
    // Newline-separated so the shell can read it without a JSON parser, and
    // so the credential never becomes a child process argv value.
    process.stdout.write(`${agentId}\n${credential}`);
  ' "$LAST_RESPONSE_BODY") || fail "register response did not carry a usable { agentId, credential } pair; cannot continue as the newly enrolled agent"

  REGISTERED_AGENT_ID="${parsed%%$'\n'*}"
  REGISTERED_CREDENTIAL="${parsed#*$'\n'}"
  [ -n "$REGISTERED_AGENT_ID" ] || fail "register response carried an empty agentId"
  [ -n "$REGISTERED_CREDENTIAL" ] || fail "register response carried an empty credential"
  AGENT_ID="$REGISTERED_AGENT_ID"
  log "adopted registered identity: agentId $AGENT_ID (credential held in memory only)"
}

run_all() {
  if [ "$EXECUTE" -eq 1 ]; then
    require_execute_verify_materials
  fi

  if [ -z "$AGENT_ID" ]; then
    AGENT_ID="ref-agent-$(random_id)"
    log "generated --agent-id $AGENT_ID for this 'all' run (pass --agent-id explicitly to reuse an existing registration)"
  fi

  if [ "$EXECUTE" -eq 0 ]; then
    [ -n "$JOB_ID" ] || JOB_ID="ref-job-$(random_id)"
    [ -n "$ATTEMPT_ID" ] || ATTEMPT_ID="ref-attempt-$(random_id)"
    [ -n "$RESULT_STATUS" ] || RESULT_STATUS="dry_run_complete"
  fi

  log "=== step 1/4: register ==="
  run_step register || exit 1
  if [ "$EXECUTE" -eq 1 ]; then
    adopt_registered_identity
  fi

  log "=== step 2/4: heartbeat ==="
  run_step heartbeat || exit 1

  log "=== step 3/4: claim ==="
  run_step claim || exit 1

  if [ "$EXECUTE" -eq 1 ]; then
    log "=== step 4/5: verify claimed jobs ==="
    verify_and_submit_claimed_jobs || exit 1
    return 0
  fi

  if [ -n "$JOB_FILE" ] && [ -f "$JOB_FILE" ] && [ -n "$PUBKEY_FILE" ] && [ -n "$SIGNING_KEY_ID" ]; then
    log "=== step (preview): verify --job-file ==="
    if ! cmd_verify; then
      log "verify preview rejected the supplied --job-file; continuing dry-run walkthrough"
    fi
  fi

  log "=== step 4/4: result (dry-run placeholder) ==="
  run_step result
}

main() {
  case "$STEP" in
    verify) cmd_verify; exit $? ;;
    all) run_all ;;
    *) run_step "$STEP" ;;
  esac
}

main

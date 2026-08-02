#!/usr/bin/env bash
# tokentimer-protocol.sh - Bash/curl/OpenSSL reference client for the
# CertOps agent protocol (ADR-0002/0003). See docs/certops/agent.md and
# docs/adr/0002-certops-agent-protocol.md for the wire contract this script
# implements a minimal, dependency-light walkthrough of.
#
# Purpose: a portable, auditable reference implementation
# that any integrator (or a support engineer debugging a live agent) can
# read top to bottom without a Node/PowerShell runtime, to see exactly what
# an agent sends/receives at each protocol step and how the Ed25519 signed
# job dispatch is verified. It is NOT a production agent replacement: no
# retry policy, no persistent claim/lease loop, no execution.
#
# Mandatory Ed25519 verification: this script never ships an --insecure
# escape that skips signature verification. If OpenSSL 3.x is not on PATH,
# the script fails closed with a clear error instead of silently accepting
# an unverified job.
#
# Credentials: read from the TOKENTIMER_AGENT_BOOTSTRAP_TOKEN /
# TOKENTIMER_AGENT_CREDENTIAL environment variables, or from a file via
# --bootstrap-token-file / --credential-file (mode 0600 enforced). Never
# accepted as a plain --bootstrap-token/--credential argv value: argv is
# visible in process listings on shared hosts.
#
# Usage:
#   tokentimer-protocol.sh --mode executor --step register --api-url URL --workspace-id ID [options]
#   tokentimer-protocol.sh --mode agent    --step register  --api-url URL [options]
#   tokentimer-protocol.sh --mode agent    --step heartbeat --api-url URL --agent-id ID [options]
#   tokentimer-protocol.sh --mode agent    --step claim     --api-url URL --agent-id ID [options]
#   tokentimer-protocol.sh --mode agent    --step result    --api-url URL --agent-id ID --job-id ID --attempt-id ID --result-status STATUS [options]
#   tokentimer-protocol.sh --mode agent    --step verify    --job-file JOB.json --pubkey-file PUB.pem --signing-key-id ID
#   tokentimer-protocol.sh --mode agent    --step all       --api-url URL [options]   # register -> heartbeat -> claim -> (verify, if --job-file given) -> result
#
# --mode is required and undefaulted: "executor" (external-executor event
# surface, apps/api/routes/certops-executor.js) or "agent" (the outbound
# machine-protocol surface this script primarily documents,
# apps/api/routes/certops-agent.js). --step selects the protocol message,
# or "all" to walk every step in sequence. --execute actually performs the
# HTTP call; without it the script prints the request it WOULD send
# (method, URL, headers with secrets redacted, body) and exits 0, matching
# install-agent.sh's --dry-run convention. --json prints machine-readable
# JSON on stdout (deterministic field order, see reference/fixtures/)
# instead of the human-readable narration.
#
# Determinism note: two live runs against
# a real control plane will NEVER produce byte-identical --json output,
# because registrationId/nonce/timestamps differ every run by design. Do
# not assert byte-identical live output. This script's own test suite
# (reference/reference-client.test.js) instead normalizes away those
# fields before diffing against reference/fixtures/*.json.

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CANONICALIZE_JS="$SCRIPT_DIR/lib/canonicalize.cjs"

MODE=""
STEP=""
API_URL=""
WORKSPACE_ID=""
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

usage() {
  cat <<'EOF'
Usage:
  tokentimer-protocol.sh --mode <executor|agent> --step STEP [options]

Required:
  --mode MODE            "executor" or "agent" (no default; must be explicit).
  --step STEP            all | register | heartbeat | claim | result | verify
                          (verify is local-only: no network call. "all" walks
                          register -> heartbeat -> claim -> result in sequence,
                          plus verify if --job-file is also given.)
  --api-url URL          Control plane base URL (required for all steps but verify).

Options:
  --workspace-id ID      Required for executor-mode register.
  --agent-id ID          Stable agent id (required for agent-mode heartbeat/claim/result;
                          register generates one if omitted).
  --protocol-version V   Agent protocol semver this script speaks (default 1.0.0).
  --bootstrap-token-file FILE   File containing the raw bootstrap token
                                 (mode 0600 enforced). Alternative to the
                                 TOKENTIMER_AGENT_BOOTSTRAP_TOKEN env var.
  --credential-file FILE        File containing the raw agent credential
                                 (mode 0600 enforced). Alternative to the
                                 TOKENTIMER_AGENT_CREDENTIAL env var.
  --job-file FILE        Signed job payload JSON (verify; also used by "all"
                          and by "result" to source --job-id/--signing-key-id
                          when those flags are omitted).
  --pubkey-file FILE     Pinned Ed25519 public key PEM (verify).
  --signing-key-id ID    Pinned signing key id to check the job against (verify).
  --job-id ID            Job id being reported on (result).
  --attempt-id ID        Attempt id being reported on (result).
  --result-status STATUS  succeeded | failed | rejected | dry_run_complete |
                           orphaned_unknown_effect (result; required).
  --rejection-reason R   Set alongside --result-status rejected/failed (result).
  --key-rotated true|false  Whether this attempt rotated the key (result).
  --error-message MSG    Human-readable failure detail (result).
  --ca-bundle FILE       Extra CA bundle passed to curl --cacert.
  --execute              Actually perform the HTTP call. Without this flag,
                          the script only prints the request it would send.
  --json                 Machine-readable JSON output instead of narration.
  -h, --help             Show this help.

Security:
  Ed25519 signature verification ("verify" step, and always available to
  "all") is mandatory and cannot be disabled from this script; there is no
  --insecure flag. Requires OpenSSL 3.x on PATH (checked with a clear
  failure if missing or too old).
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
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --mode=*) MODE="${1#--mode=}"; shift ;;
    --step) STEP="${2:-}"; shift 2 ;;
    --step=*) STEP="${1#--step=}"; shift ;;
    --api-url) API_URL="${2:-}"; shift 2 ;;
    --api-url=*) API_URL="${1#--api-url=}"; shift ;;
    --workspace-id) WORKSPACE_ID="${2:-}"; shift 2 ;;
    --workspace-id=*) WORKSPACE_ID="${1#--workspace-id=}"; shift ;;
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
    --execute) EXECUTE=1; shift ;;
    --json) JSON_OUTPUT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1 (see --help)" ;;
  esac
done

[ -n "$MODE" ] || fail "--mode is required (executor|agent, no default)"
case "$MODE" in
  executor|agent) : ;;
  *) fail "--mode must be 'executor' or 'agent', got '$MODE'" ;;
esac
[ -n "$STEP" ] || fail "--step is required (all|register|heartbeat|claim|result|verify)"
case "$STEP" in
  all|register|heartbeat|claim|result|verify) : ;;
  *) fail "--step must be one of all|register|heartbeat|claim|result|verify, got '$STEP'" ;;
esac

if [ "$STEP" != "verify" ]; then
  [ -n "$API_URL" ] || fail "--api-url is required for step '$STEP'"
  case "$API_URL" in
    https://*) : ;;
    http://*) log "WARNING: --api-url uses plain http://; only appropriate for local/loopback control planes" ;;
    *) fail "--api-url must start with http:// or https://" ;;
  esac
  case "$API_URL" in
    *\"*|*\\*) fail "--api-url must not contain double quotes or backslashes" ;;
  esac
fi

read_secret_file() {
  local file="$1" label="$2"
  [ -f "$file" ] || fail "$label file not found: $file"
  local mode
  mode=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null || echo "")
  if [ -n "$mode" ] && [ "$mode" != "600" ]; then
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
    printf '%s' "<no-bootstrap-token-dry-run-only>"
    return
  fi
  fail "no bootstrap token: set TOKENTIMER_AGENT_BOOTSTRAP_TOKEN or pass --bootstrap-token-file (never as a plain argv value)"
}

resolve_credential() {
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
    printf '%s' "<no-credential-dry-run-only>"
    return
  fi
  fail "no credential: set TOKENTIMER_AGENT_CREDENTIAL or pass --credential-file (never as a plain argv value)"
}

random_id() {
  # 32 lowercase-hex chars, well inside the protocol's [A-Za-z0-9_.:-]+
  # id patterns and long enough to serve as a unique nonce/registrationId
  # for reference-client demo purposes only (not cryptographically vetted
  # for production nonce use; the control plane is the source of truth).
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

# -------------------------------------------------------------------- verify
# Does not exit on its own: prints the {"allowed":...} JSON line to stdout
# and returns 0 (allowed) or 1 (rejected), so both the standalone "verify"
# step and the "all" walkthrough can call it and decide what to do next.
cmd_verify() {
  [ -n "$JOB_FILE" ] || fail "--job-file is required for verify"
  [ -n "$PUBKEY_FILE" ] || fail "--pubkey-file is required for verify"
  [ -n "$SIGNING_KEY_ID" ] || fail "--signing-key-id is required for verify"
  [ -f "$JOB_FILE" ] || fail "job file not found: $JOB_FILE"
  [ -f "$PUBKEY_FILE" ] || fail "public key file not found: $PUBKEY_FILE"
  require_openssl3
  require_node

  local canonical_file signature_file
  canonical_file=$(mktemp)
  signature_file=$(mktemp)
  # RETURN traps are not function-scoped in bash: without unregistering it
  # here, this trap would fire AGAIN when run_all() (a caller further up
  # the stack) itself returns, by which point canonical_file/signature_file
  # are out of scope and "set -u" turns that into an unbound-variable crash.
  trap 'rm -f "$canonical_file" "$signature_file"; trap - RETURN' RETURN

  node "$CANONICALIZE_JS" canonicalize "$JOB_FILE" > "$canonical_file"

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

  local job_signature
  job_signature=$(node "$CANONICALIZE_JS" extract-field "$JOB_FILE" signature)
  printf '%s' "$job_signature" | openssl base64 -d -A > "$signature_file" \
    || fail "job signature is not valid base64"

  # Ed25519's "PureEdDSA" scheme signs the raw message directly (no
  # pre-hash), which is exactly what -rawin selects here; this matches
  # node:crypto.verify(null, ...) in packages/agent/src/signing/index.js
  # bit-for-bit, since both are the same algorithm, just two different
  # implementations of it.
  if openssl pkeyutl -verify -pubin -inkey "$PUBKEY_FILE" -rawin -in "$canonical_file" -sigfile "$signature_file" >/dev/null 2>&1; then
    if [ "$JSON_OUTPUT" -eq 1 ]; then
      printf '{"allowed":true}\n'
    else
      log "Signature OK: job is signed by the pinned key ($SIGNING_KEY_ID) and matches its canonical payload."
    fi
    return 0
  else
    if [ "$JSON_OUTPUT" -eq 1 ]; then
      printf '{"allowed":false,"rejectionReason":"job_integrity_failed","detail":"Ed25519 verification failed"}\n'
    else
      log "REJECTED: Ed25519 signature verification failed (job_integrity_failed)."
    fi
    return 1
  fi
}

# --------------------------------------------------------------- executor
build_executor_register_body() {
  cat <<JSON
{"schemaVersion":1,"workspaceId":"$WORKSPACE_ID","apiTokenId":"reference-client-demo"}
JSON
}

# ------------------------------------------------------------------- agent
build_agent_register_body() {
  local registration_id
  registration_id="ref-$(random_id)"
  cat <<JSON
{"schemaVersion":1,"protocolVersion":"$PROTOCOL_VERSION","messageType":"register","agentId":"${AGENT_ID:-ref-agent-$(random_id)}","sentAt":"$(iso_now)","body":{"bootstrapTokenId":"reference-client-demo","agentVersion":"reference-client","registrationId":"$registration_id"}}
JSON
}

build_agent_heartbeat_body() {
  [ -n "$AGENT_ID" ] || fail "--agent-id is required for agent-mode heartbeat"
  cat <<JSON
{"schemaVersion":1,"protocolVersion":"$PROTOCOL_VERSION","messageType":"heartbeat","agentId":"$AGENT_ID","sentAt":"$(iso_now)","body":{"agentVersion":"reference-client"}}
JSON
}

build_agent_claim_body() {
  [ -n "$AGENT_ID" ] || fail "--agent-id is required for agent-mode claim"
  cat <<JSON
{"schemaVersion":1,"protocolVersion":"$PROTOCOL_VERSION","messageType":"claim","agentId":"$AGENT_ID","sentAt":"$(iso_now)","body":{"maxJobs":1}}
JSON
}

json_escape() {
  # Minimal JSON string escaping for the free-text --error-message /
  # --rejection-reason values this script accepts as CLI args (never for
  # canonicalized/signed bytes -- that path only ever goes through
  # canonicalize.cjs, which uses JSON.stringify).
  printf '%s' "$1" | node -e 'process.stdout.write(JSON.stringify(require("fs").readFileSync(0,"utf8")))'
}

build_agent_result_body() {
  [ -n "$AGENT_ID" ] || fail "--agent-id is required for agent-mode result"
  [ -n "$JOB_ID" ] || fail "--job-id is required for agent-mode result (or pass --job-file to source it)"
  [ -n "$ATTEMPT_ID" ] || fail "--attempt-id is required for agent-mode result"
  [ -n "$RESULT_STATUS" ] || fail "--result-status is required for agent-mode result"
  case "$RESULT_STATUS" in
    succeeded|failed|rejected|dry_run_complete|orphaned_unknown_effect) : ;;
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
  cat <<JSON
{"schemaVersion":1,"protocolVersion":"$PROTOCOL_VERSION","messageType":"result","agentId":"$AGENT_ID","sentAt":"$(iso_now)","body":{"jobId":"$JOB_ID","attemptId":"$ATTEMPT_ID","status":"$RESULT_STATUS","rejectionReason":$rejection_json,"keyRotated":$key_rotated_json,"errorMessage":$error_message_json}}
JSON
}

route_for_step() {
  local step="$1"
  case "$MODE:$step" in
    executor:register) echo "/api/v1/certops/executor/observations" ;;
    agent:register) echo "/api/v1/certops/agent/register" ;;
    agent:heartbeat) echo "/api/v1/certops/agent/heartbeat" ;;
    agent:claim) echo "/api/v1/certops/agent/jobs/claim" ;;
    agent:result) echo "/api/v1/certops/agent/jobs/results" ;;
    *) fail "no known route for mode '$MODE' step '$step' (executor mode only documents register/observations here; heartbeat/claim/result are agent-mode-only surfaces)" ;;
  esac
}

perform_request() {
  local step="$1" body="$2" auth_header="$3" route url response status
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
    return 0
  fi

  mapfile -t common_args < <(curl_common_args)
  response=$(curl "${common_args[@]}" -H "Authorization: Bearer $auth_header" -X POST -d "$body" -w '\n%{http_code}' "$url") \
    || fail "request to $url failed"
  status="${response##*$'\n'}"
  local payload="${response%$'\n'*}"

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
  case "$MODE:$step" in
    executor:register)
      [ -n "$WORKSPACE_ID" ] || fail "--workspace-id is required for executor-mode register"
      auth_header=$(resolve_bootstrap_token)
      body=$(build_executor_register_body)
      ;;
    agent:register)
      auth_header=$(resolve_bootstrap_token)
      body=$(build_agent_register_body)
      ;;
    agent:heartbeat)
      auth_header=$(resolve_credential)
      body=$(build_agent_heartbeat_body)
      ;;
    agent:claim)
      auth_header=$(resolve_credential)
      body=$(build_agent_claim_body)
      ;;
    agent:result)
      auth_header=$(resolve_credential)
      body=$(build_agent_result_body)
      ;;
    *)
      fail "unsupported combination: --mode $MODE --step $step"
      ;;
  esac
  perform_request "$step" "$body" "$auth_header"
}

run_all() {
  [ "$MODE" = "agent" ] || fail "--step all is only defined for --mode agent (executor mode has a single register step; call it directly with --step register)"
  if [ -z "$AGENT_ID" ]; then
    AGENT_ID="ref-agent-$(random_id)"
    log "generated --agent-id $AGENT_ID for this 'all' run (pass --agent-id explicitly to reuse an existing registration)"
  fi
  # Source job-id/signing-key-id/result defaults from --job-file when the
  # operator did not pass them explicitly, so "all --job-file X" is a
  # complete, self-contained walkthrough.
  if [ -n "$JOB_FILE" ] && [ -f "$JOB_FILE" ]; then
    require_node
    [ -n "$JOB_ID" ] || JOB_ID=$(node "$CANONICALIZE_JS" extract-field "$JOB_FILE" jobId 2>/dev/null || echo "")
    [ -n "$ATTEMPT_ID" ] || ATTEMPT_ID=$(node "$CANONICALIZE_JS" extract-field "$JOB_FILE" attemptId 2>/dev/null || echo "ref-attempt-$(random_id)")
    [ -n "$SIGNING_KEY_ID" ] || SIGNING_KEY_ID=$(node "$CANONICALIZE_JS" extract-field "$JOB_FILE" signingKeyId 2>/dev/null || echo "")
  fi
  [ -n "$JOB_ID" ] || JOB_ID="ref-job-$(random_id)"
  [ -n "$ATTEMPT_ID" ] || ATTEMPT_ID="ref-attempt-$(random_id)"
  [ -n "$RESULT_STATUS" ] || RESULT_STATUS="dry_run_complete"

  log "=== step 1/4: register ==="
  run_step register

  log "=== step 2/4: heartbeat ==="
  run_step heartbeat

  log "=== step 3/4: claim ==="
  run_step claim

  if [ -n "$JOB_FILE" ] && [ -n "$PUBKEY_FILE" ] && [ -n "$SIGNING_KEY_ID" ]; then
    log "=== step (extra): verify ==="
    cmd_verify || log "verify rejected the job; continuing with the 'all' walkthrough anyway (this is a demo, not a real dispatch loop)"
  fi

  log "=== step 4/4: result ==="
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

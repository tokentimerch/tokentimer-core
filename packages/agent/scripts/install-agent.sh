#!/bin/sh
# install-agent.sh - install the TokenTimer CertOps Agent as a systemd service.
#
# This script installs FROM THE LOCAL PACKAGE DIRECTORY it lives in
# (packages/agent of a checked-out or unpacked release); it never downloads
# remote artifacts. A hosted one-liner installer will come later.
#
# What it does (see --help for flags):
#   1. Verifies OS/arch (Linux amd64/arm64; macOS best-effort for dev) and
#      that the installed Node satisfies the package.json "engines" range.
#   2. Creates the tokentimer-agent system user.
#   3. Copies the agent package to /opt/tokentimer-agent/app and creates the
#      state (config + credential) dir /opt/tokentimer-agent/state with 0700.
#   4. Writes a config.json skeleton (0600) from flags/env.
#   5. Stores the bootstrap token in state/bootstrap.env (0600) for the
#      service's first-run registration. The token is single-use and is
#      NEVER echoed back to the terminal by this script.
#   6. Installs, enables and starts the tokentimer-agent systemd unit
#      (template: tokentimer-agent.service next to this script), writes a
#      target-specific drop-in override for ReadWritePaths from --write-path,
#      and optionally installs a polkit rule for --reload-service units.
#
# Security notes:
#   - config.json is 0600 and the state dir is 0700, matching what the agent
#     itself enforces (src/config/index.js re-asserts modes on every write).
#   - Prefer passing the bootstrap token via the TOKENTIMER_AGENT_BOOTSTRAP_TOKEN
#     environment variable over --bootstrap-token so it does not land in
#     shell history or process listings.

set -eu

INSTALL_ROOT="/opt/tokentimer-agent"
APP_DIR="$INSTALL_ROOT/app"
STATE_DIR="$INSTALL_ROOT/state"
AGENT_USER="tokentimer-agent"
UNIT_NAME="tokentimer-agent.service"
UNIT_DEST="/etc/systemd/system/$UNIT_NAME"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PACKAGE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
UNIT_TEMPLATE="$SCRIPT_DIR/$UNIT_NAME"

API_URL=""
WORKSPACE_ID=""
BOOTSTRAP_TOKEN="${TOKENTIMER_AGENT_BOOTSTRAP_TOKEN:-}"
CA_BUNDLE=""
DRY_RUN=0
UNINSTALL=0
# Space-separated absolute paths for cert/deploy writes (B16). Populated via
# repeated --write-path flags and/or --write-paths-file.
WRITE_PATHS=""
# Space-separated reload service names (nginx|apache|httpd|haproxy).
RELOAD_SERVICES=""
WRITE_PATHS_FILE=""
ALLOW_INSECURE_LOCAL_HTTP=0
VALIDATE_SERVER_URL_JS="$SCRIPT_DIR/validate-server-url.js"

UNIT_DROPIN_DIR="/etc/systemd/system/${UNIT_NAME}.d"
UNIT_DROPIN_FILE="$UNIT_DROPIN_DIR/override.conf"
POLKIT_RULE_FILE="/etc/polkit-1/rules.d/50-tokentimer-agent.rules"
HOST_SANDBOX_JS="$SCRIPT_DIR/host-sandbox.js"

usage() {
  cat <<'EOF'
Usage:
  sudo ./install-agent.sh --api-url URL --workspace-id ID [options]
  sudo ./install-agent.sh --uninstall [--dry-run]

Installs the TokenTimer CertOps Agent from this local package directory as a
hardened systemd service running as the tokentimer-agent system user.
(No remote downloads; a hosted one-liner installer comes later.)

Required for install:
  --api-url URL          Control plane base URL (config.json serverUrl).
                         Must be https:// unless --allow-insecure-local-http
                         is set AND the host is loopback (localhost / 127/8 /
                         ::1 / *.localhost), matching the agent runtime.
  --workspace-id ID      Workspace the agent belongs to (recorded in
                         config.json; the bootstrap token is already
                         workspace-scoped server-side).
  Bootstrap token        Supplied interactively: when neither the
                         TOKENTIMER_AGENT_BOOTSTRAP_TOKEN env var nor
                         --bootstrap-token is given, the installer reads the
                         token from a hidden prompt (recommended; nothing
                         lands in shell history or process listings). The
                         env var is the non-interactive alternative.
                         --bootstrap-token TOKEN still works but is
                         discouraged: argv is visible in process listings.
                         Single-use ttboot_ token created in the dashboard
                         (CertOps > Deploy an agent).

Options:
  --ca-bundle PATH       PEM CA bundle for a private-CA control plane
                         (copied into the state dir, config.json caBundlePath).
  --write-path PATH      Absolute directory the agent may write certificates
                         into (repeatable). Examples: /etc/letsencrypt,
                         /etc/nginx/certs, /etc/ssl/tokentimer. Never grants
                         all of /etc. Paths are installed into a systemd
                         drop-in ReadWritePaths list.
  --write-paths-file F   File with one absolute write path per line (# comments
                         and blank lines allowed). Merged with --write-path.
  --reload-service NAME  Allow the agent to `systemctl reload` this service
                         via a generated polkit rule (repeatable). Allowed:
                         nginx, apache/apache2, httpd, haproxy. Polkit is used
                         instead of sudoers because the unit keeps
                         NoNewPrivileges=true (sudo cannot escalate).
  --allow-insecure-local-http
                         Permit plain http:// ONLY for loopback hosts, matching
                         the runtime allowInsecureLocalHttp gate. Required for
                         local development; never use for production. Also
                         writes allowInsecureLocalHttp=true into config.json.
  --dry-run              Print every action without executing anything.
  --uninstall            Stop/disable the service and remove the app dir,
                         unit file, drop-in override, and polkit rule. The
                         state dir (credential, keys) and the system user are
                         preserved; remove them manually once you are sure
                         (rm -rf /opt/tokentimer-agent &&
                         userdel tokentimer-agent).
  -h, --help             Show this help.

Layout created:
  /opt/tokentimer-agent/app     agent package (read-only at runtime)
  /opt/tokentimer-agent/state   config dir, mode 0700, owner tokentimer-agent:
                                config.json (0600), credential (0600, written
                                by the agent at registration), bootstrap.env
                                (0600, deleted automatically by the agent
                                after its first successful registration)
  .../tokentimer-agent.service.d/override.conf
                                generated ReadWritePaths (state + --write-path)
  /etc/polkit-1/rules.d/50-tokentimer-agent.rules
                                optional, only when --reload-service is set

After install:
  systemctl status tokentimer-agent
  journalctl -u tokentimer-agent -f

Host permissions note:
  ReadWritePaths lets the sandbox reach a path; the tokentimer-agent user
  must still own or have write ACL on those directories. Ensure that before
  enabling deploy jobs (for example: setfacl -m u:tokentimer-agent:rwx DIR).
EOF
}

log() { printf '%s\n' "install-agent: $*"; }
fail() { printf '%s\n' "install-agent: ERROR: $*" >&2; exit 1; }

# Runs (or prints, under --dry-run) a non-secret command. Never pass the
# bootstrap token through this function: its arguments are echoed.
run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '%s\n' "[dry-run] $*"
  else
    "$@"
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --api-url) API_URL="${2:-}"; shift 2 ;;
    --api-url=*) API_URL="${1#--api-url=}"; shift ;;
    --workspace-id) WORKSPACE_ID="${2:-}"; shift 2 ;;
    --workspace-id=*) WORKSPACE_ID="${1#--workspace-id=}"; shift ;;
    --bootstrap-token) BOOTSTRAP_TOKEN="${2:-}"; shift 2 ;;
    --bootstrap-token=*) BOOTSTRAP_TOKEN="${1#--bootstrap-token=}"; shift ;;
    --ca-bundle) CA_BUNDLE="${2:-}"; shift 2 ;;
    --ca-bundle=*) CA_BUNDLE="${1#--ca-bundle=}"; shift ;;
    --write-path)
      [ -n "${2:-}" ] || fail "--write-path requires an absolute directory path"
      WRITE_PATHS="$WRITE_PATHS ${2}"
      shift 2
      ;;
    --write-path=*)
      WRITE_PATHS="$WRITE_PATHS ${1#--write-path=}"
      shift
      ;;
    --write-paths-file) WRITE_PATHS_FILE="${2:-}"; shift 2 ;;
    --write-paths-file=*) WRITE_PATHS_FILE="${1#--write-paths-file=}"; shift ;;
    --reload-service)
      [ -n "${2:-}" ] || fail "--reload-service requires a service name"
      RELOAD_SERVICES="$RELOAD_SERVICES ${2}"
      shift 2
      ;;
    --reload-service=*)
      RELOAD_SERVICES="$RELOAD_SERVICES ${1#--reload-service=}"
      shift
      ;;
    --allow-insecure-local-http) ALLOW_INSECURE_LOCAL_HTTP=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1 (see --help)" ;;
  esac
done

OS=$(uname -s)
ARCH=$(uname -m)
IS_DARWIN=0
case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64|aarch64|arm64) : ;;
      *) fail "unsupported architecture '$ARCH' (supported: amd64/x86_64, arm64/aarch64)" ;;
    esac
    ;;
  Darwin)
    IS_DARWIN=1
    log "macOS detected: best-effort dev install (no system user, no systemd unit)."
    ;;
  *)
    fail "unsupported OS '$OS'. The agent installer supports Linux (amd64/arm64) and, best-effort for development, macOS."
    ;;
esac

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" -eq 1 ]; then
  if [ "$IS_DARWIN" -eq 1 ]; then
    log "macOS: no systemd unit to remove. Removing app dir only."
    run rm -rf "$APP_DIR"
    log "Done. State dir $STATE_DIR (credential, keys) was preserved."
    exit 0
  fi
  [ "$DRY_RUN" -eq 1 ] || [ "$(id -u)" -eq 0 ] || fail "uninstall must run as root (use sudo)"
  if [ -f "$UNIT_DEST" ] || systemctl list-unit-files "$UNIT_NAME" >/dev/null 2>&1; then
    run systemctl stop "$UNIT_NAME" || true
    run systemctl disable "$UNIT_NAME" || true
  fi
  run rm -f "$UNIT_DEST"
  run rm -f "$UNIT_DROPIN_FILE"
  run rmdir "$UNIT_DROPIN_DIR" 2>/dev/null || true
  run rm -f "$POLKIT_RULE_FILE"
  run systemctl daemon-reload
  run rm -rf "$APP_DIR"
  log "Uninstalled the service, drop-in override, polkit rule, and app dir."
  log "Preserved (remove manually once you are sure):"
  log "  - $STATE_DIR (agent credential, keys, replay store)"
  log "  - system user $AGENT_USER (userdel $AGENT_USER)"
  exit 0
fi

# ----------------------------------------------------------- validate input
[ -n "$API_URL" ] || fail "--api-url is required (control plane base URL)"
[ -n "$WORKSPACE_ID" ] || fail "--workspace-id is required"

# Hidden interactive prompt (preferred path): the dashboard's copyable
# command carries no token; the operator pastes it here, with terminal echo
# disabled, so it never touches shell history or process listings.
if [ -z "$BOOTSTRAP_TOKEN" ] && [ "$DRY_RUN" -eq 0 ]; then
  if [ -t 0 ]; then
    printf '%s' "install-agent: paste the bootstrap token (input hidden): " >&2
    stty -echo
    # Restore echo even if the read is interrupted.
    trap 'stty echo 2>/dev/null || true' EXIT INT TERM
    IFS= read -r BOOTSTRAP_TOKEN
    stty echo
    trap - EXIT INT TERM
    printf '\n' >&2
  fi
fi
if [ -z "$BOOTSTRAP_TOKEN" ] && [ "$DRY_RUN" -eq 1 ]; then
  log "dry-run: no bootstrap token supplied; a real install prompts for it interactively."
else
  [ -n "$BOOTSTRAP_TOKEN" ] || fail "bootstrap token is required: paste it at the interactive prompt, or set TOKENTIMER_AGENT_BOOTSTRAP_TOKEN"
  case "$BOOTSTRAP_TOKEN" in
    ttboot_*) : ;;
    *) fail "bootstrap token does not look like a ttboot_ token (value not shown)" ;;
  esac
fi
case "$API_URL" in
  http://*|https://*) : ;;
  *) fail "--api-url must start with http:// or https://" ;;
esac
# These values are interpolated into config.json below; refuse anything that
# could break out of a JSON string instead of trying to escape it.
case "$API_URL" in
  *\"*|*\\*) fail "--api-url must not contain double quotes or backslashes" ;;
esac
case "$WORKSPACE_ID" in
  *\"*|*\\*) fail "--workspace-id must not contain double quotes or backslashes" ;;
esac
if printf '%s%s' "$API_URL" "$WORKSPACE_ID" | LC_ALL=C tr -d '[:print:]' | grep -q .; then
  fail "--api-url and --workspace-id must not contain control or non-printable characters"
fi

# Match the agent runtime serverUrl gate exactly (src/protocol parseServerUrl):
# https always ok; plain http only for loopback when --allow-insecure-local-http.
[ -f "$VALIDATE_SERVER_URL_JS" ] || fail "server URL validator not found: $VALIDATE_SERVER_URL_JS"
VALIDATE_ARGS="$API_URL"
if [ "$ALLOW_INSECURE_LOCAL_HTTP" -eq 1 ]; then
  VALIDATE_ARGS="$VALIDATE_ARGS --allow-insecure-local-http"
fi
# shellcheck disable=SC2086
NORMALIZED_API_URL=$(node "$VALIDATE_SERVER_URL_JS" $VALIDATE_ARGS) \
  || fail "--api-url was rejected by the same rule the agent runtime uses (https required; http only for loopback with --allow-insecure-local-http)"
API_URL="$NORMALIZED_API_URL"
if [ -n "$CA_BUNDLE" ]; then
  [ -f "$CA_BUNDLE" ] || fail "--ca-bundle file not found: $CA_BUNDLE"
  grep -q "BEGIN CERTIFICATE" "$CA_BUNDLE" || fail "--ca-bundle contains no PEM certificate block"
  if grep -q "PRIVATE KEY" "$CA_BUNDLE"; then
    fail "--ca-bundle contains private key material; a CA bundle must hold public certificates only"
  fi
fi

[ -f "$PACKAGE_DIR/package.json" ] || fail "agent package.json not found next to this script (expected $PACKAGE_DIR/package.json); run from an unpacked agent package"
[ -f "$PACKAGE_DIR/bin/tokentimer-agent.js" ] || fail "agent entrypoint bin/tokentimer-agent.js not found in $PACKAGE_DIR"
[ -f "$UNIT_TEMPLATE" ] || { [ "$IS_DARWIN" -eq 1 ] || fail "systemd unit template not found: $UNIT_TEMPLATE"; }
[ -f "$HOST_SANDBOX_JS" ] || fail "host sandbox helper not found: $HOST_SANDBOX_JS"

# Merge --write-paths-file into WRITE_PATHS, then validate every path through
# host-sandbox.js (rejects /, /etc, relative paths, and shell metacharacters).
if [ -n "$WRITE_PATHS_FILE" ]; then
  [ -f "$WRITE_PATHS_FILE" ] || fail "--write-paths-file not found: $WRITE_PATHS_FILE"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ""|\#*) continue ;;
    esac
    WRITE_PATHS="$WRITE_PATHS $line"
  done < "$WRITE_PATHS_FILE"
fi
VALIDATED_WRITE_PATHS=""
for write_path in $WRITE_PATHS; do
  validated=$(node "$HOST_SANDBOX_JS" validate-path "$write_path") \
    || fail "invalid --write-path: $write_path"
  VALIDATED_WRITE_PATHS="$VALIDATED_WRITE_PATHS $validated"
done
WRITE_PATHS=$VALIDATED_WRITE_PATHS

VALIDATED_RELOAD_SERVICES=""
for reload_service in $RELOAD_SERVICES; do
  node "$HOST_SANDBOX_JS" map-reload-service "$reload_service" >/dev/null \
    || fail "invalid --reload-service: $reload_service"
  VALIDATED_RELOAD_SERVICES="$VALIDATED_RELOAD_SERVICES $reload_service"
done
RELOAD_SERVICES=$VALIDATED_RELOAD_SERVICES

if [ "$DRY_RUN" -eq 0 ] && [ "$IS_DARWIN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  fail "install must run as root (use sudo)"
fi

# -------------------------------------------------------- node version gate
# engines.node is a single ">=x.y.z" range in this package; a plain sed
# parse avoids needing node before the node check itself.
REQUIRED_RANGE=$(sed -n 's/.*"node"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$PACKAGE_DIR/package.json")
command -v node >/dev/null 2>&1 || fail "node is not installed or not on PATH; the agent requires Node '$REQUIRED_RANGE'"
REQUIRED_MAJOR=$(printf '%s' "$REQUIRED_RANGE" | sed -n 's/[^0-9]*\([0-9][0-9]*\).*/\1/p')
NODE_MAJOR=$(node -v | sed -n 's/^v\([0-9][0-9]*\).*/\1/p')
[ -n "$REQUIRED_MAJOR" ] || fail "could not parse required Node version from $PACKAGE_DIR/package.json (engines.node='$REQUIRED_RANGE')"
[ -n "$NODE_MAJOR" ] || fail "could not parse installed Node version from 'node -v'"
if [ "$NODE_MAJOR" -lt "$REQUIRED_MAJOR" ]; then
  fail "Node $(node -v) is too old; the agent requires engines.node '$REQUIRED_RANGE'"
fi
log "Node $(node -v) satisfies engines.node '$REQUIRED_RANGE'."

# ------------------------------------------------------------- system user
if [ "$IS_DARWIN" -eq 0 ]; then
  if id "$AGENT_USER" >/dev/null 2>&1; then
    log "System user $AGENT_USER already exists."
  elif command -v useradd >/dev/null 2>&1; then
    run useradd --system --home-dir "$INSTALL_ROOT" --no-create-home --shell /usr/sbin/nologin "$AGENT_USER"
  elif command -v adduser >/dev/null 2>&1; then
    run adduser -S -H -h "$INSTALL_ROOT" -s /sbin/nologin "$AGENT_USER"
  else
    fail "neither useradd nor adduser is available to create the $AGENT_USER system user"
  fi
fi

# ------------------------------------------------------------ install files
# Staged, atomic-swap install: extract into a fresh staging dir next to the
# app dir, then swap it into place. A failed copy can never leave a
# half-written app dir behind, and a running agent keeps its old files until
# the swap (systemd restart picks up the new tree).
log "Installing agent package from $PACKAGE_DIR to $APP_DIR"
run mkdir -p "$INSTALL_ROOT"
if [ "$DRY_RUN" -eq 1 ]; then
  printf '%s\n' "[dry-run] stage $PACKAGE_DIR into $APP_DIR.staging.\$\$ (excluding node_modules), then atomically swap into $APP_DIR"
else
  APP_STAGING="$APP_DIR.staging.$$"
  APP_PREVIOUS="$APP_DIR.previous.$$"
  rm -rf "$APP_STAGING"
  mkdir -p "$APP_STAGING"
  # tar pipe preserves layout and lets us exclude node_modules portably.
  if ! (cd "$PACKAGE_DIR" && tar -cf - --exclude=./node_modules .) | (cd "$APP_STAGING" && tar -xf -); then
    rm -rf "$APP_STAGING"
    fail "failed to stage the agent package; $APP_DIR was left untouched"
  fi
  if [ -d "$APP_DIR" ]; then
    mv "$APP_DIR" "$APP_PREVIOUS"
  fi
  if ! mv "$APP_STAGING" "$APP_DIR"; then
    [ -d "$APP_PREVIOUS" ] && mv "$APP_PREVIOUS" "$APP_DIR"
    rm -rf "$APP_STAGING"
    fail "failed to activate the staged agent package; the previous install was restored"
  fi
  rm -rf "$APP_PREVIOUS"
fi

run mkdir -p "$STATE_DIR"
run chmod 0700 "$STATE_DIR"

# ------------------------------------------------------- config.json (0600)
# Fields consumed by the agent's config loader (src/config/index.js):
# serverUrl (required) and caBundlePath (optional). workspaceId is recorded
# for operators; the loader ignores unknown fields and the bootstrap token
# is already workspace-scoped server-side. agentId and the credential are
# written by the agent itself at first-run registration.
CONFIG_PATH="$STATE_DIR/config.json"
CA_BUNDLE_DEST=""
if [ -n "$CA_BUNDLE" ]; then
  CA_BUNDLE_DEST="$STATE_DIR/ca-bundle.pem"
  run cp "$CA_BUNDLE" "$CA_BUNDLE_DEST"
  run chmod 0644 "$CA_BUNDLE_DEST"
fi

if [ -f "$CONFIG_PATH" ] && [ "$DRY_RUN" -eq 0 ]; then
  log "Existing $CONFIG_PATH found; leaving it untouched (delete it to re-generate)."
elif [ "$DRY_RUN" -eq 1 ]; then
  printf '%s\n' "[dry-run] write $CONFIG_PATH (0600) with serverUrl=$API_URL workspaceId=$WORKSPACE_ID${CA_BUNDLE_DEST:+ caBundlePath=$CA_BUNDLE_DEST}"
else
  # Values were charset-validated above (no quotes/backslashes/control
  # chars), so plain interpolation cannot produce malformed JSON. Written
  # to a temp file first and renamed so a crash never leaves a torn file.
  CONFIG_TMP="$CONFIG_PATH.tmp.$$"
  umask 177
  {
    printf '{\n'
    printf '  "serverUrl": "%s",\n' "$API_URL"
    printf '  "workspaceId": "%s"' "$WORKSPACE_ID"
    if [ -n "$CA_BUNDLE_DEST" ]; then
      printf ',\n  "caBundlePath": "%s"' "$CA_BUNDLE_DEST"
    fi
    if [ "$ALLOW_INSECURE_LOCAL_HTTP" -eq 1 ]; then
      printf ',\n  "allowInsecureLocalHttp": true'
    fi
    printf '\n}\n'
  } > "$CONFIG_TMP"
  umask 022
  chmod 0600 "$CONFIG_TMP"
  mv "$CONFIG_TMP" "$CONFIG_PATH"
  # Sanity-parse the result with the node we already verified, so a bad
  # value can never install an unreadable config.
  node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" "$CONFIG_PATH" \
    || fail "generated $CONFIG_PATH is not valid JSON (unexpected characters in --api-url/--workspace-id?)"
fi

# --------------------------------------- bootstrap token env file (0600)
# The single-use ttboot_ token is stored only for the service's first-run
# registration and is never printed by this script. The agent deletes
# bootstrap.env itself right after a successful registration.
BOOTSTRAP_ENV="$STATE_DIR/bootstrap.env"
if [ "$DRY_RUN" -eq 1 ]; then
  printf '%s\n' "[dry-run] write $BOOTSTRAP_ENV (0600) with TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=<redacted>"
else
  BOOTSTRAP_ENV_TMP="$BOOTSTRAP_ENV.tmp.$$"
  umask 177
  printf 'TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=%s\n' "$BOOTSTRAP_TOKEN" > "$BOOTSTRAP_ENV_TMP"
  umask 022
  chmod 0600 "$BOOTSTRAP_ENV_TMP"
  mv "$BOOTSTRAP_ENV_TMP" "$BOOTSTRAP_ENV"
fi

if [ "$IS_DARWIN" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  chown -R "$AGENT_USER:$AGENT_USER" "$STATE_DIR"
  chown -R root:root "$APP_DIR"
elif [ "$IS_DARWIN" -eq 0 ]; then
  printf '%s\n' "[dry-run] chown -R $AGENT_USER:$AGENT_USER $STATE_DIR; chown -R root:root $APP_DIR"
fi

# ------------------------------------------------------------ systemd unit
if [ "$IS_DARWIN" -eq 1 ]; then
  log "macOS dev install complete. Run the agent manually with:"
  log "  TOKENTIMER_AGENT_CONFIG_DIR=$STATE_DIR TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=<token> node $APP_DIR/bin/tokentimer-agent.js"
  exit 0
fi

run cp "$UNIT_TEMPLATE" "$UNIT_DEST"
run chmod 0644 "$UNIT_DEST"

# Target-specific sandbox drop-in: state dir + operator --write-path list.
# Always written so upgrades replace a previous broader (or empty) override.
OVERRIDE_ARGS="--state-dir $STATE_DIR"
for write_path in $WRITE_PATHS; do
  OVERRIDE_ARGS="$OVERRIDE_ARGS --write-path $write_path"
done
if [ "$DRY_RUN" -eq 1 ]; then
  printf '%s\n' "[dry-run] mkdir -p $UNIT_DROPIN_DIR"
  # shellcheck disable=SC2086
  printf '%s\n' "[dry-run] write $UNIT_DROPIN_FILE from: node $HOST_SANDBOX_JS override $OVERRIDE_ARGS"
  # shellcheck disable=SC2086
  node "$HOST_SANDBOX_JS" override $OVERRIDE_ARGS | sed 's/^/[dry-run]   /'
else
  mkdir -p "$UNIT_DROPIN_DIR"
  OVERRIDE_TMP="$UNIT_DROPIN_FILE.tmp.$$"
  # shellcheck disable=SC2086
  node "$HOST_SANDBOX_JS" override $OVERRIDE_ARGS > "$OVERRIDE_TMP"
  chmod 0644 "$OVERRIDE_TMP"
  mv "$OVERRIDE_TMP" "$UNIT_DROPIN_FILE"
fi

# Optional polkit rule for narrowly scoped systemctl reload. Prefer polkit
# over sudoers: NoNewPrivileges=true blocks setuid helpers such as sudo.
if [ -n "$RELOAD_SERVICES" ]; then
  POLKIT_ARGS="--user $AGENT_USER"
  for reload_service in $RELOAD_SERVICES; do
    POLKIT_ARGS="$POLKIT_ARGS --reload-service $reload_service"
  done
  if [ "$DRY_RUN" -eq 1 ]; then
    # shellcheck disable=SC2086
    printf '%s\n' "[dry-run] write $POLKIT_RULE_FILE from: node $HOST_SANDBOX_JS polkit $POLKIT_ARGS"
    # shellcheck disable=SC2086
    node "$HOST_SANDBOX_JS" polkit $POLKIT_ARGS | sed 's/^/[dry-run]   /'
  else
    POLKIT_TMP="$POLKIT_RULE_FILE.tmp.$$"
    mkdir -p "$(dirname -- "$POLKIT_RULE_FILE")"
    # shellcheck disable=SC2086
    node "$HOST_SANDBOX_JS" polkit $POLKIT_ARGS > "$POLKIT_TMP"
    chmod 0644 "$POLKIT_TMP"
    mv "$POLKIT_TMP" "$POLKIT_RULE_FILE"
  fi
elif [ "$DRY_RUN" -eq 1 ]; then
  printf '%s\n' "[dry-run] no --reload-service set; leaving $POLKIT_RULE_FILE untouched/absent"
else
  rm -f "$POLKIT_RULE_FILE"
fi

run systemctl daemon-reload
run systemctl enable "$UNIT_NAME"
run systemctl start "$UNIT_NAME"

log ""
log "Install complete. Next steps:"
log "  1. Check the service:      systemctl status $UNIT_NAME"
log "  2. Follow the logs:        journalctl -u $UNIT_NAME -f"
log "  3. Confirm registration in the dashboard (CertOps > Agent fleet):"
log "     the agent should appear as active within about a minute."
log "     (The agent deletes the single-use $BOOTSTRAP_ENV itself after"
log "     registering; no manual cleanup is needed.)"
log "  4. Configure agent-local policy and discovery in $CONFIG_PATH"
log "     (allowlists are default-deny until you set them), then:"
log "     systemctl restart $UNIT_NAME"
if [ -n "$WRITE_PATHS" ]; then
  log "  5. Ensure $AGENT_USER can write the configured cert paths:"
  for write_path in $WRITE_PATHS; do
    log "       $write_path"
  done
  log "     (ReadWritePaths opens the sandbox; ownership/ACLs still required.)"
fi
if [ -n "$RELOAD_SERVICES" ]; then
  log "  6. Reload authorization installed via polkit for: $RELOAD_SERVICES"
  log "     Configure policy commandProfiles.reloadArgv as"
  log "     [\"systemctl\",\"reload\",\"<unit>\"] (no sudo)."
fi

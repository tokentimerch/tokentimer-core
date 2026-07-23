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
#      (template: tokentimer-agent.service next to this script).
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
  --workspace-id ID      Workspace the agent belongs to (recorded in
                         config.json; the bootstrap token is already
                         workspace-scoped server-side).
  Bootstrap token        Via TOKENTIMER_AGENT_BOOTSTRAP_TOKEN env var
                         (preferred; keeps it out of shell history) or
                         --bootstrap-token TOKEN. Single-use ttboot_ token
                         created in the dashboard (CertOps > Deploy an agent).

Options:
  --ca-bundle PATH       PEM CA bundle for a private-CA control plane
                         (copied into the state dir, config.json caBundlePath).
  --dry-run              Print every action without executing anything.
  --uninstall            Stop/disable the service and remove the app dir and
                         unit file. The state dir (credential, keys) and the
                         system user are preserved; remove them manually once
                         you are sure (rm -rf /opt/tokentimer-agent &&
                         userdel tokentimer-agent).
  -h, --help             Show this help.

Layout created:
  /opt/tokentimer-agent/app     agent package (read-only at runtime)
  /opt/tokentimer-agent/state   config dir, mode 0700, owner tokentimer-agent:
                                config.json (0600), credential (0600, written
                                by the agent at registration), bootstrap.env
                                (0600, delete after first successful start)

After install:
  systemctl status tokentimer-agent
  journalctl -u tokentimer-agent -f
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
  run systemctl daemon-reload
  run rm -rf "$APP_DIR"
  log "Uninstalled the service and app dir."
  log "Preserved (remove manually once you are sure):"
  log "  - $STATE_DIR (agent credential, keys, replay store)"
  log "  - system user $AGENT_USER (userdel $AGENT_USER)"
  exit 0
fi

# ----------------------------------------------------------- validate input
[ -n "$API_URL" ] || fail "--api-url is required (control plane base URL)"
[ -n "$WORKSPACE_ID" ] || fail "--workspace-id is required"
[ -n "$BOOTSTRAP_TOKEN" ] || fail "bootstrap token is required: set TOKENTIMER_AGENT_BOOTSTRAP_TOKEN or pass --bootstrap-token"
case "$BOOTSTRAP_TOKEN" in
  ttboot_*) : ;;
  *) fail "bootstrap token does not look like a ttboot_ token (value not shown)" ;;
esac
case "$API_URL" in
  http://*|https://*) : ;;
  *) fail "--api-url must start with http:// or https://" ;;
esac
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
log "Installing agent package from $PACKAGE_DIR to $APP_DIR"
run mkdir -p "$APP_DIR"
# Copy the package contents (src/, bin/, package.json, scripts/). The agent
# is zero-dependency, so no npm/pnpm install step is needed.
if [ "$DRY_RUN" -eq 1 ]; then
  printf '%s\n' "[dry-run] cp -R $PACKAGE_DIR/. $APP_DIR/ (excluding node_modules)"
else
  # tar pipe preserves layout and lets us exclude node_modules portably.
  (cd "$PACKAGE_DIR" && tar -cf - --exclude=./node_modules .) | (cd "$APP_DIR" && tar -xf -)
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
  umask 177
  {
    printf '{\n'
    printf '  "serverUrl": "%s",\n' "$API_URL"
    printf '  "workspaceId": "%s"' "$WORKSPACE_ID"
    if [ -n "$CA_BUNDLE_DEST" ]; then
      printf ',\n  "caBundlePath": "%s"' "$CA_BUNDLE_DEST"
    fi
    printf '\n}\n'
  } > "$CONFIG_PATH"
  umask 022
  chmod 0600 "$CONFIG_PATH"
fi

# --------------------------------------- bootstrap token env file (0600)
# The single-use ttboot_ token is stored only for the service's first-run
# registration and is never printed by this script. Delete bootstrap.env
# once the agent shows up as active in the dashboard.
BOOTSTRAP_ENV="$STATE_DIR/bootstrap.env"
if [ "$DRY_RUN" -eq 1 ]; then
  printf '%s\n' "[dry-run] write $BOOTSTRAP_ENV (0600) with TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=<redacted>"
else
  umask 177
  printf 'TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=%s\n' "$BOOTSTRAP_TOKEN" > "$BOOTSTRAP_ENV"
  umask 022
  chmod 0600 "$BOOTSTRAP_ENV"
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
run systemctl daemon-reload
run systemctl enable "$UNIT_NAME"
run systemctl start "$UNIT_NAME"

log ""
log "Install complete. Next steps:"
log "  1. Check the service:      systemctl status $UNIT_NAME"
log "  2. Follow the logs:        journalctl -u $UNIT_NAME -f"
log "  3. Confirm registration in the dashboard (CertOps > Agent fleet):"
log "     the agent should appear as active within about a minute."
log "  4. After it registers, remove the single-use bootstrap token file:"
log "     rm $BOOTSTRAP_ENV"
log "  5. Configure agent-local policy and discovery in $CONFIG_PATH"
log "     (allowlists are default-deny until you set them), then:"
log "     systemctl restart $UNIT_NAME"

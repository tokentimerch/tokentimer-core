#!/usr/bin/env sh
# acme.sh dnsapi wrapper for TokenTimer CertOps native DNS-01 solvers.
#
# Contract (real acme.sh dnsapi): this file is SOURCED from acme.sh's
# dnsapi/ directory (installed as dns_certops.sh). acme.sh then calls the
# shell FUNCTIONS defined here:
#
#   dns_certops_add <fulldomain> <txtvalue>
#   dns_certops_rm  <fulldomain> <txtvalue>
#
# where <fulldomain> is the COMPLETE TXT record name already prefixed by
# acme.sh (e.g. "_acme-challenge.www.example.com"), NOT the bare FQDN.
#
# The Node hook (certops-dns-hook) expects the BASE domain (same semantics
# as certbot's CERTBOT_DOMAIN) and itself prepends "_acme-challenge.".
# Passing fulldomain through unchanged would double-prefix. This wrapper
# therefore strips a leading "_acme-challenge." before exporting ACME_DOMAIN.
#
# Credentials never appear here — certops-dns-hook loads them from
# agent-local 0600 files via config.json.
#
# Usage from the ACME adapter:
#   acme.sh ... --dns dns_certops ...
#   (hook name = basename of this file without .sh; NOT an absolute path)
#
# Required env (set by the agent ACME adapter, not a secret):
#   CERTOPS_DNS_HOOK  absolute path to certops-dns-hook.js

# Strip a single leading "_acme-challenge." so ACME_DOMAIN is the base
# domain the Node hook will re-prefix. Idempotent if already bare.
_certops_base_domain() {
  _fd="$1"
  case "$_fd" in
    _acme-challenge.*)
      printf '%s' "${_fd#_acme-challenge.}"
      ;;
    *)
      printf '%s' "$_fd"
      ;;
  esac
}

_certops_resolve_hook() {
  if [ -n "${CERTOPS_DNS_HOOK:-}" ]; then
    printf '%s' "$CERTOPS_DNS_HOOK"
    return 0
  fi
  # Fallback when sourced: $0 is unreliable; prefer sibling of this file
  # only if BASH_SOURCE / a caller set CERTOPS_DNSAPI_DIR. Otherwise fail.
  if [ -n "${CERTOPS_DNSAPI_DIR:-}" ] && [ -f "$CERTOPS_DNSAPI_DIR/certops-dns-hook.js" ]; then
    printf '%s' "$CERTOPS_DNSAPI_DIR/certops-dns-hook.js"
    return 0
  fi
  return 1
}

# fulldomain txtvalue — acme.sh DNS-01 present
dns_certops_add() {
  _fulldomain="$1"
  _txtvalue="$2"
  _hook="$(_certops_resolve_hook)" || {
    echo "dns_certops: CERTOPS_DNS_HOOK is unset and no fallback hook path is available" >&2
    return 1
  }
  _basedomain="$(_certops_base_domain "$_fulldomain")"
  # Subshell call (NOT exec): acme.sh sourced this file and must regain
  # control after the hook returns. Propagate the Node exit status.
  ACME_DOMAIN="$_basedomain" ACME_TXT_VALUE="$_txtvalue" \
    node "$_hook" present
  return $?
}

# fulldomain txtvalue — acme.sh DNS-01 cleanup
dns_certops_rm() {
  _fulldomain="$1"
  _txtvalue="$2"
  _hook="$(_certops_resolve_hook)" || {
    echo "dns_certops: CERTOPS_DNS_HOOK is unset and no fallback hook path is available" >&2
    return 1
  }
  _basedomain="$(_certops_base_domain "$_fulldomain")"
  ACME_DOMAIN="$_basedomain" ACME_TXT_VALUE="$_txtvalue" \
    node "$_hook" cleanup
  return $?
}

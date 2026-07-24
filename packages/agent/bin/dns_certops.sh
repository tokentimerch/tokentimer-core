#!/usr/bin/env sh
# acme.sh dnsapi wrapper for TokenTimer CertOps native DNS-01 solvers.
#
# Contract (acme.sh): this file is sourced; acme.sh calls dns_certops_add /
# dns_certops_rm with (domain, txt_value). Credentials never appear here —
# certops-dns-hook loads them from agent-local 0600 files via config.json.
#
# Usage from the ACME adapter:
#   acme.sh ... --dns /absolute/path/to/dns_certops.sh ...
# Optional env (set by the agent ACME adapter, not a secret):
#   CERTOPS_DNS_HOOK  absolute path to certops-dns-hook.js

dns_certops_add() {
  _fulldomain="$1"
  _txtvalue="$2"
  _hook="${CERTOPS_DNS_HOOK:-}"
  if [ -z "$_hook" ]; then
    _hook="$(CDPATH= cd -- "$(dirname "$0")" && pwd)/certops-dns-hook.js"
  fi
  ACME_DOMAIN="$_fulldomain" ACME_TXT_VALUE="$_txtvalue" \
    exec node "$_hook" present
}

dns_certops_rm() {
  _fulldomain="$1"
  _txtvalue="$2"
  _hook="${CERTOPS_DNS_HOOK:-}"
  if [ -z "$_hook" ]; then
    _hook="$(CDPATH= cd -- "$(dirname "$0")" && pwd)/certops-dns-hook.js"
  fi
  ACME_DOMAIN="$_fulldomain" ACME_TXT_VALUE="$_txtvalue" \
    exec node "$_hook" cleanup
}

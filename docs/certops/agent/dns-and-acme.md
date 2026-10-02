# DNS and ACME configuration

The bundled agent uses **DNS-01**. It proves domain control by publishing a TXT record and supports wildcard certificates. Configure the provider, zone, CA endpoint, and local command profile before requesting issuance.

For **HTTP-01**, use an external ACME client or cert-manager and connect its public certificate results through the executor/controller workflow. The native agent does not switch to HTTP-01 by changing its command profile. See [challenge selection and the HTTP-01 webroot example](https://tokentimer.ch/docs/self-hosted/certops/acme-challenges).

<a id="dns-01-providers"></a>

### DNS-01 providers

`src/dns` implements native TXT-record solvers so DNS-01 challenges no
longer require the ACME tool's own DNS plugins. certbot/acme.sh still drive
the ACME conversation; the ACME adapter always wires them to the
`certops-dns-hook` executable (`packages/agent/bin/certops-dns-hook.js`)
and, for acme.sh, the shipped `dns_certops.sh` dnsapi wrapper. The hook
resolves the managed zone (longest `zoneProviderMap` match, else DNS NS
walk refined by the provider zone list when available), presents/cleans
the TXT value under a cross-process file lock, then polls authoritative
nameservers (and optional configured recursive resolvers) until the value
is visible — or gone on cleanup — before returning success to the ACME
tool. Zero npm dependencies: HTTP providers use global `fetch`, Route 53
SigV4, the GCP JWT, the OVH request signature, and the Exoscale
EXO2-HMAC-SHA256 signature are computed with `node:crypto`, and RFC 2136
speaks the DNS wire format over `node:net` with a TSIG HMAC (RFC 8945,
`hmac-sha1/224/256/384/512`).

Wave-1 provider ids (exact-match against `policy.allowedDnsProviders`):
`cloudflare`, `route53`, `azure-dns`, `google-cloud-dns`, `rfc2136`,
`acme-dns`. Wave-2 provider ids: `ovhcloud`, `hetzner`, `infomaniak`,
`exoscale`, `powerdns`.

Test-only provider id: `pebble-challtestsrv` — Let's Encrypt's own
companion DNS mock for the Pebble ACME test server (no authentication;
never appropriate for a production `caEndpoint`). Use it only in a
workspace policy scoped to a test CA, to validate the DNS-01 path locally
without any real DNS zone.

Config (`config.json`): each configured provider maps to an object holding
the absolute path of its agent-local credentials file plus optional
non-secret options; the reserved `zoneProviderMap` key routes zones to
providers on multi-provider hosts (longest matching zone wins, dot-boundary
rule; with a single provider and no map entry, that provider is selected
and the zone is discovered via DNS NS / provider zone list — the challenge
hostname is never assumed to be the zone). Optional top-level
`dnsPropagation` controls the post-present / post-cleanup wait:

```json
{
  "dnsPropagation": {
    "timeoutMs": 120000,
    "intervalMs": 2000,
    "resolvers": ["1.1.1.1", "8.8.8.8"],
    "checkAuthoritative": true,
    "verificationMode": "all",
    "quorumCount": null
  }
}
```

`verificationMode` defaults to `all`, requiring every configured resolver
(and the authoritative check, when enabled) to independently confirm the
TXT record before the hook proceeds. Set it to `quorum` with a
`quorumCount` (positive integer, required in quorum mode) to instead
proceed once that many independent server checks confirm — useful when one
of several public resolvers is flaky or slow to pick up the record.

```json
{
  "dnsProviders": {
    "cloudflare": { "credentialsFile": "/etc/tokentimer-agent/dns/cloudflare.json" },
    "rfc2136": { "credentialsFile": "/etc/tokentimer-agent/dns/rfc2136.json" },
    "zoneProviderMap": {
      "example.com": "cloudflare",
      "internal.example.net": "rfc2136"
    }
  }
}
```

Credentials files are JSON objects, must be `0600` (the agent refuses
group/other-readable files on POSIX), and never leave the host:

| Provider | Credentials file fields |
|----------|-------------------------|
| `cloudflare` | `apiToken` (scoped token, Zone.DNS:Edit); optional `zoneId` (looked up by zone name when absent) |
| `route53` | `accessKeyId`, `secretAccessKey`; optional `sessionToken`, `hostedZoneId` (else `ListHostedZonesByName`), `region` (default `us-east-1`) |
| `azure-dns` | `tenantId`, `clientId`, `clientSecret`, `subscriptionId`, `resourceGroup` (client-credentials flow, DNS Zone Contributor role) |
| `google-cloud-dns` | `client_email`, `private_key`, `project_id` (standard SA JSON fields); optional `managedZone` (else looked up by `dnsName`). The SA key is a DNS credential: it signs the OAuth JWT locally and never leaves the host |
| `rfc2136` | `server`, `keyName`, `keySecretBase64`; optional `port` (default 53), `keyAlgorithm` (default `hmac-sha256`) |
| `acme-dns` | `baseUrl`, `username`, `password`, `subdomain` (from `/register`). Cleanup is a documented no-op: acme-dns rotates its two TXT slots automatically. The provider declares `capabilities.cleanupVerifiable: false`, so the hook skips the generic wait-for-TXT-absence poll after cleanup and reports evidence `status: "cleanup_not_applicable"` instead of failing/timing out |
| `ovhcloud` | `applicationKey`, `applicationSecret`, `consumerKey`; optional `endpoint` (default `https://eu.api.ovh.com/1.0`; other regions `https://ca.api.ovh.com/1.0`, `https://api.us.ovhcloud.com/1.0`). Requests are OVH-signed (`$1$` + SHA1) with the LOCAL unix time as `X-Ovh-Timestamp` (no `/auth/time` skew correction); a `POST /domain/zone/<zone>/refresh` follows every mutation so the change actually serves |
| `hetzner` | `apiToken` — **Hetzner Console / Cloud project API token** (`Authorization: Bearer`), not a legacy DNS Console token. Optional `zoneId` (looked up by zone name when absent). Uses `https://api.hetzner.cloud/v1` rrset `add_records` / `remove_records` actions (value-specific; concurrent challenges do not clobber each other). Legacy `dns.hetzner.com` Auth-API-Token credentials are not supported |
| `infomaniak` | `apiToken` (Bearer; v2 API requires `domain:read`, `dns:read`, and `dns:write` scopes together, not the older single `domain` scope). Every response is wrapped in a `{ result: "success"\|"error", data }` envelope; a non-`success` result is treated as failure even on HTTP 200 |
| `exoscale` | `apiKey`, `apiSecret`; optional `apiEndpoint` (default `https://api-ch-gva-2.exoscale.com/v2`; DNS is global, any zone endpoint works). Requests are EXO2-HMAC-SHA256 signed. Mutations are async on Exoscale's side: the accepted operation response is treated as success; the hook's propagation wait covers the apply window |
| `powerdns` | `apiUrl` (must be `https:`, e.g. `https://pdns.example:8081`; a loopback `http://127.0.0.1:8081` endpoint requires an explicit `allowInsecureLocalHttp: true`), `apiKey` (X-API-Key header); optional `serverId` (default `localhost`). Zone and record names carry a trailing dot and TXT content is double-quoted, per PowerDNS API rules. Present merges with existing TXT values at the name and `REPLACE`s the union (parallel challenges never clobber each other); cleanup `REPLACE`s the remainder or sends `changetype: DELETE` when none remain |
| `pebble-challtestsrv` | `baseUrl` (challtestsrv's management interface, default port `8055`; a loopback `http://127.0.0.1:8055` endpoint requires `allowInsecureLocalHttp: true`). No API key: challtestsrv has no authentication by design ("TEST USAGE ONLY"). `POST {baseUrl}/set-txt` / `POST {baseUrl}/clear-txt` with `{ host: "<name>.", value }`. Declares `capabilities.cleanupVerifiable: true` (unlike `acme-dns`, `/clear-txt` genuinely deletes the record) |

Hook usage. The ACME adapter builds these flags automatically; operators
debugging by hand can use the same contract. certbot manual hooks (the hook
derives the TXT name `_acme-challenge.$CERTBOT_DOMAIN` and reads
`CERTBOT_DOMAIN` + `CERTBOT_VALIDATION` from the environment certbot sets):

```
certbot certonly --csr <csr.pem> --preferred-challenges dns --manual \
  --manual-auth-hook    "/path/to/certops-dns-hook.js present" \
  --manual-cleanup-hook "/path/to/certops-dns-hook.js cleanup" \
  --config-dir <stateDir>/acme/certbot/config \
  --work-dir   <stateDir>/acme/certbot/work \
  --logs-dir   <stateDir>/acme/certbot/logs
```

On win32, the hook string is instead `"<node.exe path>" "<hookPath>" present`
/ `... cleanup` — certbot invokes the hook string through a shell, and a
bare `.js` path has no useful Windows file association, so the node
executable must be named explicitly (2026-08-05 real-host finding; also
note that Certbot itself dropped official Windows support in February 2024,
so this format matters mainly for `acmeKind: "acme.sh"` deployments run
under Git Bash, and for anyone still running a self-built/unsupported
Windows certbot).

For acme.sh, `--dns` takes the shipped dnsapi hook **name** (`dns_certops`),
not an absolute path — acme.sh sources `dnsapi/dns_certops.sh` from its own
config home and calls the `dns_certops_add` / `dns_certops_rm` shell
functions it defines. The installer symlinks the shipped script into
`<stateDir>/acme/acme.sh/dnsapi/dns_certops.sh`:

```
CERTOPS_DNS_HOOK=/path/to/certops-dns-hook.js \
LE_CONFIG_HOME=<stateDir>/acme/acme.sh \
  acme.sh --signcsr --csr <csr.pem> --dns dns_certops \
  --home <stateDir>/acme/acme.sh --config-home <stateDir>/acme/acme.sh --force ...
```

`--force` is mandatory, not optional. `--signcsr` internally calls acme.sh's
own `issue()` routine, which persists a per-domain `Le_NextRenewTime` in its
own state and silently exits `2` (`RENEW_SKIP`) on any invocation before that
self-tracked time. TokenTimer's control plane, not acme.sh, is the sole
authority on when a renewal should run (per-CA cap, `renewBeforeDays`,
manual/forced requests), so a renew job the server has already validated and
signed must never be second-guessed by acme.sh's own clock. Without `--force`,
any renew dispatched ahead of acme.sh's internally-computed schedule fails
instead of running. certbot's `--csr` mode has no equivalent stateful skip,
so this is acme.sh-specific (discovered during full end-to-end testing of the
acme.sh adapter against a live Cloudflare zone; see `src/acme/index.js`'s
`buildAdapterArgs`).

Relatedly: acme.sh routes most of its own diagnostics, including the
`RENEW_SKIP` message above, through its `_info` logger to **stdout**, not
stderr (only `_err` output lands on stderr). `index.js`'s failure path
(`acmeFailureDetail`) therefore falls back to `stdoutExcerpt` whenever
`stderrExcerpt` is empty, and both excerpts are attached to the
`validation.failed` evidence item's metadata (`stderrExcerpt`/
`stdoutExcerpt`), so an acme.sh failure is never reported as the previous,
undiagnosable "exit code 2, no stderr" with no way to tell why from the
control plane alone.

`dns_certops.sh` strips one leading `_acme-challenge.` from the complete TXT
name acme.sh calls it with and exports `ACME_DOMAIN` (base domain) /
`ACME_TXT_VALUE` into `certops-dns-hook present|cleanup`, which prepends
`_acme-challenge.` itself (same convention as certbot's `CERTBOT_DOMAIN`).
Credentials never appear on argv or in the ACME tool environment. Both
tools' working state (config/work/log dirs, or acme.sh's home) lives under
the agent's own state directory so they stay writable under the hardened
systemd unit's `ProtectSystem=strict`. See `COORDINATION-ACME-ADAPTER.md` at
the repo root for the full typed adapter-options contract (`preferredChain`,
`eabKid`/`eabHmacKey`); the adapter no longer accepts a generic `extraArgs`
passthrough.

**A full, real, tested walkthrough** — install, Cloudflare credentials,
`config.json`, job payload, and every pitfall actually hit (certbot account
registration flags, the chain-path save crash above, `certPath` needing to
be a file rather than a directory) — is documented step by step at
<https://tokentimer.ch/docs/self-hosted/next/runbooks/certops-cloudflare-worked-example>
(mirrored for the SaaS variant at
<https://tokentimer.ch/docs/cloud/runbooks/certops-cloudflare-worked-example>).
That page exists specifically so this reference material does not have to
be re-derived by trial and error a second time.

Policy gate: the hook resolves the provider and zone for the domain, then
requires BOTH `checkDnsProvider` and `checkDnsZone` to pass against the
agent-local policy engine before reading any credentials file or making any
network call. A rejection prints the `{ allowed: false, rejectionReason,
detail }` JSON to stderr and exits nonzero, so the provider id must be in
`policy.allowedDnsProviders` and the zone covered by
`policy.allowedDnsZones` (suffix match with dot boundary). Solver failures
never carry secrets: every provider response excerpt is bounded to 1024
chars and replaced wholesale with `[redacted]` if it contains a
`PRIVATE KEY` marker or any of the credential strings themselves.

Hook exit contract (`src/dns/hook.js`) — the whole interface to certbot /
acme.sh is the exit code plus the two streams:

| Exit | Meaning |
|------|---------|
| `0` | TXT record published (or removed) **and** verified per `dnsPropagation` |
| `1` | Operational failure: policy rejection, missing/unreadable `dnsProviders` config or credentials file, provider API error, or propagation timeout |
| `2` | Usage error: unknown mode (not `present`/`cleanup`), or missing `CERTBOT_DOMAIN`/`CERTBOT_VALIDATION` (`ACME_DOMAIN`/`ACME_TXT_VALUE`) |

`2` means the hook was wired up wrong and never reached the provider; `1`
means it tried and something refused. **stdout** carries one JSON object per
line of structured progress, including a `dns.propagation` event (provider,
zone, record name, attempts, elapsed, resolvers consulted) — the stream to
read when a challenge is slow rather than broken. **stderr** carries
failures: policy rejections and provider errors as machine-readable JSON
verdict objects, usage errors as plain text prefixed `certops-dns-hook:`.

The hook **fails loud and never fails open**: any unresolvable zone,
unreadable credential, policy refusal, or unconfirmed propagation exits
nonzero so the ACME client aborts *before* asking the CA to validate. A
silent "success" leaving no TXT record would burn a validation attempt and,
with some CAs, count against a rate limit. Because credentials are excluded
from every log line, evidence record, and error message (including the JSON
verdicts), an authentication failure shows *that* auth failed and never the
token that failed — verify credentials against the provider directly.

## Related

[Agent overview](../agent.md) · [Configuration](configuration.md) · [Operations](operations.md)

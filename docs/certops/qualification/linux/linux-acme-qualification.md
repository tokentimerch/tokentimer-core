# Real Linux ACME qualification

The trusted-main manual `certops-real-acme.yml` workflow runs four independent Ubuntu 24.04 jobs: certbot 4.2.0 and acme.sh 3.1.2 at commit `40290ad42a37aba57eb246e507c11944a52c0f68`. Each client runs with ordinary account registration and separately with mandatory External Account Binding (EAB). All environments use pinned Pebble 2.8.0 and its real DNS challenge service, a migrated disposable API/PostgreSQL stack, and the production Node agent. The acme.sh checkout is verified before execution. The client/account matrix has separate report scopes and artifacts; a successful certbot report cannot replace acme.sh coverage.

Each journey registers a fresh agent, uploads public file discovery, authenticates through the real login/session/CSRF flow, and requests issuance through the public workspace jobs API. It receives actual signed dispatch, generates a local key and CSR, executes the selected real ACME client and shipped DNS hook, deploys the certificate, and persists job/evidence state. The file-discovery fixtures include an adjacent private key, a disguised private-key file, base64-wrapped private data, a mixed certificate/key file, and an oversized file. Only the independently parsed public certificate may appear in observation evidence; private-key contents and a body-fragment sentinel must remain local.

Before issuance, a real owned HTTPS directory gateway exercises three responses: HTTP503, an ACME `rateLimited` problem with HTTP429 and `Retry-After: 0`, and malformed JSON with HTTP200. Each authenticated public issue job must genuinely fail within the bounded deadline without installing or promoting a certificate. An independent request counter proves that the native client encountered each response, and authoritative DNS checks require no residual TXT challenges. Restoring forwarding then reaches the actual Pebble issuer. These cases cover directory admission failures and subsequent issuance recovery; they do not prove a CA process crash, order-stage throttling, or retrying the same failed job. Native execution of the added cases remains pending.

The real six-day Pebble certificate naturally enters the default renewal window. Successful deployment must derive a reusable profile and enable its actual management period. The real renewal scheduler then admits two successive automation-sourced renewals; the same agent executes both. Each cycle requires a new CA-issued leaf, genuinely advanced expiry, genuinely rotated agent-local public key, matching local private key, persisted evidence and the new leaf served through trusted TLS. The test never edits certificate or scheduler timestamps. Before the second cycle it briefly pauses only its owned agent process while two actual sweeps race, requires exactly one job for that expiry generation, and resumes execution in a finalizer.

The public request includes an apex name, its wildcard and an additional SAN. Every initial and renewed leaf must contain exactly those names. The trusted real ACME directory must independently advertise the chosen EAB requirement. Required-EAB environments configure a fresh CA-side HMAC and a protected agent-local account file; only an opaque reference enters public dispatch and the derived profile. Persisted jobs, profiles and evidence must not contain the HMAC. The CA account configuration follows the [Pebble external-account-binding fixture](https://github.com/letsencrypt/pebble/blob/v2.8.0/test/config/pebble-config-external-account-bindings.json). Before valid issuance, required-EAB environments submit actual public jobs using a missing local account file and an invalid HMAC. Both must fail without installing a certificate or promoting the managed identity; the valid account then issues successfully. Both HMACs must remain absent from persisted public data. Other account/contact and CA failure modes remain separate coverage gaps.

The TLS observer verifies the requested hostname and chain against this run's fresh Pebble issuing root. The harness retrieves only the public `/roots/0` certificate through the fixture management interface, whose HTTPS certificate is explicitly trusted for that request. It never retrieves CA keys or installs the fixture root into the operating system. This follows the [Pebble management interface](https://github.com/letsencrypt/pebble#management-interface) contract. Initial and renewed TLS observations have bounded timeouts and must present exactly the independently parsed deployed fingerprint.

An independent authoritative DNS resolver checks that challenge TXT records are absent after failed jobs, initial issuance and each renewal. A dead DNS server or resolver timeout cannot count as cleanup.

The workflow requires all eleven protocol test names plus the real issuance/renewal journey. Missing clients, failed jobs, skipped tests, incomplete reports, and cleanup failures prevent qualification. Reports contain named outcomes and source/candidate identity; private keys, credentials, raw agent stdout, and ACME logs are not uploaded.

After both naturally due scheduler generations, the journey submits an
authenticated public manual renew request containing only the managed identity
and idempotency key. The resulting job must resolve the existing command, CA,
deployment path, DNS provider/zone and exact SAN set from its stored profile.
Repeating the request must return the same job. Actual agent execution must
produce another leaf with changed serial and SPKI, a matching local private
key, independently trusted replacement TLS, persisted evidence and no residual
TXT values. The stored execution profile must remain unchanged. This mandatory
source runs for both clients, including the existing EAB and Alpine variants;
native execution remains pending. The journey has a twelve-minute deadline
inside the fourteen-minute test-process bound, leaving workflow time for fixture
setup, report validation and unconditional cleanup.

This lane uses the public issuance REST API and invokes the production renewal scheduler within the disposable test process. It does not claim a separately scheduled worker daemon, systemd supervision, nginx/Apache/HAProxy reload, external DNS-provider credentials, or every ACME failure mode. Linux installer/systemd, browser, API, and provider scenarios remain distinct. The native workflow has not been executed during implementation; full CI qualification remains pending.


## Foreground Alpine and musl

The separate trusted-main manual `certops-alpine-acme-qualification.yml` runs both clients in the exact pinned Node24 Alpine3.23.6 image. It asserts the actual distribution, musl loader and container surface, installs the frozen workspace and migrates a disposable PostgreSQL service. Its real API child and agent run in the foreground alongside the real CA and DNS service. The same public issuance, gateway failure, wildcard/SAN, two-renewal-cycle, key-rotation, trusted TLS and DNS-cleanup assertions are mandatory. Native libc/container measurements appear in separate report scopes. This lane qualifies foreground execution; OpenRC/systemd supervision and EAB-on-Alpine remain separate. Only image identity, source syntax and workflow checks have run during implementation; the native certificate journey is pending.

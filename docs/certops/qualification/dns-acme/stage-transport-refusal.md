# ACME stage transport refusal

The qualification proxy targets pinned Pebble v2.8.0. Its upstream HTTPS target
is fixed to loopback port 14000 and validates the actual pinned CA certificate.
It preserves the external proxy `Host`, original request path and signed body
bytes. Pebble itself derives advertised URLs from that Host and checks protected
JWS URLs against the same authority; no directory or JWS rewriting occurs.

The bounded route set follows the pinned CA's public ACME endpoints and excludes
management/root-key endpoints, foreign authorities, escaped paths and URL query
or fragment inputs. Request/response bodies remain bounded. Only public counters
and native outcomes are intended as report data; signed request bodies, account
material and TLS private keys are never artifacts.

The native journey source refuses requests at `newOrder` and finalization before
forwarding them, then restores forwarding for genuine CA issuance. Finalization
refusal must follow independently observed real upstream account/order acceptance
and valid authorization or ready order. This is an owned HTTPS transport fault,
not a claim that the actual CA emitted the failure response. Public job failure,
absence of installation/activation and independent TXT cleanup are required.

The parent uses a separate owned proxy TLS certificate with an IP SAN, preserving
the existing discovery fixture. The proxy-to-Pebble hop validates the pinned
HTTPS certificate; existing local native-client qualification profiles retain
their explicit test-only TLS override. Successful CA-issued consumer TLS is
independently checked with the actual issuer root and hostname verification.

Both public fault jobs must fail without target installation or active
certificate state, then pass independent TXT cleanup. A closed sidecar is written
only after later genuine public issuance and trusted served TLS. Failed resource
drain preserves public ownership rows and private fixture files before cleanup.
Parent source, strict collection and release verification require both named
cases and the client-bound proof in each of five existing native ACME slots.
The current causal inventory contains 34 sources, including actual DNS hooks,
provider, propagation, policy, signing, API admission and reporting code.
No proxy, CA, native client or qualification workflow has run locally.

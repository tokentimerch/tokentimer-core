# Microsoft AD CS

The Windows agent can enroll from an enterprise Active Directory Certificate Services CA as the computer account. The private key stays on the host. TokenTimer does not store CA credentials.

A job with issuer kind `adcs` enrolls and renews. The agent contacts a CA only when a local enrollment rule names that CA and template. Creating an issuer or selecting it on a profile does not issue a certificate by itself. See [ADR-0014](../../adr/0014-certops-adcs-issuer-and-async-enrollment.md).

Linux hosts, and any host that cannot reach the CA over DCOM, use an [ACME gateway in front of AD CS](dns-and-acme.md#acme-gateway-in-front-of-ad-cs) instead.

## Where the agent runs

Install the agent on a domain-joined Windows member. The service runs as `LocalSystem` and authenticates to the CA with Kerberos as `DOMAIN\HOST$`. Grant Enroll on the template to that computer account, or to a group that contains it.

Do not install the agent on a domain controller. That placement is not qualified.

The transport is DCOM, the `certreq` default. The agent never passes `-rpc` to `certreq`. Enrollment web services (CES/CEP) are out of scope.

## Firewall

The member needs TCP 135 and the CA's dynamic RPC range, outbound to the CA. Blocking TCP 135 makes the submit fail before the CA records a request. The agent then retries the same CSR. It does not create a second request for a submit that never arrived.

## Certificate template

<a id="certificate-template"></a>

The template name in the issuer wizard is not created by TokenTimer. It is the template common name already published on the enterprise CA.

In Certificate Templates (`certtmpl.msc`), copy the **Template name**, not the display name. A display name such as "Web Server" can hide a template name such as `WebServer`. Publish that template on the issuing CA, and grant Enroll to the agent computer account (`DOMAIN\HOST$`) or to a group that contains it.

Type that same template name in the wizard. The dashboard does not list the CA catalog. The name must also appear, with the same CA, in the agent [enrollment rule](#enrollment-rules). A pair that is not in that rule is rejected before the CA is contacted.

<a id="template"></a>

Use a template the CA publishes, schema version 2 or later. EC keys need schema version 3 or later, and the qualified curves are P-256 and P-384 on a version 4 template.

Preflight refuses the template, before any submit, when any of these are true:

- The extended key usage is not exactly Server Authentication (`1.3.6.1.5.5.7.3.1`). Client Authentication, Any Purpose, Smart Card Logon, Certificate Request Agent, or a missing EKU all fail.
- The application policy is not Server Authentication only.
- The template is schema version 1.
- The requested key is smaller than the template minimum. On schema version 2, an EC key is refused. On schema version 3 or later, a key algorithm other than the template's algorithm is refused.

The error is `ADCS_TEMPLATE_UNSAFE`. A CA will sometimes issue a certificate that also carries Client Authentication. Preflight does not treat that as safe.

## CA flags

Preflight reads two CA settings and refuses with `ADCS_CA_CONFIG_UNSAFE` when either check fails:

- `policy\EditFlags` must not include `EDITF_ATTRIBUTESUBJECTALTNAME2`. The agent never sends a `SAN:` request attribute.
- `CA\InterfaceFlags` must include `IF_ENFORCEENCRYPTICERTREQUEST` (`0x200`), so certificate requests stay encrypted.

If the agent identity cannot read either value, preflight refuses unless local policy carries an explicit attestation for that CA.

## CA config

<a id="ca-config"></a>

`caConfig` is `DNS host\CA name`. The host is the CA computer's DNS name. The CA name is the name in the Certification Authority console, which can differ from the Windows computer name. Use that exact string in the issuer wizard and in the agent enrollment rule.

## Enrollment rules

<a id="enrollment-rules"></a>

On the agent, `config.json` lists the only CA and template pairs that host may contact:

```json
{
  "adcs": {
    "enrollmentRules": [
      {
        "caConfig": "ca01.corp.example.com\\Corp Issuing CA",
        "template": "TokenTimerWebServer"
      }
    ]
  }
}
```

`caConfig` is `host\CA name`. `template` is the template common name. A preflight or enrollment whose pair is not in this list is rejected with `issuer_not_allowlisted` and does not contact the CA. Separate CA and template allowlists are not used, because the cross product would allow pairs nobody chose.

## Renewal profile

<a id="renewal-profile"></a>

A renewal profile does not choose the template. It selects an issuer that already has a pinned CA certificate, then records the certificate DNS name, the IIS site and port, the certificate store, the key, and how many days before expiry renewal starts.

The certificate name must be a DNS name an active agent declares as a target selector. Attach the profile to that certificate in the inventory and turn automation on. The sweep enrolls only when the certificate is inside the lead time.

## Preflight and the CA key

Creating or editing an AD CS issuer sends a read-only preflight to an agent you choose. Preflight reports the template verdict, the CA flags, and each CA certificate with its key hash. Confirming a key stores `caKeySha256` on a new issuer version.

A later CA renewal that keeps the same key needs no action. A renewal that uses a new key fails pending enrollments with `ADCS_CA_KEY_CHANGED`. Run preflight again and confirm the new key before new enrollments proceed.

## Pending, uncertain, and denied

A request the CA accepts and holds is **Awaiting CA approval**. The enrollment shows the RequestId. The job ends. A later continuation polls that same request. Nothing is resubmitted while it is pending.

If the agent restarts after it has started `certreq -submit` and before it has a trustworthy result, the enrollment is **uncertain**. It is not resubmitted. Supply the RequestId from the CA, or abandon the enrollment. A supplied RequestId is accepted only when a retrieve returns a certificate for the journaled key. Abandon deletes the key on the host. A certificate the CA issues later for that request has no key.

The CA database is not readable by the computer account unless you grant CA Read. That grant exposes every row, not only this computer's requests. Leave it unset unless you accept that trade-off. Without it, reconciliation is the RequestId you supply, or a retrieve of this computer's own requests.

## Revocation

The agent checks the issued certificate before it installs anything. The member must be able to reach the CA's CRL or OCSP. A temporary outage waits and retries. An outage that lasts until the check expires does not install the certificate.

## Troubleshooting by HRESULT

Outcomes come from the CA-signed response and the process exit code. Console text is localized and is not used.

| HRESULT | When | What it means |
|---|---|---|
| `0x80094014` `CERTSRV_E_ADMIN_DENIED_REQUEST` | submit or retrieve | A CA manager denied the request. |
| `0x80094012` `CERTSRV_E_TEMPLATE_DENIED` | submit | The computer account does not have Enroll on the template. |
| `0x80094800` `CERTSRV_E_UNSUPPORTED_CERT_TYPE` | submit | The template is missing or not published on that CA. |
| `0x80094811` `CERTSRV_E_KEY_LENGTH` | submit | The key does not meet the template. |
| `0x80094003` `CERTSRV_E_BAD_REQUESTSTATUS` | submit | The key algorithm is one the template excludes. |
| `0x80070005` `E_ACCESSDENIED` | retrieve | That RequestId belongs to another requester. |
| `0x80094004` `CERTSRV_E_PROPERTY_EMPTY` | retrieve | The CA has no such RequestId. |
| `0x800706BA` `RPC_S_SERVER_UNAVAILABLE` | submit, no response file | The CA never received the request. The same CSR is retried. |
| `0x800706BF` `RPC_S_CALL_FAILED_DNE` | submit, no response file | Same as unreachable: nothing was submitted. |

Any other result after submit has started is uncertain. Do not resubmit it.

## Related

[Install on Windows](install-windows.md) · [DNS and ACME](dns-and-acme.md) · [Windows runtime](windows-runtime.md) · [ADR-0014](../../adr/0014-certops-adcs-issuer-and-async-enrollment.md)

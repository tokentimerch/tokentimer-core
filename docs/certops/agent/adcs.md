# Microsoft AD CS

The Windows agent can enroll and renew IIS certificates from an enterprise Active Directory Certificate Services CA. The service runs as `LocalSystem` and authenticates as the computer account. The private key stays on the host. TokenTimer does not store CA credentials.

A job with issuer kind `adcs` enrolls only when a local enrollment rule names that exact CA and template, a confirmed pin and fresh preflight exist on the enrolling agent, and that agent has declared `adcs-enroll-v1`. Creating an issuer, or selecting it on a profile, does not issue a certificate by itself. See [ADR-0014](../../adr/0014-certops-adcs-issuer-and-async-enrollment.md).

Cloud Pro and Team, and the Enterprise dashboard, include this issuer under **Renewals**. The CA stays on the customer network. Neither product stores CA credentials.

Linux hosts, and Windows hosts that are not domain-joined, do not enroll over DCOM. Put AD CS enrollment on a domain-joined Windows agent, or keep an [ACME gateway in front of AD CS](dns-and-acme.md#acme-gateway-in-front-of-ad-cs).

## Operator sequence

1. Join a Windows member to the domain and install the agent there. Grant Enroll on the template to that computer account, or to a group that contains it.
2. Add an [enrollment rule](#enrollment-rules) that names the CA config and the template common name. Restart `TokenTimerAgent`.
3. In **Renewals**, open **AD CS issuers** and choose **New issuer**. Name the issuer, pick the agent that can read the CA, enter the CA config and template, wait for the check, and pin one CA certificate.
4. Open **Renewal profiles** and choose **New AD CS profile**. Select that confirmed issuer, then the certificate DNS name, IIS site, port, optional SNI hostname, certificate store, key, and lead time.
5. On **Attach**, if inventory already has that DNS name, choose **Attach and enable automation**. If nothing matches, open the certificate in **Certificates** and attach the profile there. The renewal sweep enrolls when the certificate is inside the lead time.

**Renewal profiles** is the shared list on that page, and it is listed first. ACME profiles appear there after an issuance. **AD CS issuers**, further down, only prepares a private CA. Confirm an issuer there before **New AD CS profile** can select it.

## Per-enrollment timing and certificate policy

The public `POST /api/v1/workspaces/:workspaceId/certops/enrollments` request accepts four optional policy fields. Values are frozen with the selected issuer, agent, target and key; retries and continuations retain that snapshot.

- `pollInterval`: integer seconds from 60 to 86400, default 900.
- `pendingTimeout`: integer seconds from 3600 to 7776000, default 1209600 (14 days).
- `minimumRemainingValidity`: integer seconds from 0 to 31536000, default 0. An issued certificate must remain valid beyond this interval when the agent validates it.
- `requireLaterNotAfter`: boolean, default `false`. When enabled, the incoming certificate must expire later than the certificate currently installed on the target.

Omitting these fields retains the existing defaults. Explicit nulls, strings, fractional numbers and values outside these bounds are rejected before an enrollment or job is created. These options do not bypass issuer confirmation, local enrollment rules, native certificate validation or approval policy. A certificate that fails the frozen validity policy is refused before acceptance; its unaccepted key is removed and the outgoing IIS binding remains in place.

## Validation-deferral deadline

When native revocation status cannot be obtained, the issued certificate stays uninstalled and its key remains protected in `validation_deferred`. The agent retries validation until a host-local deadline, then reports `validation_expired` and removes only that unaccepted key.

Set `adcs.validationTimeoutSeconds` in the agent's protected `config.json` to an integer from `300` through `86400`. The default is `86400` (24 hours); the option permits shortening the window, not disabling or extending it. Nulls, strings, fractions and out-of-range values prevent agent startup. Restart `TokenTimerAgent` after editing it. This setting belongs to the host operator; an API enrollment or signed snapshot cannot override it.

**Operator guidance:** a short window can discard an otherwise valid issued certificate during a prolonged CRL outage. The deadline is recorded when validation first defers. Restarting the agent or restoring a longer timeout does not extend that enrollment's existing deadline. New enrollments use the new setting; installed or already accepted keys are preserved by installation-recovery custody checks.

## Where the agent runs

Install the agent on a domain-joined Windows member. The service runs as `LocalSystem` and authenticates to the CA with Kerberos as `DOMAIN\HOST$`. Grant Enroll on the template to that computer account, or to a group that contains it.

Do not install the agent on a domain controller. That placement is not qualified.

The transport is DCOM, the `certreq` default. The agent never passes `-rpc` to `certreq`. Enrollment web services (CES and CEP) are not part of this release.

## Firewall

The member needs outbound TCP 135 (the RPC endpoint mapper) and the CA's dynamic RPC range, to the CA. Blocking TCP 135 makes the submit fail before the CA records a request. The agent then retries the same request. It does not create a second request for a submit that never arrived. The error is `ADCS_CA_UNREACHABLE`, and the 14-day approval limit has not started.

## Certificate template

<a id="certificate-template"></a>

The template name in the issuer wizard is not created by TokenTimer. It is the template common name already published on the enterprise CA.

In Certificate Templates (`certtmpl.msc`), copy the **Template name**. A display name such as "Web Server" can hide a template name such as `WebServer`. Publish that template on the issuing CA, and grant Enroll to the agent computer account (`DOMAIN\HOST$`) or to a group that contains it.

Type that same template name in the wizard. The dashboard does not list the CA catalog. The name must also appear, with the same CA, in the agent [enrollment rule](#enrollment-rules). A pair that is not in that rule is rejected before the CA is contacted.

<a id="template"></a>

Use a template the CA publishes, schema version 2 or later. The extended key usage must be exactly Server Authentication (`1.3.6.1.5.5.7.3.1`). The application policy must be Server Authentication only. Client Authentication, Any Purpose, Smart Card Logon, Certificate Request Agent, or a missing extended key usage all fail the check. A CA will sometimes issue a certificate that also carries Client Authentication. The check does not treat that as safe.

EC keys need schema version 3 or later. The profile offers P-256 and P-384. On schema version 2, an EC key is refused. On schema version 3 or later, a key algorithm other than the template's algorithm is refused. A requested key smaller than the template minimum is refused. Schema version 1 is refused.

The error is `ADCS_TEMPLATE_UNSAFE`.

## CA flags

The check reads two CA settings and refuses with `ADCS_CA_CONFIG_UNSAFE` when either check fails:

- `policy\EditFlags` must not include `EDITF_ATTRIBUTESUBJECTALTNAME2`. The agent never sends a `SAN:` request attribute.
- `CA\InterfaceFlags` must include `IF_ENFORCEENCRYPTICERTREQUEST` (`0x200`), so certificate requests stay encrypted.

If the computer account cannot read either value, the check refuses. An enrollment rule can set `operatorAttested` to `true` for that CA after you have verified the flags yourself. Leave it unset otherwise. Attestation applies only to unreadable flags. A known unsafe value always refuses enrollment, including when the other flag is unreadable and `operatorAttested` is true.

Before generating a key for a new enrollment, and before resuming an enrollment that has not yet submitted its CSR, the agent reads the current template and CA settings again. It checks the template identity, server-auth-only policies, schema, minimum key size, and requested key algorithm against the frozen enrollment. Schema 2 supports RSA; newer schemas must explicitly match the requested RSA or ECDSA algorithm. Missing or ambiguous required attributes refuse enrollment with `ADCS_TEMPLATE_UNSAFE`. Unsafe CA settings refuse with `ADCS_CA_CONFIG_UNSAFE`; an unmatched CA key refuses with `ADCS_CA_KEY_UNPINNED`.

A successful check can be reused for up to five minutes between key generation and the first submit within the same execution. Each new execution reads the settings again. A safety refusal while recovering an unused key records the refusal and removes only that enrollment's unused container. A refusal before the CSR exists records no CSR or issued-certificate evidence. Already submitted requests keep their frozen issuer and follow retrieval and certificate validation; later template edits do not turn a pending request into a new submission. Signed terminal cleanup also remains independent of CA availability.

## CA config

<a id="ca-config"></a>

CA config is `DNS host\CA name`. The host is the CA computer's DNS name. The CA name is the name in the Certification Authority console, which can differ from the Windows computer name. Use that exact string in the issuer wizard and in the agent enrollment rule.

Example: `ca01.corp.example.com\Corp Issuing CA`.

## Enrollment rules

<a id="enrollment-rules"></a>

On the agent, `config.json` lists the only CA and template pairs that host may contact:

```json
{
  "adcs": {
    "enrollmentRules": [
      {
        "caConfig": "ca01.corp.example.com\\Corp Issuing CA",
        "template": "WebServer",
        "dnsScopes": ["corp.example.com"],
        "keyAlgorithms": ["rsa", "ecdsa"]
      }
    ]
  }
}
```

`caConfig` is `host\CA name`. `template` is the template common name. The pair must match the issuer exactly. A preflight or enrollment whose pair is not in this list is rejected with `issuer_not_allowlisted` and does not contact the CA. Separate CA and template allowlists are not used, because the cross product would allow pairs nobody chose.

Enrollment additionally requires `dnsScopes` and `keyAlgorithms` on one matching rule. Every requested SAN, the target name and any SNI name must equal a DNS scope or be beneath it at a dot boundary: `corp.example.com` covers `web.corp.example.com`, but not `evilcorp.example.com`. Use DNS zones without `*.` prefixes. `dnsScopes` accepts 1–32 unique ASCII zones; names are matched case-insensitively. `keyAlgorithms` accepts one or both of `rsa` and `ecdsa`; template key-size and curve constraints still apply separately. DNS permission on one rule cannot combine with key permission on another. Empty or malformed explicit lists prevent agent startup. A CA/template-only rule can perform read-only issuer preflight but cannot authorize enrollment.

**Operator action:** add explicit DNS and key constraints before enabling enrollment, then restart the service. Public issuer confirmation, profile changes and immutable signed snapshots cannot broaden these host-local permissions. Tightening a rule refuses later continuations and deletes only their exact unaccepted key; an accepted or installing key requires installation reconciliation and is preserved. Terminal cancellation/expiry cleanup remains available even after local rules change.

Restart `TokenTimerAgent` after you save the rule. The certificate DNS name on the renewal profile must be in `declaredTargetSelectors`. Add the name there and restart the agent. The next heartbeat publishes it. An empty list does not remove the last name. If the issuer wizard stays on "Waiting for the agent to report the preflight verdict", confirm the agent is online, that this rule names the same CA and template, and that the agent build advertises AD CS preflight.

## Create the issuer

In **Renewals**, open **AD CS issuers**, then **New issuer**.

1. **Name.** A name you will recognize later. This is not the CA name.
2. **Check the CA.** Choose the Windows agent that will enroll the certificate. Enter the CA config and the template common name, then **Run check**. The check reads the template and the CA certificates, and it stores the CA certificate and the template OID on that agent. It does not issue a certificate. A different agent cannot enroll until it has run the same check.
3. **Choose a certificate.** When both checks are safe, choose the newest CA certificate with **Use this certificate**. Enrollment accepts only the certificate you pin. Closing the wizard before the check finishes, or closing a safe check without pinning, discards the draft.

The issuer is ready when it shows a chosen certificate. A later CA renewal that keeps the same key needs no action. A check that comes back unsafe is not pinned. That issuer stays hidden until **Show N unsafe issuers** is checked.

## Renewal profile

<a id="renewal-profile"></a>

**Renewal profiles** lists every profile, including ACME profiles created by an issuance. In that same list, choose **New AD CS profile**. The wizard offers only issuers with a pinned CA certificate. The template stays on the issuer. The profile does not choose a new one.

1. **Issuer.** Profile name, then the confirmed AD CS issuer.
2. **Deployment.** Certificate name (the DNS name, which becomes the common name), optional extra DNS names, IIS site, port, optional SNI hostname, certificate store, key, and lead time in days. Defaults are site `Default Web Site`, port `443`, store `My`, RSA 2048, and 30 days. RSA sizes are 2048, 3072, and 4096. ECDSA sizes are 256 and 384. The certificate name is included as a DNS name. Extra names are additional names on the same certificate. Create the IIS site and listener first. The agent updates the binding. It does not create the site.
3. **Review.** Confirm the summary, then **Create profile**.
4. **Attach.** If inventory already has that DNS name, choose **Attach and enable automation**. When that registration is already managed, attaching stops the current period and starts a new one with this profile. Earlier periods stay in history. If nothing matches, the lookup fails, or the registration cannot be changed here, use **Certificates** instead. Do not attach a different certificate. The profile still enrolls the name you typed, and the other certificate stays in inventory under its old name.

An active agent must already declare the certificate name as a target selector. Add the name to `declaredTargetSelectors` and restart the agent. The next heartbeat publishes it. If none does, the renewal sweep skips the certificate and does not create an enrollment. When several active agents declare the name, the most recently seen agent receives the renewal. Run the CA check on that agent. Open the profile details to see the certificate names, not only the count. Switching auto-renewal off names those certificates.

**Certificates** is the fallback. In **Certificate management**, the registration must show this profile. **No automatic renewal** means no profile is assigned. If the registration is stopped, select this profile and choose **Start managing again**. Selecting the profile turns automation on. **Track without automatic renewal** leaves the certificate unrenewed. If the registration is already managing and shows **No automatic renewal**, stop managing, then start it again with this profile selected. Leave the profile's **Auto-renew** on. Switching it off stops renewal for every certificate that uses the profile.

The renewal sweep enrolls when that certificate is inside the lead time, automation is on, and an agent that declares the name is active. Creating the profile does not enroll immediately. If certificate operations are paused for the workspace, the sweep creates no renewal.

## Operator states

| State | Meaning | Operator action |
|---|---|---|
| Issuer configuration | An AD CS issuer exists with CA config and template under **Renewals → AD CS issuers**. | Complete CA/template preflight and pin a CA certificate before **New AD CS profile** can select it. This alone does not enroll. |
| CA/template preflight | The chosen agent ran **Run check** for that CA config and template. Verdicts and CA certificates are stored for that agent. | Fix unsafe template or CA flags, or add the matching enrollment rule, then run the check again on the agent that will enroll. |
| Confirmed CA public-key pin | You chose **Use this certificate** on a safe check. Enrollment accepts only that pin. | After a CA key change, run the check again and pin the new certificate. Same-key CA renewals need no action. |
| Agent readiness | A domain-joined Windows agent is online, has the enrollment rule, declares the certificate DNS name, and can reach the CA. | Join the domain, install the agent, grant Enroll, add the rule and target selector, restart `TokenTimerAgent`. |
| Preflight freshness (24h) | A safe preflight older than 24 hours is not usable for renewal start or cached pin reuse. | Run **Run check** again on the enrolling agent. Dashboard may show **Waiting for CA check**. |
| Enrollment eligibility | Renewal can create an enrollment when the profile is attached, automation is on, lead time applies, preflight is fresh and pinned, and an agent declares a fresh `adcs-enroll-v1`. | Confirm the agent is online, heartbeating, and declares `adcs-enroll-v1`. Issuer or profile setup alone does not start enrollment. |
| Pending CA approval | Dashboard **Awaiting CA approval**: the CA accepted the request and holds it. Polled about every 15 minutes; not resubmitted. | Approve or deny on the CA. The 14-day limit starts when the CA accepts the request. |
| Submission uncertainty | Dashboard **Submission uncertain** (`ADCS_DISPOSITION_UNKNOWN`): submit started without a trustworthy result. | Reconcile with the CA RequestId, or **Abandon** then **Free the key**. Do not resubmit. |
| Validation deferral | Dashboard **Validation deferred**: certificate issued but CRL/OCSP was unreachable to the agent service account. Nothing installed yet. | Restore revocation reachability for the computer account. After 24 hours the enrollment expires and the key is removed. |
| Capacity deferral | Certificate row shows **At CA capacity**: this CA already has as many renewals in flight as it allows. | Wait; it continues when an earlier renewal for that CA finishes. A job waiting on approval may still need attention. |
| Deployment completion | Enrollment reached **Installed**: certificate validated, accepted into the store, IIS binding updated, and verify passed. | Confirm the site serves the new certificate. No further enrollment action unless a later renewal is due. |
| **Waiting for CA check** | Renewal-path badge: path is unavailable because a fresh CA check is required (`waiting_for_fresh_preflight`). | Open the issuer under **Renewals → AD CS issuers**, pick the enrolling agent, **Run check**, and pin if needed. |
| **No AD CS support** | Pending-job label: no candidate agent has a fresh `adcs-enroll-v1` declaration (`adcs_enroll_capability_unavailable`). | Upgrade to a Windows agent build that declares `adcs-enroll-v1`, keep it online, and confirm a recent heartbeat. |

## Pending approval

A request the CA accepts and holds shows **Awaiting CA approval**, with the RequestId. The enrollment is checked again about every 15 minutes. Nothing is resubmitted while it is pending. Approve or deny it on the CA.

The 14-day limit starts when the CA accepts the request. While the enrollment is still **Requested** or **Prepared**, that limit has not started. **Cancel enrollment** removes it, and the CA was not contacted. After 14 days in **Awaiting CA approval**, the enrollment expires and the key on the host is removed.

Cancellation, expiry, and abandonment dispatch a signed cleanup continuation
to the original agent. The agent deletes only that enrollment's uninstalled
CNG key and reports completion after recording the terminal outcome. It
does not retrieve the pending CA request during cleanup, so cleanup can
finish while the CA is unavailable. If deletion fails, the control plane
keeps scheduling cleanup. A repeated continuation checks absence safely.

Cleanup refuses a key whose journal or ownership receipt shows issuance,
acceptance, or installation may have begun. If the journal is missing, an
absent key can be acknowledged, while a present key requires operator
reconciliation. Cleanup never deletes an unproven key to clear a failed job.

## Uncertain submission

If the agent restarts after it has started submit and before it has a trustworthy result, the enrollment is **Submission uncertain**. The error is `ADCS_DISPOSITION_UNKNOWN`. It is not resubmitted.

On that enrollment, enter the RequestId from the CA and choose **Reconcile**. A supplied RequestId is accepted only when a retrieve returns a certificate for the key already on the host. Or choose **Abandon**, then **Free the key**. Abandon deletes the key on the host. A certificate the CA issues later for that request has no key on the agent.

The RequestId is a candidate. The signed continuation retrieves that exact
request and checks its public key, pinned CA, template, and certificate names
before installing it. A wrong or inaccessible RequestId leaves the enrollment
uncertain and retains the key; the agent does not submit another request or
attach a different candidate automatically. A pending candidate can be checked
again after the CA approves it. Change the proposed RequestId or abandon the
enrollment when the CA cannot produce a valid certificate for it.

The CA database is not readable by the computer account unless you grant CA Read. Leave that right unset. It exposes every request, not only this computer's. Without it, reconciliation is the RequestId you supply, or a retrieve of this computer's own requests.

## Installation recovery

An interrupted enrollment reported as `installing` remains eligible for a signed continuation after its active job ends. The agent inspects the existing certificate, key and IIS binding and resumes the first incomplete installation step; it does not generate another key or submit another CA request.

A service crash after lease renewal can leave the current job `orphaned_unknown_effect`, with no final enrollment result. That status requires a human decision. Send `POST /api/v1/workspaces/:id/certops/enrollments/:enrollmentId/recover` with the exact `orphanedJobId`, `acknowledgeUnknownEffect: true`, and a printable `reason` of up to 500 characters after inspecting the CA and host. An authenticated operator with `certops.issuer.manage` receives a new continuation, or the existing active recovery. The endpoint refuses a different job, a job without its reconciliation flag, a live unrelated attempt, terminal enrollment revival and changes to the frozen issuer, agent, key, names or target. Workspace pause and approval policy apply; internal worker identities cannot make this decision.

The agent's authoritative local journal determines which step can resume. A prepared CSR can make its first submit after current safety checks; a submitted or uncertain request cannot be submitted again. A missing journal refuses recovery without deleting or generating a key. The original orphaned job keeps its historical unknown-effect flag; recovery is audited as `certops.enrollment.recovery_requested`, and the new continuation must prove the actual outcome. A legitimately reclaimed original renew job can also resume its own durable journal only while its job, attempt, snapshot and container identity still match. A different job must use a signed continuation, and failed installations require the explicit retry below.

An explicit `install_failed` result waits for an operator decision. After correcting the IIS or certificate-store problem, an operator with `certops.issuer.manage` can send an empty JSON object to `POST /api/v1/workspaces/:id/certops/enrollments/:enrollmentId/retry-installation`. The endpoint returns `201` with the new `jobId`, or `200` with the existing active retry. It accepts only failed installations and cannot change the enrollment's agent, CA, template, key, DNS names or target. The retry is audited as `certops.enrollment.installation_retry_requested`, respects workspace pause and approval policy, and reuses the issued certificate and protected key. It does not acknowledge an unsafe key deletion or recreate a missing issued key.

## CA key change

Enrollment accepts only the CA certificate you pinned. A CA renewal that keeps the same key needs no action. A renewal that uses a new key fails the enrollment with `ADCS_CA_KEY_CHANGED`. The issuer shows that the CA key changed.

Open that issuer under **AD CS issuers**, pick an agent that can reach the CA, choose **Run check**, and **Use this certificate** on the new certificate. The CA config and template stay the same. A different pair is a new issuer. New profiles cannot select the issuer until the new certificate is pinned.

## Revocation

The agent checks the issued certificate before it installs anything. That check runs as the agent service account, which is the computer account. The member must be able to reach the CA's CRL or OCSP as that account. An interactive sign-in on the same host can fail to read an LDAP CRL even when the agent can. If revocation is unreachable from the agent, validation waits and the certificate stays uninstalled. The enrollment shows **Validation deferred**. If revocation is still unreachable after 24 hours, validation expires, the certificate is not installed, and the key is removed.

## Troubleshooting

These are the error codes the product returns. Each one names the operator action.

| Code | What to do |
|---|---|
| `issuer_not_allowlisted` | Add an enrollment rule for this exact CA config and template, restart `TokenTimerAgent`, and run the check again. The agent does not contact the CA until that rule exists. |
| `ADCS_TEMPLATE_UNSAFE` | Use the template common name. The template must be schema version 2 or later, schema version 3 or later for EC, and Server Authentication only. Publish it on that CA. |
| `ADCS_CA_CONFIG_UNSAFE` | Clear `EDITF_ATTRIBUTESUBJECTALTNAME2` and set `IF_ENFORCEENCRYPTICERTREQUEST` (`0x200`). Run the check again. |
| `ADCS_CA_KEY_UNPINNED` | Run the CA check on the agent that will enroll, then pin a CA certificate. The check stores that certificate and the template OID on the agent. A check on a different agent does not prepare this one. |
| `ADCS_CA_UNREACHABLE` | Open TCP 135 and the CA's dynamic RPC range from the agent to the CA. The same request is retried. The 14-day limit has not started. |
| `ADCS_DISPOSITION_UNKNOWN` | The enrollment is **Submission uncertain**. Reconcile with the CA's RequestId, or abandon it and free the key. Do not submit it again. |
| `ADCS_CERTIFICATE_INVALID` | The CA returned a certificate that failed the name, Server Authentication, template, or chain check. Nothing was installed. Correct the template or the profile names, then start a new enrollment. |
| `ADCS_CA_KEY_CHANGED` | Run the check on the issuer and pin the new CA certificate. A renewal that keeps the same key needs no action. |

A denied request can also carry a CA result. Console text is localized and is not used.

| HRESULT | When | What to do |
|---|---|---|
| `0x80094014` `CERTSRV_E_ADMIN_DENIED_REQUEST` | submit or retrieve | A CA manager denied the request. |
| `0x80094012` `CERTSRV_E_TEMPLATE_DENIED` | submit | Grant Enroll on the template to the computer account, or to a group that contains it. |
| `0x80094800` `CERTSRV_E_UNSUPPORTED_CERT_TYPE` | submit | Publish the template on that CA, and use the template common name. |
| `0x80094811` `CERTSRV_E_KEY_LENGTH` | submit | Choose a key the template allows. |
| `0x80094003` `CERTSRV_E_BAD_REQUESTSTATUS` | submit | Choose the key algorithm the template allows. |
| `0x80070005` `E_ACCESSDENIED` | retrieve | That RequestId belongs to another requester. |
| `0x80094004` `CERTSRV_E_PROPERTY_EMPTY` | retrieve | The CA has no such RequestId. |
| `0x800706BA` `RPC_S_SERVER_UNAVAILABLE` | submit, no response file | The CA never received the request. The same request is retried. |
| `0x800706BF` `RPC_S_CALL_FAILED_DNE` | submit, no response file | Same as unreachable: nothing was submitted. |

Any other result after submit has started is uncertain. Do not resubmit it.

## Signed response validation

The CMC helper verifies the CA signature and pinned public key before trusting
response facts. Pending RequestIds must be nonzero unsigned 32-bit values;
the maximum value remains supported. Status fields require a nonempty list of
valid body identifiers, valid UTF-8 description text, exactly one optional
choice, and a valid GeneralizedTime pending timestamp. Malformed fields and
trailing data fail closed. The field layout follows the existing
[RFC5272 CMC status and pending structures](https://www.rfc-editor.org/rfc/rfc5272#section-6.1.2).

Thirty-three focused native Go checks on Windows passed the genuine signed issued, pending,
and denied fixture controls, tampering and truncation refusals, malformed field
checks, and English/French/German description parsing. Localized descriptions
are synthetic structured-content cases; they do not replace responses from
qualified localized AD CS hosts. The mandatory Windows Go suite includes these
tests. This helper decodes responses and does not implement signed CMC renewal
requests.

## Related

[Current state index](../CURRENT_STATE.md) · [Install on Windows](install-windows.md) · [DNS and ACME](dns-and-acme.md) · [Windows runtime](windows-runtime.md) · [Certificate details](../certificate-details.md) · [ADR-0014](../../adr/0014-certops-adcs-issuer-and-async-enrollment.md)

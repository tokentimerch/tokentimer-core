# Supporting response-delivery file barriers

This fixture establishes native Windows file mechanics using owned temporary
reader/writer processes. It does not execute `certreq`, an agent, a Windows
service, CNG operations, certificate enrollment or an AD CS lab. There is no
mandatory qualification suite or release-matrix slot for this supporting proof.

Run the explicit supporting control on Windows:

```powershell
$env:CERTOPS_RESPONSE_BARRIER_SUPPORT = '1'
node scripts/certops-response-barrier-support.js
```

The source requires no product credentials or network connection. Three separate
owned cases attempt the first write to `issued.cer`, `chain.p7b` and
`submit-response.rsp`. These are zero-length supporting placeholders, never
invented CA response material or files passed to a product decoder.

The existing selected Windows job in `certops-qualification.yml` runs these
supporting controls on its Windows Server 2022 and 2025 images. Changes to the
driver, worker, controller or pure-test source select the Windows lane on trusted
`main` pushes; documentation-only changes retain cheap tooling selection. Manual
`windows` or `all` selection also runs the controls. A missing native primitive
or failed observation fails the step. This adds no AD CS qualification slot and
does not turn the supporting JSON into a native enrollment report.

## Actual observations

Each case grants a real acknowledged level-1 file oplock on a public temporary
input and on all three outputs. The external driver registers its exact child
PID, creation time, executable, script digest and parent identity before
authorizing access. It must then observe the actual synchronous input read
breaking the input oplock. All three output barriers are already armed before
that input operation is acknowledged.

After the child actually reads and hashes the input, its selected synchronous
output open must break that output oplock. All output identities and lengths must
remain unchanged and zero. The driver terminates only its retained exact child
process handle, proves process exit and PID absence, checks the input and immutable
guard identities/hashes, and only then releases output holders. Every output must
still be empty afterward.

The public supporting result contains twelve boolean observations for each of the
three output positions. `nativeAdcsQualified` and `sourceAcquisitionRaceQualified`
are always false. The explicit Windows temporary-file execution has observed all
36 flags; this is local supporting execution, not a real-host AD CS qualification.

## Cleanup contract

Private immutable `.active-guard.json`, `.registered-worker.json` and
`.drained.json` receipts bind the exact owned root, files, identities and process
lifetimes. They are not uploaded. The caller independently checks native file
identity, source hashes, zero output lengths, marker identity and actual holder
and writer PID absence before removing the temporary root.

A missing break, unknown reader identity, changed file/receipt, live child or
incomplete drain fails the proof and preserves the root. Timeout requests
cancellation through the owned protocol; the caller never kills a holder to force
cleanup. The holder retains its output oplocks until exact child termination is
proved. Passing evidence requires graceful holder completion and exact drain
receipts; a forced holder exit produces no passing proof.

## Remaining real-response work

Microsoft documents that [level-1 oplocks require an acknowledgment before an
incompatible operation proceeds](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock_level_1).
Directory child-enumeration changes are [advisory notifications that do not wait
for acknowledgment](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock).
Directory watching therefore cannot substitute for a blocking input or output
barrier.

The supporting input exists before the child starts. Production AD CS creates a
fresh invocation directory and writes its CSR immediately before launching the
real client. Reliably acquiring that actual input barrier remains unimplemented;
missing it must fail, rather than qualify a timing-based polling experiment.
Further work must independently bind the actual client/service identity and
CA-issued requester, CSR SPKI, RequestId and public leaf while response delivery
is blocked. Supporting placeholders must be removed only after the genuine
producer and client are both stopped, before production recovery can inspect
response paths. Journals, dates, CA responses and helper outcomes cannot be
substituted.

An intentionally operator-created second same-CSR CA request remains a separate
ambiguity control even when the first actual response loss is eventually proved.
The current experimental response-loss workflow remains nonqualified.

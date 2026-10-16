# Native Microsoft OCSP responder and endpoint availability

This source fixture belongs to the explicit disposable domain AD CS workflows,
for both the original issuing CA and the hierarchy's enterprise subordinate.
It adds no Azure VM or permanently running service. Routine `standard-hosted`
qualification remains Azure-free. Native execution is pending; supporting tests
and successful source validation are not OCSP qualification.

The existing CA VM must initially have no Online Responder, IIS or WAS role,
no responder configuration, no HTTP listener on port 80 and no existing private
fixture directory contents. An actual enterprise administrator context is
required for the directory template. A fixed original-CA mutex and an immutable,
private, native-file-identity receipt precede mutation. Existing installations,
objects or permissions are refused rather than adopted or repaired.

The fixture installs Microsoft's Online Responder on that existing CA. It creates
one owned OCSP-only signing template and a nonexportable machine RSA key, submits
one actual officer request and independently identifies its issued CA row. Node
crypto's OpenSSL-backed library verifies the exact delegated certificate's CA
signature, CA-key pin, current validity, signing-only key usage, OCSP-only EKU,
owned template OID and noncritical no-check extension before acceptance. No
OpenSSL CLI execution is claimed. Only the actual observed responder service
account receives a temporary read grant on that exact key.

Four mandatory cases require:

- `adcs-real-native-ocsp-delegated-signer`: the original CA, new role/template,
  actual issued signer request, native private-key association and native COM
  configuration are cross-bound before use.
- `adcs-real-ocsp-deferred-same-leaf-signed-continuation`: the exact native
  helper is blocked before the first public renewal. Its actual failed signed
  result must leave a durable `validation_deferred` public leaf and generated,
  unaccepted protected CNG key. An independent native signature binds that key
  to the issued leaf; a complete native certificate-store reference scan and
  unchanged outgoing custody, binding and trusted TLS prove no premature
  installation. After the owned rule is removed, one distinct signed
  continuation must install the identical CSR/key/leaf and native RequestId
  without another CA request. Both actual result nonces, distinct claims and
  final current-claim verification evidence are independently read. Only poll
  eligibility uses the supported scheduler `now` input; native clocks and the
  validation deadline remain unchanged. This does not qualify background timing.
- `adcs-real-ocsp-only-leaf-native-endpoint-recovery`: a real public renewal
  installs a fresh My-store CNG/IIS leaf containing the exact OCSP URL and no
  CRL fallback. Original CA publication is restored before fault injection.
  Nonce-free requests obtain actual signed good responses from Microsoft IIS;
  exact DER signatures and certificate/issuer identity are checked independently.
  The shipped CryptoAPI helper must return `valid`, `revocation_unknown`,
  `valid` while an exact helper-program outbound rule blocks only the original
  CA address on TCP 80. Node's independently reachable signed responses remain
  good during the helper-specific block. Installed custody, HTTP.sys settings,
  native IIS binding and trusted SNI TLS must remain unchanged.
- `adcs-real-ocsp-original-publication-renewal-and-drain`: a second real public
  renewal under the restored publication installs another fresh leaf/key, with
  current-claim evidence and an independent CA RequestId. Only then are the
  exact responder configuration, template/OID and signer certificate/key
  removed. Original key permissions are restored before public-entry removal;
  a complete native all-store survivor scan must authorize exact key deletion.
  Original responder and IIS worker handles must exit through ordinary service
  stops, followed by fresh stopped/disabled/service, process and HTTP-port checks.

The three CA request increments are real: one officer signer request and two
machine renewal requests. An independent native RequestId is always mandatory.
The immediate-issued protocol may omit its API/journal RequestId; any reported
ID must equal the independently observed CA value. No API field is fabricated.

Every member broker process is contained before execution in the reviewed native
Job wrapper, and each CA operation uses a fresh WinRM session. Credentials remain
in private inherited environment/in-memory credentials, never command arguments,
artifacts or public receipts. Candidate modules, the exact shipped helper and
private exchanges are bounded and hash-bound. The native directory handle denies
namespace replacement across private writes. Local Job drainage does not prove
that a disconnected remote operation stopped: once dispatched, an uncertain
completion prevents every subsequent remote action, including restore retries.
The whole owned lab is preserved for mandatory workflow teardown in that case.

Cleanup is deliberately conservative. Active owned resources and private signing
key are removed or stopped and independently drained. Newly installed inert
feature packages remain for verified destruction of the disposable lab; the
fixture does not claim pristine role-package restoration. Guard disappearance,
foreign ACL/object changes, unknown key references, uncertain WinRM completion
or failed cleanup preserve native and durable ownership and fail qualification.
Private broker exchanges, directory ACLs, key/container identities and credentials
must never be uploaded as artifacts.

This bounded fixture does **not** qualify an authoritative revoked/unknown OCSP
status, signed CMC renewal, alternate responder signing algorithms or every
OCSP extension. Those scope promotions are explicitly false in the closed proof.
The existing domain workflow's execution timeout and mandatory owned-resource
cleanup remain in force; role installation adds work only to this explicitly
selected paid lab and no elapsed-time qualification is inferred.

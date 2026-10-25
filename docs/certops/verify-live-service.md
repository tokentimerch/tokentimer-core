# Verify the certificate in use

Record a baseline, perform the operation, then make a new client connection using either client example below. Job success, an installed file, a machine-store entry and a live TLS response are separate evidence.

## Linux client: check the actual listener

Substitute a concrete listener address and the DNS name clients use:

```bash
openssl s_client -connect 192.0.2.10:443 \
  -servername www.example.com -verify_hostname www.example.com \
  -verify_return_error -CAfile /path/to/trusted-issuer-ca.pem \
  </dev/null > served.pem &&
openssl x509 -in served.pem -noout -serial -dates -fingerprint -sha256
```

Require successful chain and hostname validation. Obtain the CA file from a trusted source, not an unverified listener. Public-CA checks may use the client's normal system trust. Compare the returned identity/validity with the new certificate and with the pre-renewal baseline. For distribution, probe every consumer's concrete address separately; two load-balancer requests do not prove two consumers.

## Windows and IIS

Inspect **Certificates (Local Computer) → Personal → Certificates**, then **IIS Manager → site → Bindings → HTTPS → Edit → View**. Match the selected certificate and private-key association with the replacement. Do not make a second manual binding change merely to inspect it.

For a Windows client, connect to the concrete listener address and authenticate the hostname clients use. Default chain/hostname validation stays enabled:

```powershell
$tcp = [System.Net.Sockets.TcpClient]::new('192.0.2.10', 443)
$tls = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false)
try {
  $tls.AuthenticateAsClient('www.example.com')
  $served = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $tls.RemoteCertificate
  )
  $served | Format-List Thumbprint, SerialNumber, NotBefore, NotAfter
} finally {
  $tls.Dispose()
  $tcp.Dispose()
}
```

Compare that fresh result with the IIS-bound replacement, not an older stored copy.

IIS renewal uses **IIS rebinding**, not a blanket `iisreset`. A retained Personal-store copy may be an older leaf. Use an exact thumbprint/serial rather than a subject name; SAN-only certificates may have no Subject CN. A fresh TLS probe must return the same replacement identity. Windows `Thumbprint` uses SHA-1, while the OpenSSL command uses SHA-256: compare matching algorithms.

## Verify a trust-store installation

On Ubuntu/Debian, test the actual system bundle before installation, after it and after controlled removal:

```bash
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt approved-root.pem
```

This is different from trusting the supplied root against itself with `-CAfile approved-root.pem`. Applications with private trust stores may differ. On Windows, inspect **Local Computer → Trusted Root Certification Authorities** for a root or **Intermediate Certification Authorities** for an intermediate; match the approved fingerprint and chain result. Personal holds a server certificate/private key and is a different store. Workspace retirement does not remove OS installations.

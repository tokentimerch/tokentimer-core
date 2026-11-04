//go:build windows

package verifiedextraction

import (
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestVerifyCMSRejectsUntrustedInputs(t *testing.T) {
	pin := strings.Repeat("a", 64)
	if _, err := VerifyCMS(nil, pin); err == nil {
		t.Fatal("accepted empty CMS")
	}
	if _, err := VerifyCMS([]byte("not CMS"), pin); err == nil {
		t.Fatal("accepted malformed CMS")
	}
	if _, err := VerifyCMS([]byte("x"), ""); err == nil {
		t.Fatal("accepted missing publisher pin")
	}
}

func TestVerifyCMSRejectsValidSignatureFromUntrustedRoot(t *testing.T) {
	// The key lives only in the child process; no certificate is added to a store.
	fixture := `
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$rsa=[Security.Cryptography.RSA]::Create(2048)
$req=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=untrusted fixture',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
$oids=[Security.Cryptography.OidCollection]::new();$oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')) | Out-Null
$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false))
$cert=$req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1),[DateTimeOffset]::Now.AddDays(1))
$content=[Security.Cryptography.Pkcs.ContentInfo]::new([Text.Encoding]::UTF8.GetBytes('{}'))
$cms=[Security.Cryptography.Pkcs.SignedCms]::new($content,$false)
$signer=[Security.Cryptography.Pkcs.CmsSigner]::new($cert)
$signer.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
$cms.ComputeSignature($signer);$cms.CheckSignature($true)
$sha=[Security.Cryptography.SHA256]::Create()
$pin=([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant()
@{cms=[Convert]::ToBase64String($cms.Encode());pin=$pin} | ConvertTo-Json -Compress
`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fixture).Output()
	if err != nil {
		t.Fatalf("create cryptographically valid fixture: %v", err)
	}
	var data struct {
		CMS string `json:"cms"`
		Pin string `json:"pin"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		t.Fatal(err)
	}
	encoded, err := base64.StdEncoding.DecodeString(data.CMS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCMS(encoded, data.Pin); err == nil {
		t.Fatal("untrusted root accepted")
	}
	if _, err := VerifyCMS(encoded, strings.Repeat("a", 64)); err == nil {
		t.Fatal("wrong publisher accepted")
	}
}

//go:build windows

package verifiedextraction

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNativeCMSRejectsUntrustedWrongPinAndTampering(t *testing.T) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	// Ephemeral in-memory fixture: no key or certificate is installed in a store.
	script := `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security
$rsa=[Security.Cryptography.RSA]::Create(2048)
$req=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=CMS fixture',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
$oids=[Security.Cryptography.OidCollection]::new(); $oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')) | Out-Null
$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false))
$cert=$req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1),[DateTimeOffset]::Now.AddDays(1))
$content=[Security.Cryptography.Pkcs.ContentInfo]::new([Text.Encoding]::UTF8.GetBytes('fixture-manifest-content'))
$cms=[Security.Cryptography.Pkcs.SignedCms]::new($content,$false)
$signer=[Security.Cryptography.Pkcs.CmsSigner]::new($cert); $signer.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
$cms.ComputeSignature($signer)
$detached=[Security.Cryptography.Pkcs.SignedCms]::new($content,$true); $detached.ComputeSignature($signer)
$multiple=[Security.Cryptography.Pkcs.SignedCms]::new($content,$false); $multiple.ComputeSignature($signer); $multiple.ComputeSignature($signer)
$weak=[Security.Cryptography.Pkcs.SignedCms]::new($content,$false); $weakSigner=[Security.Cryptography.Pkcs.CmsSigner]::new($cert); $weakSigner.DigestAlgorithm=[Security.Cryptography.Oid]::new('1.3.14.3.2.26'); $weak.ComputeSignature($weakSigner)
$sha=[Security.Cryptography.SHA256]::Create(); $pin=([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant()
@{cms=[Convert]::ToBase64String($cms.Encode());detached=[Convert]::ToBase64String($detached.Encode());multiple=[Convert]::ToBase64String($multiple.Encode());weak=[Convert]::ToBase64String($weak.Encode());pin=$pin}|ConvertTo-Json -Compress`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "PSModulePath="+filepath.Join(sys, "WindowsPowerShell", "v1.0", "Modules"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture generation: %v %s", err, out)
	}
	var fixture struct{ CMS, Detached, Multiple, Weak, Pin string }
	if err := json.Unmarshal(out, &fixture); err != nil {
		t.Fatal(err)
	}
	cms, err := base64.StdEncoding.DecodeString(fixture.CMS)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmsShape(cms); err != nil {
		t.Fatalf("valid DER fixture refused: %v", err)
	}
	for _, encoded := range []string{fixture.Detached, fixture.Multiple, fixture.Weak} {
		bad, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nativeCMSPrototype(bad, fixture.Pin); err == nil {
			t.Fatal("detached, multi-signer or weak-digest CMS accepted")
		}
	}
	if _, err := nativeCMSPrototype(cms, fixture.Pin); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("untrusted fixture must reach chain and fail: %v", err)
	}
	if _, err := nativeCMSPrototype(cms, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "publisher mismatch") {
		t.Fatalf("wrong pin must fail: %v", err)
	}
	index := bytes.Index(cms, []byte("fixture-manifest-content"))
	if index < 0 {
		t.Fatal("encapsulated fixture content absent")
	}
	cms[index] ^= 1
	if _, err := nativeCMSPrototype(cms, fixture.Pin); err == nil {
		t.Fatal("tampered CMS accepted")
	}
}

// This test temporarily changes LocalMachine ROOT. It is opt-in,
// requires LocalSystem, and must run only on a disposable VM. It does not prove
// CRL/OCSP behavior of a subordinate certificate chain.
func TestNativeCMSTrustedEphemeralRoot(t *testing.T) {
	if os.Getenv("TT_REQUIRE_CMS_TRUST_FIXTURE") != "1" {
		t.Skip("requires disposable SYSTEM VM")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid.String() != "S-1-5-18" {
		t.Fatal("LocalSystem required on disposable VM")
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	script := `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security
$rsa=[Security.Cryptography.RSA]::Create(2048)
$req=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Disposable Native CMS Root',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature),$true))
$oids=[Security.Cryptography.OidCollection]::new(); $oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')) | Out-Null
$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false))
$cert=$req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1),[DateTimeOffset]::Now.AddDays(1))
$content=[Security.Cryptography.Pkcs.ContentInfo]::new([Text.Encoding]::UTF8.GetBytes('trusted-fixture-content'))
$cms=[Security.Cryptography.Pkcs.SignedCms]::new($content,$false)
$signer=[Security.Cryptography.Pkcs.CmsSigner]::new($cert); $signer.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1'); $cms.ComputeSignature($signer)
$sha=[Security.Cryptography.SHA256]::Create(); $pin=([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant()
@{cms=[Convert]::ToBase64String($cms.Encode());cert=[Convert]::ToBase64String($cert.RawData);pin=$pin}|ConvertTo-Json -Compress`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "PSModulePath="+filepath.Join(sys, "WindowsPowerShell", "v1.0", "Modules"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture generation: %v %s", err, out)
	}
	var fixture struct{ CMS, Cert, Pin string }
	if err := json.Unmarshal(out, &fixture); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(fixture.Cert)
	if err != nil || len(der) == 0 {
		t.Fatal("fixture certificate invalid")
	}
	cms, err := base64.StdEncoding.DecodeString(fixture.CMS)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString("ROOT")
	const certStoreProvSystemW = 10
	const certSystemStoreLocalMachine = 0x00020000
	store, err := windows.CertOpenStore(certStoreProvSystemW, 0, 0, certSystemStoreLocalMachine, uintptr(unsafe.Pointer(name)))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertCloseStore(store, 0)
	cert, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &der[0], uint32(len(der)))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertFreeCertificateContext(cert)
	var added *windows.CertContext
	if err := windows.CertAddCertificateContextToStore(store, cert, 1, &added); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := windows.CertDeleteCertificateFromStore(added); err != nil {
			t.Errorf("remove disposable fixture root: %v", err)
		}
	}()
	content, err := nativeCMSPrototype(cms, fixture.Pin)
	if err != nil {
		t.Fatalf("trusted fixture rejected: %v", err)
	}
	if string(content) != "trusted-fixture-content" {
		t.Fatal("unexpected authenticated content")
	}
}

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

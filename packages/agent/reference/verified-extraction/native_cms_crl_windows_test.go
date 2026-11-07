//go:build windows

package verifiedextraction

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// VM-only: temporarily installs a unique root and its signed CRL, then
// removes the exact contexts. The lab must be destroyed if interrupted.
func TestNativeCMSRevocationCache(t *testing.T) {
	if os.Getenv("TT_REQUIRE_CMS_CRL_FIXTURE") != "1" {
		t.Skip("requires disposable SYSTEM VM")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid.String() != "S-1-5-18" {
		t.Fatal("LocalSystem required on disposable VM")
	}
	now := time.Now().UTC()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(70001), Subject: pkix.Name{CommonName: "Disposable CMS CRL Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 7, 8, 12, 23, 29, 34, 48, 55, 67, 72, 83, 94, 102, 111, 120, 133, 144, 155, 166}}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(80001), Subject: pkix.Name{CommonName: "Disposable CMS CRL Signer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, CRLDistributionPoints: []string{"http://127.0.0.1/disposable-crl-fixture.crl"}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey.Precompute()
	pad := func(n *big.Int, size int) string {
		return base64.StdEncoding.EncodeToString(n.FillBytes(make([]byte, size)))
	}
	request := map[string]string{"cert": base64.StdEncoding.EncodeToString(leafDER), "Modulus": pad(leafKey.N, 256), "Exponent": base64.StdEncoding.EncodeToString(big.NewInt(int64(leafKey.E)).Bytes()), "D": pad(leafKey.D, 256), "P": pad(leafKey.Primes[0], 128), "Q": pad(leafKey.Primes[1], 128), "DP": pad(leafKey.Precomputed.Dp, 128), "DQ": pad(leafKey.Precomputed.Dq, 128), "InverseQ": pad(leafKey.Precomputed.Qinv, 128)}
	input, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	script := `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security
$r=[Console]::In.ReadToEnd()|ConvertFrom-Json
$p=New-Object Security.Cryptography.RSAParameters
foreach($n in @('Modulus','Exponent','D','P','Q','DP','DQ','InverseQ')) {$p.$n=[Convert]::FromBase64String($r.$n)}
$rsa=[Security.Cryptography.RSA]::Create();$rsa.ImportParameters($p)
$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($r.cert))
$leaf=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($cert,$rsa)
$content=[Security.Cryptography.Pkcs.ContentInfo]::new([Text.Encoding]::UTF8.GetBytes('crl-fixture-content'))
$cms=[Security.Cryptography.Pkcs.SignedCms]::new($content,$false);$s=[Security.Cryptography.Pkcs.CmsSigner]::new($leaf)
$s.IncludeOption=[Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly;$s.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1');$cms.ComputeSignature($s)
[Console]::Out.Write([Convert]::ToBase64String($cms.Encode()))`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "PSModulePath="+filepath.Join(sys, "WindowsPowerShell", "v1.0", "Modules"))
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("in-memory CMS signing failed: %v", err)
	}
	cms, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal("invalid generated CMS")
	}
	pinRaw := sha256.Sum256(leafDER)
	pin := hex.EncodeToString(pinRaw[:])
	open := func(n string) windows.Handle {
		name, _ := windows.UTF16PtrFromString(n)
		h, e := windows.CertOpenStore(10, 0, 0, 0x20000, uintptr(unsafe.Pointer(name)))
		if e != nil {
			t.Fatal(e)
		}
		return h
	}
	rootStore := open("ROOT")
	defer windows.CertCloseStore(rootStore, 0)
	caStore := open("CA")
	defer windows.CertCloseStore(caStore, 0)
	cert, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &rootDER[0], uint32(len(rootDER)))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertFreeCertificateContext(cert)
	var added *windows.CertContext
	if err := windows.CertAddCertificateContextToStore(rootStore, cert, 1, &added); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := windows.CertDeleteCertificateFromStore(added); err != nil {
			t.Errorf("fixture root cleanup: %v", err)
		}
	}()
	makeCRL := func(revoked bool) []byte {
		tpl := &x509.RevocationList{Number: big.NewInt(100), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
		if revoked {
			tpl.Number = big.NewInt(101)
			tpl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: now.Add(-time.Minute)}}
		}
		b, e := x509.CreateRevocationList(rand.Reader, tpl, root, rootKey)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	dll := windows.NewLazySystemDLL("crypt32.dll")
	addCRL := dll.NewProc("CertAddEncodedCRLToStore")
	delCRL := dll.NewProc("CertDeleteCRLFromStore")
	add := func(data []byte) uintptr {
		var ctx uintptr
		ok, _, e := addCRL.Call(uintptr(caStore), uintptr(windows.X509_ASN_ENCODING), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 1, uintptr(unsafe.Pointer(&ctx)))
		if ok == 0 || ctx == 0 {
			t.Fatalf("add fixture CRL: %v", e)
		}
		return ctx
	}
	remove := func(ctx uintptr) {
		ok, _, e := delCRL.Call(ctx)
		if ok == 0 {
			t.Errorf("remove fixture CRL: %v", e)
		}
	}
	// A revoked leaf must never be accepted; inspection of error status shows
	// whether the CRL was actually consumed instead of merely being absent.
	crl := add(makeCRL(true))
	defer remove(crl)
	_, err = nativeCMSPrototype(cms, pin)
	if err == nil || !strings.Contains(err.Error(), "0x00000004") {
		t.Fatalf("revoked leaf was not identified using cached CRL: %v", err)
	}
}

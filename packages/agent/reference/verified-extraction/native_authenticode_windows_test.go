//go:build windows

package verifiedextraction

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNativeCertificatePinMatching(t *testing.T) {
	data := []byte("fixture DER bytes")
	sum := sha256.Sum256(data)
	if !nativeCertificateMatchesPin(data, hex.EncodeToString(sum[:])) {
		t.Fatal("exact certificate hash rejected")
	}
	if nativeCertificateMatchesPin(data, strings.Repeat("0", 64)) || nativeCertificateMatchesPin(nil, hex.EncodeToString(sum[:])) {
		t.Fatal("untrusted certificate pin accepted")
	}
}

func TestNativeRFC3161AttributePolicy(t *testing.T) {
	sha, _ := windows.BytePtrFromString("2.16.840.1.101.3.4.2.1")
	rfc, _ := windows.BytePtrFromString("1.3.6.1.4.1.311.3.3.1")
	legacy, _ := windows.BytePtrFromString("1.2.840.113549.1.9.6")
	data := byte(1)
	blob := windows.CryptAttrBlob{Size: 1, Data: &data}
	attr := nativeCryptAttribute{OID: rfc, ValueCount: 1, Values: &blob}
	info := nativeCMSSignerInfo{HashAlgorithm: windows.CryptAlgorithmIdentifier{ObjId: sha}, Unauthenticated: nativeCryptAttributes{Count: 1, Attributes: &attr}}
	if !hasSingleRFC3161Timestamp(&info) {
		t.Fatal("RFC3161 marker rejected")
	}
	attr.OID = legacy
	if hasSingleRFC3161Timestamp(&info) {
		t.Fatal("legacy timestamp accepted")
	}
	attr.OID = rfc
	attr.ValueCount = 0
	if hasSingleRFC3161Timestamp(&info) {
		t.Fatal("empty timestamp accepted")
	}
	attrs := []nativeCryptAttribute{{OID: rfc, ValueCount: 1, Values: &blob}, {OID: legacy, ValueCount: 1, Values: &blob}}
	info.Unauthenticated = nativeCryptAttributes{Count: 2, Attributes: &attrs[0]}
	if hasSingleRFC3161Timestamp(&info) {
		t.Fatal("mixed legacy and RFC3161 timestamps accepted")
	}
}

func TestNativeAuthenticodePrototype(t *testing.T) {
	if os.Getenv("TT_REQUIRE_NATIVE_AUTHENTICODE_EXPERIMENT") != "1" {
		t.Skip("experimental native trust provider test")
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	file := os.Getenv("TT_NATIVE_SIGNED_FIXTURE")
	if file == "" {
		file, err = exec.LookPath("node.exe")
		if err != nil {
			t.Skip("embedded Authenticode fixture unavailable")
		}
	}
	script := `$s=Get-AuthenticodeSignature -LiteralPath $env:TT_NATIVE_FIXTURE; if ($s.Status -ne 'Valid' -or !$s.TimeStamperCertificate) { exit 2 }; $h=[Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($h.ComputeHash($s.SignerCertificate.RawData))).Replace('-','').ToLowerInvariant() } finally { $h.Dispose() }`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "TT_NATIVE_FIXTURE="+file, "PSModulePath="+filepath.Join(sys, "WindowsPowerShell", "v1.0", "Modules"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture unavailable (%s): %v %s", file, err, out)
	}
	pin := strings.TrimSpace(string(out))
	if err := nativeAuthenticodePrototype(file, pin); err != nil {
		t.Fatalf("native verification: %v", err)
	}
	bad := "0" + pin[1:]
	if bad == pin {
		bad = "1" + pin[1:]
	}
	if err := nativeAuthenticodePrototype(file, bad); err == nil {
		t.Fatal("wrong publisher accepted")
	}
	data, err := os.ReadFile(file)
	if err != nil || len(data) < 8192 {
		t.Fatalf("read signed fixture: %v", err)
	}
	data[4096] ^= 0x01
	tampered := filepath.Join(t.TempDir(), "tampered.exe")
	if err := os.WriteFile(tampered, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := nativeAuthenticodePrototype(tampered, pin); err == nil {
		t.Fatal("tampered signed executable accepted")
	}
	unsigned := filepath.Join(t.TempDir(), "unsigned.ps1")
	if err := os.WriteFile(unsigned, []byte("Write-Output unsigned"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := nativeAuthenticodePrototype(unsigned, pin); err == nil {
		t.Fatal("unsigned file accepted")
	}
}

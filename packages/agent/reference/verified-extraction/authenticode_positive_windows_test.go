//go:build windows

package verifiedextraction

import (
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This exercises Windows trust and timestamp verification, but does not prove
// that a future TokenTimer release uses the intended production publisher.
func TestAuthenticodeVerifierAcceptsTrustedSystemExecutable(t *testing.T) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(sys, "cmd.exe")
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	script := "$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath $env:TT_AUTH_PROBE; if ($s.Status -ne 'Valid' -or !$s.TimeStamperCertificate) { exit 2 }; $h=[Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($h.ComputeHash($s.SignerCertificate.RawData))).Replace('-','').ToLowerInvariant() } finally { $h.Dispose() }"
	fixture := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	fixture.Env = append(os.Environ(), "TT_AUTH_PROBE="+exe, "PSModulePath="+filepath.Join(sys, "WindowsPowerShell", "v1.0", "Modules"))
	out, err := fixture.CombinedOutput()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok && e.ExitCode() == 2 {
			t.Skip("Windows system executable is not trusted and timestamped in this environment")
		}
		t.Fatalf("inspect system-signed fixture: %v %s", err, out)
	}
	pin := strings.TrimSpace(string(out))
	request, err := json.Marshal(struct {
		Files []authenticodeFile `json:"files"`
	}{[]authenticodeFile{{Path: exe, Pin: pin}}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := runSystemPowerShell(authenticodeVerifierScript, request)
	if err != nil {
		t.Fatalf("embedded verifier rejected a Windows-trusted timestamped system executable: %v", err)
	}
	if string(verified) != "OK" {
		t.Fatalf("unexpected verifier result: %q", verified)
	}
	wrong := "0" + pin[1:]
	if wrong == pin {
		wrong = "1" + pin[1:]
	}
	request, err = json.Marshal(struct {
		Files []authenticodeFile `json:"files"`
	}{[]authenticodeFile{{Path: exe, Pin: wrong}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runSystemPowerShell(authenticodeVerifierScript, request); err == nil {
		t.Fatal("embedded verifier accepted an incorrect publisher pin")
	}
}

//go:build windows

package verifiedextraction

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

//go:embed verify-cms.ps1
var cmsVerifierScript string

// VerifyCMS checks an encapsulated CMS manifest against a publisher certificate
// pin obtained independently. Windows chain validation and cached revocation
// checks fail closed. The launcher calling this function must itself have been
// authenticated by an independent verifier before execution.
func VerifyCMS(cms []byte, publisherCertificateSHA256 string) ([]byte, error) {
	if len(cms) == 0 || len(cms) > 8<<20 || !digest.MatchString(publisherCertificateSHA256) {
		return nil, fmt.Errorf("invalid CMS input or publisher pin")
	}
	request, err := json.Marshal(struct {
		CMS string `json:"cms"`
		Pin string `json:"pin"`
	}{base64.StdEncoding.EncodeToString(cms), publisherCertificateSHA256})
	if err != nil {
		return nil, err
	}
	out, err := runSystemPowerShell(cmsVerifierScript, request)
	if err != nil {
		return nil, fmt.Errorf("publisher signature, chain or revocation validation failed: %w", err)
	}
	content, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil || len(content) == 0 || len(content) > 8<<20 {
		return nil, fmt.Errorf("invalid verified CMS content")
	}
	return content, nil
}

// runSystemPowerShell executes only script text compiled into the launcher,
// never code from the downloaded package. The OS system directory is obtained
// through Win32 rather than trusting an inherited PATH or SystemRoot.
func runSystemPowerShell(script string, request []byte) ([]byte, error) {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	getSystemDirectory := kernel.NewProc("GetSystemDirectoryW")
	buf := make([]uint16, 32768)
	n, _, _ := getSystemDirectory.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		return nil, fmt.Errorf("Windows system directory unavailable")
	}
	systemDir := syscall.UTF16ToString(buf[:n])
	root := filepath.Dir(systemDir)
	powershell := filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe")
	encoded := utf16.Encode([]rune(script))
	raw := make([]byte, 2*len(encoded))
	for i, v := range encoded {
		binary.LittleEndian.PutUint16(raw[i*2:], v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	cmd.Dir = systemDir
	cmd.Env = []string{"SystemRoot=" + root, "WINDIR=" + root, "PATH=" + systemDir, "PSModulePath=" + filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "Modules")}
	cmd.Stdin = bytes.NewReader(request)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

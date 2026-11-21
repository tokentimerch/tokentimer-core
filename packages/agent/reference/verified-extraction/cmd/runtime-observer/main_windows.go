//go:build windows

// Command runtime-observer is a narrow, experimental native observation. It
// does not execute the runtime, authenticate an inventory or qualify release.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	verified "tokentimer-verified-extraction"
)

const verifier = `$ErrorActionPreference='Stop'
try {
  $request=[Console]::In.ReadToEnd() | ConvertFrom-Json
  $sig=Get-AuthenticodeSignature -LiteralPath $request.path -ErrorAction Stop
  if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or -not $sig.TimeStamperCertificate) { throw 'Not trusted' }
  [Console]::Out.Write('OK')
} catch { [Console]::Error.Write('Runtime trust check failed.'); exit 1 }`

type staging interface {
	Root() string
	LockPayload() error
	Cleanup() error
	Close()
}

func systemPowerShell(path string) error {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	getSystemDirectory := kernel.NewProc("GetSystemDirectoryW")
	buf := make([]uint16, 32768)
	n, _, _ := getSystemDirectory.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		return errors.New("system directory unavailable")
	}
	system := syscall.UTF16ToString(buf[:n])
	root := filepath.Dir(system)
	powershell := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	units := utf16.Encode([]rune(verifier))
	raw := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], u)
	}
	req, err := json.Marshal(struct {
		Path string `json:"path"`
	}{path})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	cmd.Dir = system
	cmd.Env = []string{"SystemRoot=" + root, "WINDIR=" + root, "PATH=" + system, "PSModulePath=" + filepath.Join(system, "WindowsPowerShell", "v1.0", "Modules")}
	cmd.Stdin = bytes.NewReader(req)
	out, err := cmd.Output()
	if err != nil || string(out) != "OK" {
		return errors.New("native runtime signature verification failed")
	}
	return nil
}

type receipt struct {
	SchemaVersion         int    `json:"schemaVersion"`
	Kind                  string `json:"kind"`
	Architecture          string `json:"architecture"`
	ArchiveSHA256         string `json:"archiveSha256"`
	RuntimeSHA256         string `json:"runtimeSha256"`
	AuthenticodeStatus    string `json:"authenticodeStatus"`
	TimestampPresent      bool   `json:"timestampPresent"`
	RuntimeExecuted       bool   `json:"runtimeExecuted"`
	InstallationPerformed bool   `json:"installationPerformed"`
}

// runWithStage never produces a receipt until verification and secure cleanup
// have both succeeded. Callers cannot obtain a release authorization here.
func runWithStage(data []byte, archiveSHA, arch string, stage staging, verify func(string) error) (out receipt, err error) {
	defer stage.Close()
	defer func() {
		if cleanupErr := stage.Cleanup(); cleanupErr != nil {
			err = fmt.Errorf("protected stage cleanup failed: %w", cleanupErr)
		}
		if err != nil {
			out = receipt{}
		}
	}()
	filename := filepath.Join(stage.Root(), "node.exe")
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return receipt{}, err
	}
	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return receipt{}, writeErr
	}
	if closeErr != nil {
		return receipt{}, closeErr
	}
	if err := stage.LockPayload(); err != nil {
		return receipt{}, err
	}
	if err := verify(filename); err != nil {
		return receipt{}, err
	}
	return receipt{SchemaVersion: 1, Kind: "windows-upstream-runtime-observation", Architecture: arch, ArchiveSHA256: archiveSHA,
		RuntimeSHA256: digest(data), AuthenticodeStatus: "Valid", TimestampPresent: true, RuntimeExecuted: false, InstallationPerformed: false}, nil
}

func run(archive []byte, archiveSHA, arch string) (receipt, error) {
	pin, ok := runtimePins[arch]
	if !ok || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(archiveSHA) {
		return receipt{}, errors.New("invalid candidate identity")
	}
	data, err := runtimeFromArchive(archive, archiveSHA, arch, pin)
	if err != nil {
		return receipt{}, err
	}
	stage, err := verified.NewPrivateStaging()
	if err != nil {
		return receipt{}, fmt.Errorf("protected staging unavailable: %w", err)
	}
	return runWithStage(data, archiveSHA, arch, stage, systemPowerShell)
}

func main() {
	path := flag.String("archive", "", "candidate archive")
	hash := flag.String("archive-sha256", "", "independently trusted archive SHA-256")
	arch := flag.String("architecture", "", "amd64 or arm64")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "archive is required")
		os.Exit(1)
	}
	f, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "archive unavailable")
		os.Exit(1)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxArchive {
		_ = f.Close()
		fmt.Fprintln(os.Stderr, "invalid archive")
		os.Exit(1)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxArchive+1))
	_ = f.Close()
	if err != nil || len(data) == 0 || len(data) > maxArchive {
		fmt.Fprintln(os.Stderr, "invalid archive")
		os.Exit(1)
	}
	r, err := run(data, *hash, *arch)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		os.Exit(1)
	}
}

//go:build windows

package verifiedextraction

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIndependentIdentityRuntimeOnNativeNTFS(t *testing.T) {
	node, err := exec.LookPath("node.exe")
	if err != nil {
		t.Skip("Node runtime unavailable")
	}
	versionBytes, err := exec.Command(node, "-p", "process.versions.node").Output()
	if err != nil {
		t.Fatal(err)
	}
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	root := filepath.Dir(filepath.Dir(f.journal))
	app := filepath.Join(root, "app")
	previous := app + ".previous.321"
	runtimeDir := filepath.Join(app, "runtime")
	archDir := filepath.Join(runtimeDir, runtime.GOARCH)
	for _, dir := range []string{app, previous, runtimeDir, archDir} {
		if err := createRestrictedDirectory(dir, f.sddl); err != nil {
			t.Fatal(err)
		}
	}
	source, err := os.Open(node)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.Create(filepath.Join(archDir, "node.exe"))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err = io.Copy(io.MultiWriter(target, hash), source); err != nil {
		t.Fatal(err)
	}
	if err = target.Close(); err != nil {
		t.Fatal(err)
	}
	pin := identityContract{Scheme: "node-fs-win32-v1", NodeVersion: strings.TrimSpace(string(versionBytes)), Architecture: runtime.GOARCH, NodeSHA256: hex.EncodeToString(hash.Sum(nil))}
	t.Setenv("NODE_OPTIONS", "--require=not-an-existing-package")
	t.Setenv("NODE_PATH", "not-an-existing-path")
	if err := verifyIdentityRuntime(app, previous, pin, f.parentPolicy); err != nil {
		t.Fatal(err)
	}
	// A byte change after the trusted pin was established must be rejected.
	file, err := os.OpenFile(filepath.Join(archDir, "node.exe"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte{0}, 0); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyIdentityRuntime(app, previous, pin, f.parentPolicy); err == nil {
		t.Fatal("substituted runtime accepted")
	}
	pin.NodeSHA256 = strings.Repeat("a", 64)
	if err := verifyIdentityRuntime(app, previous, pin, f.parentPolicy); err == nil {
		t.Fatal("untrusted runtime pin accepted")
	}
}

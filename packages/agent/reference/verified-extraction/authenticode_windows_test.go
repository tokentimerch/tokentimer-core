//go:build windows

package verifiedextraction

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthenticodeRejectsUnsignedPayload(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"scripts/install-agent.ps1", "runtime/amd64/node.exe"} {
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("unsigned"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	entries := []Entry{{Path: "package/scripts/install-agent.ps1"}, {Path: "package/runtime/amd64/node.exe"}}
	if err := verifyAuthenticode(root, entries, "amd64", strings.Repeat("a", 64), strings.Repeat("b", 64)); err == nil {
		t.Fatal("unsigned payload accepted")
	}
}
func TestAuthenticodeRejectsMismatchedRuntimeArchitecture(t *testing.T) {
	entries := []Entry{{Path: "package/scripts/install-agent.ps1"}, {Path: "package/runtime/arm64/node.exe"}}
	err := verifyAuthenticode(t.TempDir(), entries, "amd64", strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err == nil || !strings.Contains(err.Error(), "architecture") {
		t.Fatalf("wrong architecture not rejected first: %v", err)
	}
}

func TestAuthenticodeRejectsUnsupportedBatchScript(t *testing.T) {
	entries := []Entry{{Path: "package/scripts/install-agent.ps1"}, {Path: "package/runtime/amd64/node.exe"}, {Path: "package/scripts/unsafe.cmd"}}
	err := verifyAuthenticode(t.TempDir(), entries, "amd64", strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err == nil || !strings.Contains(err.Error(), "unsupported Windows executable") {
		t.Fatalf("batch script was not rejected: %v", err)
	}
}
func TestPrepareCandidateRefusesUnauthenticatedManifest(t *testing.T) {
	candidate := Candidate{CMS: []byte("not CMS"), PublisherPin: strings.Repeat("a", 64)}
	if _, err := PrepareCandidate(candidate); err == nil {
		t.Fatal("unauthenticated candidate accepted")
	}
}

func TestPreparedInstallerPathRequiresHeldPayloadLocks(t *testing.T) {
	p := &Prepared{staging: &PrivateStaging{}}
	if _, err := p.InstallerPath(); err == nil {
		t.Fatal("unlocked payload path exposed")
	}
	p.Close()
	if _, err := p.InstallerPath(); err == nil {
		t.Fatal("closed payload path exposed")
	}
}

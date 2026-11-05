//go:build windows

package verifiedextraction

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"tokentimer-verified-extraction/bootstraplock"
)

func TestLockedInstalledInventoryRejectsChanges(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	root := filepath.Dir(filepath.Dir(f.journal))
	app := filepath.Join(root, "app")
	bin := filepath.Join(app, "bin")
	for _, dir := range []string{app, bin} {
		if err := createRestrictedDirectory(dir, f.sddl); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(bin, "agent.js")
	content := []byte("verified content")
	if err := os.WriteFile(file, content, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	manifest := Manifest{Files: []Entry{{Path: "package/bin/agent.js", Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}}}
	locks, err := lockVerifiedInstalledApp(app, manifest, f.parentPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("changed"), 0600); err == nil {
		t.Error("locked file changed")
	}
	if err := os.Rename(app, app+"-replaced"); err == nil {
		t.Error("locked app renamed")
	}
	locks.Close()
	if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if l, err := lockVerifiedInstalledApp(app, manifest, f.parentPolicy); err == nil {
		l.Close()
		t.Fatal("changed file accepted")
	}
	if err := os.WriteFile(file, content, 0600); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(bin, "extra.js")
	if err := os.WriteFile(extra, []byte("extra"), 0600); err != nil {
		t.Fatal(err)
	}
	if l, err := lockVerifiedInstalledApp(app, manifest, f.parentPolicy); err == nil {
		l.Close()
		t.Fatal("extra file accepted")
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if l, err := lockVerifiedInstalledApp(app, manifest, f.parentPolicy); err == nil {
		l.Close()
		t.Fatal("missing file accepted")
	}
}
func TestAuthenticatedActiveVerifierRejectsUnsignedManifest(t *testing.T) {
	_, err := authenticatedActiveVerifier(Candidate{CMS: []byte("invalid"), PublisherPin: strings.Repeat("a", 64)}, bootstraplock.Policy{})
	if err == nil {
		t.Fatal("unsigned inventory accepted")
	}
}

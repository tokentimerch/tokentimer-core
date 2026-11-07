//go:build windows && credentialprepareexperiment

package verifiedextraction

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func testCredentialCandidate() credentialCandidate {
	return credentialCandidate{Version: 1, Operation: strings.Repeat("a", 32), Credential: "ttagent_" + strings.Repeat("b", 16) + "_" + strings.Repeat("c", 64)}
}

func writeTrustedCandidateFixture(t *testing.T, name, sddl, content string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(path, windows.GENERIC_WRITE, 0, &attrs, windows.CREATE_NEW, windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var n uint32
	b := []byte(content)
	if len(b) != 0 {
		if err := windows.WriteFile(h, b, &n, nil); err != nil || n != uint32(len(b)) {
			t.Fatal("fixture write failed")
		}
	}
	if err := windows.FlushFileBuffers(h); err != nil {
		t.Fatal(err)
	}
}

func TestCandidatePrepareRecoverAndNoOverwrite(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	dir := filepath.Dir(f.journal)
	candidate := testCredentialCandidate()
	if err := prepareCredentialCandidate(dir, f.sddl, f.parentPolicy, f.stagePolicy, candidate); err != nil {
		t.Fatal(err)
	}
	got, err := readCredentialCandidate(dir, f.parentPolicy, f.stagePolicy)
	if err != nil || got != candidate {
		t.Fatalf("candidate recovery failed: %v", err)
	}
	other := candidate
	other.Operation = strings.Repeat("d", 32)
	if err := prepareCredentialCandidate(dir, f.sddl, f.parentPolicy, f.stagePolicy, other); err == nil {
		t.Fatal("overwrote existing candidate")
	}
	got, err = readCredentialCandidate(dir, f.parentPolicy, f.stagePolicy)
	if err != nil || got != candidate {
		t.Fatal("existing candidate was changed")
	}
}

func TestCandidateRefusesHardlinkAndConcurrentWriter(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("e", 32))
	dir := filepath.Dir(f.journal)
	if err := prepareCredentialCandidate(dir, f.sddl, f.parentPolicy, f.stagePolicy, testCredentialCandidate()); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, candidateName)
	link := filepath.Join(dir, "candidate-link")
	if err := os.Link(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialCandidate(dir, f.parentPolicy, f.stagePolicy); err == nil {
		t.Fatal("accepted multiply-linked candidate")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(path, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if _, err := readCredentialCandidate(dir, f.parentPolicy, f.stagePolicy); err == nil {
		t.Fatal("accepted a concurrent writer")
	}
}

func TestCandidateRefusesReparsePoint(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("a", 32))
	dir := filepath.Dir(f.journal)
	target := filepath.Join(dir, "other-file")
	writeTrustedCandidateFixture(t, target, f.sddl, `{"version":1}`)
	if err := os.Symlink(target, filepath.Join(dir, candidateName)); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := readCredentialCandidate(dir, f.parentPolicy, f.stagePolicy); err == nil {
		t.Fatal("accepted reparse point")
	}
	if err := prepareCredentialCandidate(dir, f.sddl, f.parentPolicy, f.stagePolicy, testCredentialCandidate()); err == nil {
		t.Fatal("replaced reparse point")
	}
}

func TestCandidateRejectsMalformedAndIncompleteRecords(t *testing.T) {
	for _, contents := range []string{"", `{}`, `{"version":1,"version":1}`, `{"version":1,"operation":"short","credential":"bad"}`, `{"version":1} trailing`} {
		t.Run(strings.ReplaceAll(contents, "/", "_"), func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("d", 32))
			dir := filepath.Dir(f.journal)
			writeTrustedCandidateFixture(t, filepath.Join(dir, candidateName), f.sddl, contents)
			if _, err := readCredentialCandidate(dir, f.parentPolicy, f.stagePolicy); err == nil {
				t.Fatal("accepted malformed candidate")
			}
			if err := prepareCredentialCandidate(dir, f.sddl, f.parentPolicy, f.stagePolicy, testCredentialCandidate()); err == nil {
				t.Fatal("replaced uncertain record")
			}
		})
	}
}

func TestCandidateConcurrentPrepareHasOneWinner(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("b", 32))
	dir := filepath.Dir(f.journal)
	a := testCredentialCandidate()
	b := a
	b.Operation = strings.Repeat("e", 32)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, candidate := range []credentialCandidate{a, b} {
		go func(c credentialCandidate) {
			<-start
			results <- prepareCredentialCandidate(dir, f.sddl, f.parentPolicy, f.stagePolicy, c)
		}(candidate)
	}
	close(start)
	e1, e2 := <-results, <-results
	if (e1 == nil) == (e2 == nil) {
		t.Fatalf("expected exactly one winner, got %v and %v", e1, e2)
	}
	got, err := readCredentialCandidate(dir, f.parentPolicy, f.stagePolicy)
	if err != nil || (got != a && got != b) {
		t.Fatalf("winner not recoverable: %v", err)
	}
}

func TestCandidateRejectsInvalidInputsWithoutWriting(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("c", 32))
	dir := filepath.Dir(f.journal)
	bad := testCredentialCandidate()
	bad.Credential = "not-a-credential"
	if err := prepareCredentialCandidate(dir, f.sddl, f.parentPolicy, f.stagePolicy, bad); err == nil {
		t.Fatal("accepted invalid credential")
	}
	if _, err := os.Stat(filepath.Join(dir, candidateName)); !os.IsNotExist(err) {
		t.Fatal("created candidate for invalid input")
	}
	if err := prepareCredentialCandidate("relative", f.sddl, f.parentPolicy, f.stagePolicy, testCredentialCandidate()); err == nil {
		t.Fatal("accepted relative path")
	}
}

func TestCandidateRefusesUntrustedReadAccess(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("a", 32))
	dir := filepath.Dir(f.journal)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	worldReadable := "O:" + sid + "G:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)"
	if err := prepareCredentialCandidate(dir, worldReadable, f.parentPolicy, f.stagePolicy, testCredentialCandidate()); err == nil {
		t.Fatal("accepted world-readable candidate")
	}
	b, err := os.ReadFile(filepath.Join(dir, candidateName))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Fatal("wrote secret before validating confidentiality")
	}
	if _, err := readCredentialCandidate(dir, f.parentPolicy, f.stagePolicy); err == nil {
		t.Fatal("recovered untrusted candidate")
	}
}

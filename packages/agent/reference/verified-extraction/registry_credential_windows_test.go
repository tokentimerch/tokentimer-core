//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func registryFixture(t *testing.T) (registry.Key, string, map[string]bool, string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sddl := "O:" + sid + "G:" + sid + "D:P(A;;KA;;;" + sid + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	path := "Software\\TTRegistryCandidateTest-" + hex.EncodeToString(random)
	name, _ := windows.UTF16PtrFromString(path)
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var h windows.Handle
	var disposition uint32
	r, _, _ := regCredentialCreate.Call(uintptr(registry.CURRENT_USER), uintptr(unsafe.Pointer(name)), 0, 0, 0, uintptr(registry.ALL_ACCESS|windows.READ_CONTROL), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&disposition)))
	if r != 0 || disposition != 1 {
		t.Fatalf("could not create fixture: %d", r)
	}
	k := registry.Key(h)
	t.Cleanup(func() {
		_ = registry.DeleteKey(k, "CredentialRotationPending")
		_ = k.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, path)
	})
	return k, sddl, map[string]bool{sid: true}, path
}

func registryFixtureRecord() registryCredentialRecord {
	return registryCredentialRecord{Version: 1, Operation: strings.Repeat("a", 32), Credential: "ttagent_" + strings.Repeat("b", 16) + "_" + strings.Repeat("c", 64)}
}

func TestRegistryCandidatePrepareRecoverAndNoOverwrite(t *testing.T) {
	k, sddl, trusted, _ := registryFixture(t)
	want := registryFixtureRecord()
	if err := prepareRegistryCredential(k, sddl, trusted, want); err != nil {
		t.Fatal(err)
	}
	got, err := readRegistryCredential(k, trusted)
	if err != nil || got != want {
		t.Fatalf("recovery failed: %v", err)
	}
	other := want
	other.Operation = strings.Repeat("d", 32)
	if err := prepareRegistryCredential(k, sddl, trusted, other); err == nil {
		t.Fatal("existing journal was replaced")
	}
	got, err = readRegistryCredential(k, trusted)
	if err != nil || got != want {
		t.Fatal("journal changed")
	}
}

func TestRegistryParentLeaseValidatesEachComponent(t *testing.T) {
	k, sddl, trusted, path := registryFixture(t)
	trusted["S-1-5-18"] = true
	trusted["S-1-5-32-544"] = true
	lease, err := openRegistryParent(registry.CURRENT_USER, strings.Split(path, `\`), trusted)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := prepareRegistryCredential(lease.handles[len(lease.handles)-1], sddl, trusted, registryFixtureRecord()); err != nil {
		t.Fatal(err)
	}
	got, err := readRegistryCredential(k, trusted)
	if err != nil || got != registryFixtureRecord() {
		t.Fatalf("journal under leased parent not recovered: %v", err)
	}
	for _, segments := range [][]string{{}, {"Software", ".."}, {"Software", `bad\child`}, {"Software", "bad/child"}} {
		bad, err := openRegistryParent(registry.CURRENT_USER, segments, trusted)
		if err == nil {
			bad.Close()
			t.Fatalf("accepted invalid path %v", segments)
		}
	}
}

func TestRegistryAncestorCreatorOwnerIsNotAnUntrustedWriter(t *testing.T) {
	parent, _, trusted, _ := registryFixture(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	create := func(name, sddl string) registry.Key {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := windows.UTF16PtrFromString(name)
		attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		var h windows.Handle
		var disposition uint32
		r, _, _ := regCredentialCreate.Call(uintptr(parent), uintptr(unsafe.Pointer(p)), 0, 0, 0, uintptr(registry.ALL_ACCESS|windows.READ_CONTROL), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&disposition)))
		if r != 0 || disposition != 1 {
			t.Fatalf("create fixture: %d", r)
		}
		k := registry.Key(h)
		t.Cleanup(func() { _ = k.Close(); _ = registry.DeleteKey(parent, name) })
		return k
	}
	base := "O:" + sid + "G:" + sid + "D:P(A;;KA;;;" + sid + ")"
	creator := create("Creator", base+"(A;CI;KA;;;CO)")
	if err := validateRegistryAncestor(creator, trusted); err != nil {
		t.Fatalf("trusted owner with creator placeholder rejected: %v", err)
	}
	if err := validateCredentialRegistryKey(creator, trusted); err == nil {
		t.Fatal("credential parent allowed creator placeholder")
	}
	world := create("World", base+"(A;;KW;;;WD)")
	if err := validateRegistryAncestor(world, trusted); err == nil {
		t.Fatal("untrusted writer accepted")
	}
}

func TestRegistryParentRejectsLinkMarker(t *testing.T) {
	k, _, trusted, path := registryFixture(t)
	trusted["S-1-5-18"] = true
	trusted["S-1-5-32-544"] = true
	if err := k.SetStringValue("SymbolicLinkValue", "not-a-trusted-link"); err != nil {
		t.Fatal(err)
	}
	lease, err := openRegistryParent(registry.CURRENT_USER, strings.Split(path, `\`), trusted)
	if err == nil {
		lease.Close()
		t.Fatal("accepted ambiguous registry link marker")
	}
}

func TestRegistryJournalPipeRoundTripAndBounds(t *testing.T) {
	k, sddl, trusted, _ := registryFixture(t)
	want := registryFixtureRecord()
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runCredentialJournalWithParent(k, trusted, sddl, []string{"prepare"}, bytes.NewReader(b), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), want.Credential) || out.String() != "{\"state\":\"prepared\"}\n" {
		t.Fatal("prepare disclosed credential")
	}
	out.Reset()
	if err := runCredentialJournalWithParent(k, trusted, sddl, []string{"read"}, bytes.NewReader(nil), &out); err != nil {
		t.Fatal(err)
	}
	var got registryCredentialRecord
	if json.Unmarshal(out.Bytes(), &got) != nil || got != want {
		t.Fatal("pipe recovery failed")
	}
	out.Reset()
	if err := runCredentialJournalWithParent(k, trusted, sddl, []string{"prepare", want.Credential}, bytes.NewReader(b), &out); err == nil || strings.Contains(err.Error(), want.Credential) || out.Len() != 0 {
		t.Fatal("accepted or exposed secret argument")
	}
	if err := runCredentialJournalWithParent(k, trusted, sddl, []string{"read"}, strings.NewReader(want.Credential), &out); err == nil || strings.Contains(err.Error(), want.Credential) || out.Len() != 0 {
		t.Fatal("accepted or exposed unexpected input")
	}
	if err := runCredentialJournalWithParent(k, trusted, sddl, []string{"prepare"}, strings.NewReader(strings.Repeat("x", 513)), &out); err == nil || out.Len() != 0 {
		t.Fatal("accepted oversized input")
	}
}

func TestRegistryJournalPipeChild(t *testing.T) {
	path, mode := os.Getenv("TT_JOURNAL_TEST_PATH"), os.Getenv("TT_JOURNAL_TEST_MODE")
	if path == "" {
		return
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS|windows.READ_CONTROL)
	if err != nil {
		os.Exit(4)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		os.Exit(5)
	}
	sid := user.User.Sid.String()
	sddl := "O:" + sid + "G:" + sid + "D:P(A;;KA;;;" + sid + ")"
	err = runCredentialJournalWithParent(k, map[string]bool{sid: true}, sddl, []string{mode}, os.Stdin, os.Stdout)
	_ = k.Close()
	if err != nil {
		os.Exit(6)
	}
	os.Exit(0)
}

func TestRegistryJournalPipesAcrossProcesses(t *testing.T) {
	_, _, _, path := registryFixture(t)
	want := registryFixtureRecord()
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := func(mode string) *exec.Cmd {
		c := exec.Command(exe, "-test.run=^TestRegistryJournalPipeChild$")
		c.Env = append(os.Environ(), "TT_JOURNAL_TEST_PATH="+path, "TT_JOURNAL_TEST_MODE="+mode)
		return c
	}
	prepare := child("prepare")
	prepare.Stdin = bytes.NewReader(b)
	out, err := prepare.Output()
	if err != nil || string(out) != "{\"state\":\"prepared\"}\n" {
		t.Fatalf("prepare pipe failed: %v", err)
	}
	if strings.Contains(strings.Join(prepare.Args, " "), want.Credential) || strings.Contains(strings.Join(prepare.Env, " "), want.Credential) {
		t.Fatal("credential leaked to args or environment")
	}
	read := child("read")
	read.Stdin = bytes.NewReader(nil)
	out, err = read.Output()
	if err != nil {
		t.Fatalf("read pipe failed: %v", err)
	}
	var got registryCredentialRecord
	if json.Unmarshal(out, &got) != nil || got != want {
		t.Fatal("second process did not recover the candidate")
	}
}

func TestRegistryCandidateRefusesUntrustedReadAccess(t *testing.T) {
	k, _, trusted, _ := registryFixture(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sddl := "O:" + sid + "G:" + sid + "D:P(A;;KA;;;" + sid + ")(A;;KR;;;WD)"
	if err := prepareRegistryCredential(k, sddl, trusted, registryFixtureRecord()); err == nil {
		t.Fatal("accepted untrusted reader")
	}
	child, err := registry.OpenKey(k, "CredentialRotationPending", registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if _, _, err := child.GetBinaryValue("Record"); err == nil {
		t.Fatal("wrote secret before validating ACL")
	}
}

func TestRegistryCandidateRetainsIncompleteKey(t *testing.T) {
	k, _, trusted, _ := registryFixture(t)
	child, _, err := registry.CreateKey(k, "CredentialRotationPending", registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	child.Close()
	if _, err := readRegistryCredential(k, trusted); err == nil {
		t.Fatal("accepted incomplete candidate")
	}
	_, sddl, _, _ := registryFixture(t)
	if err := prepareRegistryCredential(k, sddl, trusted, registryFixtureRecord()); err == nil {
		t.Fatal("replaced uncertain candidate")
	}
}

func TestRegistryCandidateFlushFailureNeverReturnsCandidate(t *testing.T) {
	k, sddl, trusted, _ := registryFixture(t)
	failure := errors.New("injected flush failure")
	fail := func(registry.Key) error { return failure }
	if err := prepareRegistryCredentialWithFlush(k, sddl, trusted, registryFixtureRecord(), fail); !errors.Is(err, failure) {
		t.Fatal("prepare did not report flush failure")
	}
	got, err := readRegistryCredentialWithFlush(k, trusted, fail)
	if !errors.Is(err, failure) || got != (registryCredentialRecord{}) {
		t.Fatal("read returned a candidate after failed flush")
	}
	if err := prepareRegistryCredential(k, sddl, trusted, registryFixtureRecord()); err == nil {
		t.Fatal("uncertain record was overwritten")
	}
	got, err = readRegistryCredential(k, trusted)
	if err != nil || got != registryFixtureRecord() {
		t.Fatalf("later validated flush could not recover: %v", err)
	}
}

func TestRegistryCandidateChild(t *testing.T) {
	path := os.Getenv("TT_REGISTRY_TEST_PATH")
	if path == "" {
		return
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS|windows.READ_CONTROL)
	if err != nil {
		os.Exit(4)
	}
	defer k.Close()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		os.Exit(5)
	}
	sid := user.User.Sid.String()
	sddl := "O:" + sid + "G:" + sid + "D:P(A;;KA;;;" + sid + ")"
	if os.Getenv("TT_REGISTRY_TEST_CRASH_BEFORE_FLUSH") == "1" {
		_ = prepareRegistryCredentialWithFlush(k, sddl, map[string]bool{sid: true}, registryFixtureRecord(), func(registry.Key) error { os.Exit(0); return nil })
		os.Exit(6)
	}
	if prepareRegistryCredential(k, sddl, map[string]bool{sid: true}, registryFixtureRecord()) != nil {
		os.Exit(3)
	}
}

func TestRegistryCandidateRecoverAfterWriterDiesBeforeFlush(t *testing.T) {
	k, _, trusted, path := registryFixture(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestRegistryCandidateChild$")
	child.Env = append(os.Environ(), "TT_REGISTRY_TEST_PATH="+path, "TT_REGISTRY_TEST_CRASH_BEFORE_FLUSH=1")
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	got, err := readRegistryCredential(k, trusted)
	if err != nil || got != registryFixtureRecord() {
		t.Fatalf("candidate not recovered and flushed: %v", err)
	}
}

func TestRegistryCandidateConcurrentProcesses(t *testing.T) {
	k, _, trusted, path := registryFixture(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	makeChild := func() *exec.Cmd {
		c := exec.Command(exe, "-test.run=^TestRegistryCandidateChild$")
		c.Env = append(os.Environ(), "TT_REGISTRY_TEST_PATH="+path)
		return c
	}
	a, b := makeChild(), makeChild()
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		_ = a.Wait()
		t.Fatal(err)
	}
	ea, eb := a.Wait(), b.Wait()
	if (ea == nil) == (eb == nil) {
		t.Fatalf("expected one winner, got %v and %v", ea, eb)
	}
	got, err := readRegistryCredential(k, trusted)
	if err != nil || got != registryFixtureRecord() {
		t.Fatalf("winner unrecoverable: %v", err)
	}
}

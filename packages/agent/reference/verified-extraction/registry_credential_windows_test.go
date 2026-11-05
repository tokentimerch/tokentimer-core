//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"crypto/rand"
	"encoding/hex"
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

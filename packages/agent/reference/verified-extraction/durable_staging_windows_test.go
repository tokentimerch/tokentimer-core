//go:build windows

package verifiedextraction

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

// An ACL remains an OS-enforced boundary after a guard handle closes.
// This fixture uses the current user as the only trusted identity and does
// not qualify SYSTEM/Admin ownership, WMI/SCM actors, crash, or reboot.
func TestProtectedDirectoryIdentityAndDACLAfterHandleClose(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	root := filepath.Join(t.TempDir(), "quarantine")
	if err := createRestrictedDirectory(root, "O:"+sid+"G:"+sid+"D:P(A;OICI;FA;;;"+sid+")"); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "payload")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := getDirectoryIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		t.Fatal(err)
	}
	open := func() windows.Handle {
		h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	held := open()
	if err := windows.CloseHandle(held); err != nil {
		t.Fatal(err)
	}
	reopened := open()
	defer windows.CloseHandle(reopened)
	policy := bootstraplock.Policy{Owners: map[string]bool{sid: true}, Writers: map[string]bool{sid: true}}
	if err := policy.ValidateHandle(syscall.Handle(reopened), false); err != nil {
		t.Fatalf("protected ACL changed: %v", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(reopened, &info); err != nil {
		t.Fatal(err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (directoryIdentity{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}) != id {
		t.Fatal("staging identity changed")
	}
	content, err := os.ReadFile(file)
	if err != nil || string(content) != "fixture" {
		t.Fatalf("payload not retained: %v", err)
	}
}

func TestKilledStageGuardFixture(t *testing.T) {
	root := os.Getenv("TT_STAGE_GUARD_FIXTURE")
	if root == "" {
		return
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	if err := createRestrictedDirectory(root, "O:"+sid+"G:"+sid+"D:P(A;OICI;FA;;;"+sid+")"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "payload"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(guard)
	if err := os.WriteFile(root+".ready", []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Second)
	}
}

// A killed guard releases OS handles, but must not remove the protected tree.
// This does not prove recovery after reboot or safety against privileged actors.
func TestProtectedStagePersistsAfterGuardProcessKilled(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	cmd := exec.Command(os.Args[0], "-test.run=^TestKilledStageGuardFixture$")
	cmd.Env = append(os.Environ(), "TT_STAGE_GUARD_FIXTURE="+root)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(root + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("guard fixture did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	id, err := getDirectoryIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	got, err := getDirectoryIdentity(root)
	if err != nil || got != id {
		t.Fatalf("protected staging identity changed after guard death: %v", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	policy := bootstraplock.Policy{Owners: map[string]bool{sid: true}, Writers: map[string]bool{sid: true}}
	if err := policy.ValidateHandle(syscall.Handle(h), false); err != nil {
		t.Fatalf("staging DACL no longer protected: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(root, "payload"))
	if err != nil || string(content) != "fixture" {
		t.Fatalf("protected payload not retained: %v", err)
	}
}

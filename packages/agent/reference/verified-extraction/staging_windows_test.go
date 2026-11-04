//go:build windows

package verifiedextraction

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

// Uses the non-privileged test identity, never an administrator-only directory.
func TestCreateRestrictedDirectoryIsAtomicAndProtected(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	target := filepath.Join(t.TempDir(), "private")
	sddl := "O:" + sid + "G:" + sid + "D:P(A;OICI;FA;;;" + sid + ")"
	if err := createRestrictedDirectory(target, sddl); err != nil {
		t.Fatal(err)
	}
	path, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(path, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	flags, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if flags&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("DACL unexpectedly inherited")
	}
	policy := bootstraplock.Policy{Owners: map[string]bool{sid: true}, Writers: map[string]bool{sid: true}}
	if err := policy.ValidateHandle(syscall.Handle(h), false); err != nil {
		t.Fatalf("actual DACL/owner rejected: %v", err)
	}
	if err := createRestrictedDirectory(target, sddl); err == nil {
		t.Fatal("existing staging directory accepted")
	}
}

func TestNewPrivateStagingRequiresElevation(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("test requires non-elevated token")
	}
	if _, err := NewPrivateStaging(); err == nil {
		t.Fatal("non-elevated staging accepted")
	}
}

func TestCleanupChecksOwnershipBeforeRemoving(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "TokenTimer-Staging-"+strings.Repeat("a", 32))
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "marker")
	if err := os.WriteFile(marker, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := getDirectoryIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	stage := &PrivateStaging{path: root, parent: parent, identity: directoryIdentity{volume: id.volume, indexHigh: id.indexHigh, indexLow: id.indexLow + 1}, ancestors: &bootstraplock.Locks{}, staging: &bootstraplock.Locks{}}
	if err := stage.Cleanup(); err == nil {
		t.Fatal("changed identity accepted")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("unowned content was removed")
	}
	stage.identity = id
	if err := stage.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("expected staging removed, got %v", err)
	}
}

func TestCreateFailureCleanupPreservesNonEmptyStaging(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "TokenTimer-Staging-"+strings.Repeat("b", 32))
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := getDirectoryIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	stage := &PrivateStaging{path: root, parent: parent, identity: id, ancestors: &bootstraplock.Locks{}}
	marker := filepath.Join(root, "marker")
	if err := os.WriteFile(marker, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stage.removeEmptyAfterCreateFailure(); err == nil {
		t.Fatal("non-empty directory removed")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("staging content was removed")
	}
}

func TestCleanupReleasesLocksWhenDeletionAndReacquisitionFail(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "TokenTimer-Staging-"+strings.Repeat("c", 32))
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "held")
	if err := os.WriteFile(file, []byte("hold"), 0600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(file)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	id, err := getDirectoryIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	// Empty policy intentionally prevents relocking after deletion is blocked.
	stage := &PrivateStaging{path: root, parent: parent, identity: id, ancestors: &bootstraplock.Locks{}, staging: &bootstraplock.Locks{}}
	if err := stage.Cleanup(); err == nil {
		t.Fatal("locked file unexpectedly deleted")
	}
	if stage.ancestors != nil {
		t.Fatal("ancestor handles retained after failed recovery")
	}
}

func TestFailedPreparationReleasesHandlesWhenCleanupRefuses(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "TokenTimer-Staging-"+strings.Repeat("d", 32))
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	stage := &PrivateStaging{path: root, parent: parent, ancestors: &bootstraplock.Locks{}, staging: &bootstraplock.Locks{}}
	err := cleanupFailedStage(stage, errors.New("verification failed"))
	if err == nil || !strings.Contains(err.Error(), "manual recovery") {
		t.Fatalf("unexpected recovery result: %v", err)
	}
	if stage.ancestors != nil || stage.staging != nil {
		t.Fatal("handles retained after failed preparation")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal("unidentified staging should be preserved")
	}
}

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

// This creates and removes one randomly named staging directory using the
// production API. It is opt-in and must run on an authorized disposable host.
// It validates the current host's staging ACL/path only, not an installer,
// release signature, WMI/SCM execution or automatic crash recovery.
func TestNativePrivateStagingWithElevatedToken(t *testing.T) {
	if os.Getenv("TT_REQUIRE_STAGING_NATIVE") != "1" {
		t.Skip("set TT_REQUIRE_STAGING_NATIVE=1 on an authorized disposable host")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("native staging qualification requires an elevated token")
	}
	parent, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := NewPrivateStaging()
	if err != nil {
		t.Fatalf("create production private staging: %v", err)
	}
	// Refuse cleanup entirely if the created target is outside the intended
	// parent or does not have the production random-name format.
	if !strings.EqualFold(filepath.Dir(stage.Root()), filepath.Clean(parent)) || !stageNamePattern.MatchString(filepath.Base(stage.Root())) {
		stage.Close()
		t.Fatal("created staging path is outside the verified target parent")
	}
	defer func() {
		if err := stage.Cleanup(); err != nil {
			stage.Close()
			t.Errorf("owned staging cleanup failed: %v", err)
		}
	}()
	id, err := getDirectoryIdentity(stage.Root())
	if err != nil || id != stage.identity {
		t.Fatalf("staging identity mismatch: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stage.Root(), "fixture.txt"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stage.LockPayload(); err != nil {
		t.Fatalf("lock protected payload: %v", err)
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
	stage := &PrivateStaging{freshOwned: true, path: root, parent: parent, identity: directoryIdentity{volume: id.volume, indexHigh: id.indexHigh, indexLow: id.indexLow + 1}, ancestors: &bootstraplock.Locks{}, staging: &bootstraplock.Locks{}}
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
	stage := &PrivateStaging{freshOwned: true, path: root, parent: parent, identity: id, ancestors: &bootstraplock.Locks{}, staging: &bootstraplock.Locks{}}
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

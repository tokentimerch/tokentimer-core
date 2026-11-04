//go:build windows

package verifiedextraction

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

// PrivateStaging holds ancestor and staging handles for the caller. It is a
// building block: it does not authenticate the launcher or any package.
type PrivateStaging struct {
	intentMu        sync.Mutex
	intentAttempted bool
	intentFlushed   bool
	freshOwned      bool
	path            string
	parent          string
	identity        directoryIdentity
	policy          bootstraplock.Policy
	ancestors       *bootstraplock.Locks
	staging         *bootstraplock.Locks
	payload         *bootstraplock.Locks
}

// Root is immutable to callers; its contents must remain locked until use ends.
func (s *PrivateStaging) Root() string { return s.path }

type directoryIdentity struct {
	volume    uint32
	indexHigh uint32
	indexLow  uint32
}

func getDirectoryIdentity(path string) (directoryIdentity, error) {
	var result directoryIdentity
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return result, err
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return result, err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return result, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return result, fmt.Errorf("invalid staging directory")
	}
	return directoryIdentity{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}, nil
}

// LockPayload must be called after verified extraction and held through use.
func (s *PrivateStaging) LockPayload() error {
	s.intentMu.Lock()
	defer s.intentMu.Unlock()
	if s.ancestors == nil || s.staging == nil || s.payload != nil {
		return fmt.Errorf("staging is not active")
	}
	locks, err := bootstraplock.LockProtectedTree(s.path, s.policy)
	if err != nil {
		return err
	}
	s.payload = locks
	return nil
}

// Close releases path locks. The caller must not execute extracted data after
// closing the locks. Secure deletion/recovery of the directory is separate.
func (s *PrivateStaging) Close() {
	s.intentMu.Lock()
	defer s.intentMu.Unlock()
	s.closeLocked()
}

func (s *PrivateStaging) closeLocked() {
	if s.payload != nil {
		s.payload.Close()
		s.payload = nil
	}
	if s.staging != nil {
		s.staging.Close()
		s.staging = nil
	}
	if s.ancestors != nil {
		s.ancestors.Close()
		s.ancestors = nil
	}
}

var stageNamePattern = regexp.MustCompile("^TokenTimer-Staging-[a-f0-9]{32}$")

// Cleanup only removes the specific protected directory created by this
// instance, with the parent still locked and the original file identity intact.
// Unexpected links or changed identity cause a fail-closed operator recovery.
func (s *PrivateStaging) Cleanup() error {
	s.intentMu.Lock()
	defer s.intentMu.Unlock()
	if s.ancestors == nil || s.staging == nil || !filepath.IsAbs(s.path) ||
		!strings.EqualFold(filepath.Dir(s.path), s.parent) || !stageNamePattern.MatchString(filepath.Base(s.path)) {
		return fmt.Errorf("staging ownership not established")
	}
	// An absent marker on a recovered stage proves nothing about past execution.
	if !s.freshOwned {
		return ErrExecutionRecoveryPending
	}
	// Once execution intent has been attempted, or a marker already exists,
	// this instance cannot prove that external WMI/SCM actors have finished.
	// Never interpret a malformed or unreadable marker as permission to delete.
	if s.intentAttempted {
		return ErrExecutionRecoveryPending
	}
	if _, err := os.Lstat(s.path + ".intent"); err == nil || !os.IsNotExist(err) {
		return ErrExecutionRecoveryPending
	}
	id, err := getDirectoryIdentity(s.path)
	if err != nil || id != s.identity {
		return fmt.Errorf("staging identity changed")
	}
	err = filepath.WalkDir(s.path, func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(p)
		if err != nil {
			return err
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("staging contains a reparse point")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if s.payload != nil {
		s.payload.Close()
		s.payload = nil
	}
	s.staging.Close()
	s.staging = nil
	if err := os.RemoveAll(s.path); err != nil {
		// Reacquire before permitting retry. Otherwise release the ancestors
		// and require explicit manual recovery.
		locks, lockErr := bootstraplock.LockProtectedTree(s.path, s.policy)
		if lockErr != nil {
			s.closeLocked()
			return fmt.Errorf("staging cleanup failed; manual recovery required: %w", err)
		}
		s.staging = locks
		return fmt.Errorf("staging cleanup failed; retry is possible: %w", err)
	}
	s.ancestors.Close()
	s.ancestors = nil
	return nil
}

// removeEmptyAfterCreateFailure uses only a saved file identity and a locked
// parent. It never removes a non-empty or unidentified staging directory.
func (s *PrivateStaging) removeEmptyAfterCreateFailure() error {
	if s.ancestors == nil || !filepath.IsAbs(s.path) ||
		!strings.EqualFold(filepath.Dir(s.path), s.parent) || !stageNamePattern.MatchString(filepath.Base(s.path)) {
		return fmt.Errorf("staging ownership not established")
	}
	id, err := getDirectoryIdentity(s.path)
	if err != nil || id != s.identity {
		return fmt.Errorf("staging identity unavailable or changed")
	}
	entries, err := os.ReadDir(s.path)
	if err != nil || len(entries) != 0 {
		return fmt.Errorf("staging is not verified empty")
	}
	return os.Remove(s.path)
}

func createRestrictedDirectory(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	return windows.CreateDirectory(name, &attrs)
}

// NewPrivateStaging fails closed unless elevated, and creates a new random
// directory with a protected DACL atomically under the OS Program Files path.
// Admins and SYSTEM are trusted; service-owner TrustedInstaller is trusted for
// ancestor ownership. Existing/replaced paths and uncertain ACLs are refused.
// Caller must authenticate the launcher and manifest independently first.
func NewPrivateStaging() (_ *PrivateStaging, err error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, fmt.Errorf("an elevated token is required")
	}
	parent, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(parent) {
		return nil, fmt.Errorf("Program Files path is not absolute")
	}
	sid, _, _, err := windows.LookupSID("", "NT SERVICE\\TrustedInstaller")
	if err != nil {
		return nil, fmt.Errorf("TrustedInstaller SID unavailable")
	}
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, sid.String(): true}
	policy := bootstraplock.Policy{Owners: trusted, Writers: trusted}
	ancestors, err := bootstraplock.LockAncestors(parent, policy)
	if err != nil {
		return nil, fmt.Errorf("unsafe staging parent: %w", err)
	}
	stage := &PrivateStaging{ancestors: ancestors, parent: filepath.Clean(parent), policy: policy}
	created := false
	defer func() {
		if err != nil {
			if created {
				if cleanupErr := stage.removeEmptyAfterCreateFailure(); cleanupErr != nil {
					err = fmt.Errorf("%w; unverified staging retained at %s: %v", err, stage.path, cleanupErr)
				}
			}
			stage.Close()
		}
	}()
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return nil, err
	}
	stage.path = filepath.Join(parent, "TokenTimer-Staging-"+hex.EncodeToString(random))
	// Owner/group = Builtin Administrators; protected inherited DACL grants only
	// SYSTEM and Administrators, including their inherited file/directory rights.
	if err = createRestrictedDirectory(stage.path, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"); err != nil {
		return nil, fmt.Errorf("create private staging: %w", err)
	}
	created = true
	stage.identity, err = getDirectoryIdentity(stage.path)
	if err != nil {
		return nil, fmt.Errorf("identify private staging: %w", err)
	}
	stage.staging, err = bootstraplock.LockProtectedTree(stage.path, policy)
	if err != nil {
		return nil, fmt.Errorf("verify private staging: %w", err)
	}
	stage.freshOwned = true
	return stage, nil
}

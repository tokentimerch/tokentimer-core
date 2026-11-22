//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

// Experimental building block only. Handle/ACL protection does not prove the
// source is the expected enrollment or that old SYSTEM work has stopped.
// The caller owns and must clear returned bytes. No paths or data are logged.
func readProtectedEnrollmentFile(dir, name string, policy bootstraplock.Policy, privateReaders map[string]bool, limit int64) ([]byte, error) {
	return readProtectedEnrollmentFileWithHook(dir, name, policy, privateReaders, limit, nil)
}

func readProtectedEnrollmentFileWithHook(dir, name string, policy bootstraplock.Policy, privateReaders map[string]bool, limit int64, afterValidation func() error) ([]byte, error) {
	volume := filepath.VolumeName(dir)
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || len(volume) != 2 || volume[1] != ':' || name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `\/:`+"\x00") || len(privateReaders) == 0 || limit < 1 || limit > 1<<20 {
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	locks, err := bootstraplock.LockAncestors(dir, policy)
	if err != nil {
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	defer locks.Close()
	ptr, err := windows.UTF16PtrFromString(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	f := os.NewFile(uintptr(h), "enrollment-input")
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	defer f.Close()
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || int64(info.FileSizeLow) > limit {
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	var filesystem [32]uint16
	if windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))) != nil || windows.UTF16ToString(filesystem[:]) != "NTFS" {
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	if policy.ValidateHandle(syscall.Handle(h), false) != nil {
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	if validateEnrollmentPrivateReaders(h, privateReaders) != nil {
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	if afterValidation != nil && afterValidation() != nil {
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) == 0 || int64(len(b)) > limit {
		clear(b)
		return nil, fmt.Errorf("enrollment input unavailable")
	}
	return b, nil
}

func validateEnrollmentPrivateReaders(h windows.Handle, trusted map[string]bool) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() {
		return fmt.Errorf("file security unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !trusted[owner.String()] {
		return fmt.Errorf("untrusted file owner")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("file DACL not protected")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return fmt.Errorf("file DACL unavailable")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil {
			return fmt.Errorf("file ACE unavailable")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 16 {
			return fmt.Errorf("unsupported file ACE")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !trusted[sid.String()] {
			return fmt.Errorf("untrusted file reader")
		}
	}
	return nil
}

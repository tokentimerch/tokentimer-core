//go:build windows

// Package bootstraplock provides experimental NTFS path locks.
// Authentication and ACL validation are required independently.
package bootstraplock

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	fileReadAttributes    = 0x80
	fileReadData          = 0x01
	readControl           = 0x00020000
	fileShareRead         = 1
	fileShareWrite        = 2
	openExisting          = 3
	flagOpenReparsePoint  = 0x00200000
	flagBackupSemantics   = 0x02000000
	attributeReparsePoint = 0x400
	attributeDirectory    = 0x10
)

type Locks struct {
	handles []syscall.Handle
	files   map[string]bool
}

// LockAncestors holds each component, including the requested directory, against
// replacement while checking the security descriptor on the opened handle.
// The supplied policy must originate outside the untrusted package.
func LockAncestors(root string, policy Policy) (_ *Locks, err error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("path must be absolute")
	}
	root = filepath.Clean(root)
	l := &Locks{files: make(map[string]bool)}
	defer func() {
		if err != nil {
			l.Close()
		}
	}()
	var ancestors []string
	for p := root; ; p = filepath.Dir(p) {
		ancestors = append(ancestors, p)
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
	}
	for i := len(ancestors) - 1; i >= 0; i-- {
		// The final directory contains newly created protected stages and must
		// exclude untrusted child creation, unlike its higher ancestors.
		ancestor := i != 0
		if err = l.open(ancestors[i], true, func(h syscall.Handle) error { return policy.ValidateHandle(h, ancestor) }); err != nil {
			return nil, err
		}
	}
	return l, nil
}

func (l *Locks) Close() {
	for i := len(l.handles) - 1; i >= 0; i-- {
		_ = syscall.CloseHandle(l.handles[i])
	}
	l.handles = nil
}

func (l *Locks) open(name string, directory bool, validate func(syscall.Handle) error) error {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	share := uint32(fileShareRead)
	if directory {
		share |= fileShareWrite
	}
	access := uint32(fileReadAttributes | fileReadData)
	if validate != nil {
		access |= readControl
	}
	h, err := syscall.CreateFile(p, access, share, nil, openExisting, flagOpenReparsePoint|flagBackupSemantics, 0)
	if err != nil {
		return fmt.Errorf("lock %s: %w", name, err)
	}
	var info syscall.ByHandleFileInformation
	if err = syscall.GetFileInformationByHandle(h, &info); err != nil {
		_ = syscall.CloseHandle(h)
		return err
	}
	if info.FileAttributes&attributeReparsePoint != 0 {
		_ = syscall.CloseHandle(h)
		return fmt.Errorf("reparse point refused: %s", name)
	}
	if (info.FileAttributes&attributeDirectory != 0) != directory {
		_ = syscall.CloseHandle(h)
		return fmt.Errorf("unexpected file type: %s", name)
	}
	if validate != nil {
		if err = validate(h); err != nil {
			_ = syscall.CloseHandle(h)
			return fmt.Errorf("security descriptor %s: %w", name, err)
		}
	}
	l.handles = append(l.handles, h)
	if !directory {
		l.files[strings.ToLower(filepath.Clean(name))] = true
	}
	return nil
}

// LockTree holds each ancestor and every currently enumerated bundle entry
// without FILE_SHARE_DELETE. Files are also opened without FILE_SHARE_WRITE.
// The caller must independently authenticate the helper and payload and
// establish that all directories are protected against untrusted creation,
// ACL changes and writes. Enumeration is not an authenticated inventory.
// LockProtectedTree verifies owner and DACL on the actual locked handles.
// It does not authenticate the caller, helper, or bundle; a trusted launcher
// must authenticate and extract the payload before calling it.
func LockProtectedTree(root string, policy Policy) (*Locks, error) {
	return lockTree(root, &policy)
}

func lockTree(root string, policy *Policy) (_ *Locks, err error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("bundle path must be absolute")
	}
	root = filepath.Clean(root)
	l := &Locks{files: make(map[string]bool)}
	defer func() {
		if err != nil {
			l.Close()
		}
	}()
	var ancestors []string
	for p := root; ; p = filepath.Dir(p) {
		ancestors = append(ancestors, p)
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
	}
	for i := len(ancestors) - 1; i >= 0; i-- {
		var validate func(syscall.Handle) error
		if policy != nil {
			ancestor := i != 0
			validate = func(h syscall.Handle) error { return policy.ValidateHandle(h, ancestor) }
		}
		if err = l.open(ancestors[i], true, validate); err != nil {
			return nil, err
		}
	}
	err = filepath.WalkDir(root, func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if strings.EqualFold(name, root) {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("link refused: %s", name)
		}
		var validate func(syscall.Handle) error
		if policy != nil {
			validate = func(h syscall.Handle) error { return policy.ValidateHandle(h, false) }
		}
		return l.open(name, d.IsDir(), validate)
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

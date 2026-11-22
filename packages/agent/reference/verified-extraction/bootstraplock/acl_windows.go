//go:build windows

package bootstraplock

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Policy is supplied by a trusted launcher, not by the payload being checked.
// This experimental policy is deliberately conservative: it does not resolve
// group membership or claim to authenticate the publisher of a package.
type Policy struct {
	Owners  map[string]bool
	Writers map[string]bool
}

const (
	// Generic write/all, DELETE, WRITE_DAC, WRITE_OWNER, DELETE_CHILD and
	// FILE_WRITE_ATTRIBUTES can affect the identity or metadata of an ancestor.
	ancestorWriteMask uint32 = 0x500D0142
	// Also reject file data/append and directory creation within the payload.
	payloadWriteMask uint32 = 0x500D0156
)

func (p Policy) ValidateHandle(h syscall.Handle, ancestor bool) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(h), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return p.validateDescriptor(sd, ancestor)
}

func (p Policy) validateDescriptor(sd *windows.SECURITY_DESCRIPTOR, ancestor bool) error {
	if sd == nil || !sd.IsValid() {
		return fmt.Errorf("missing or invalid security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !p.Owners[owner.String()] {
		return fmt.Errorf("untrusted owner")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("missing or empty DACL")
	}
	mask := payloadWriteMask
	if ancestor {
		mask = ancestorWriteMask
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return fmt.Errorf("unreadable ACE")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("unsupported ACE type")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if uint32(ace.Mask)&mask == 0 {
			continue
		}
		if ace.Header.AceSize < 16 {
			return fmt.Errorf("invalid ACE length")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !p.Writers[sid.String()] {
			return fmt.Errorf("untrusted write access")
		}
	}
	return nil
}

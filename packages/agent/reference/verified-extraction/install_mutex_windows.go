//go:build windows

package verifiedextraction

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const installMutexName = `Global\TokenTimer.Agent.Install.v1`

// The installer uses the same named mutex. Its security descriptor must be
// verified even when CreateMutex opened an object created by another process.
func lockInstall(ctx context.Context) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return 0, err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(installMutexName)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateMutex(&attrs, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return 0, fmt.Errorf("create install mutex: %w", err)
	}
	if h == 0 {
		return 0, fmt.Errorf("install mutex unavailable")
	}
	if err := validateInstallMutex(h); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	for {
		if err := ctx.Err(); err != nil {
			windows.CloseHandle(h)
			return 0, err
		}
		state, err := windows.WaitForSingleObject(h, 100)
		if err != nil {
			windows.CloseHandle(h)
			return 0, err
		}
		if state == windows.WAIT_OBJECT_0 || state == windows.WAIT_ABANDONED {
			return h, nil
		}
		if state != uint32(windows.WAIT_TIMEOUT) {
			windows.CloseHandle(h)
			return 0, fmt.Errorf("unexpected install mutex wait: %d", state)
		}
		time.Sleep(time.Millisecond)
	}
}

func unlockInstall(h windows.Handle) error {
	err := windows.ReleaseMutex(h)
	closeErr := windows.CloseHandle(h)
	if err != nil {
		return fmt.Errorf("release install mutex: %w", err)
	}
	return closeErr
}

func validateInstallMutex(h windows.Handle) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() {
		return fmt.Errorf("install mutex security unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || (owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544") {
		return fmt.Errorf("untrusted install mutex owner")
	}
	flags, _, err := sd.Control()
	if err != nil || flags&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("install mutex DACL is not protected")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 2 {
		return fmt.Errorf("invalid install mutex DACL")
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Header.AceSize < 16 {
			return fmt.Errorf("invalid install mutex ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || (sid.String() != "S-1-5-18" && sid.String() != "S-1-5-32-544") || seen[sid.String()] {
			return fmt.Errorf("untrusted install mutex ACE")
		}
		// Mutex full control is 0x1f0001; reject reduced or additional access.
		if uint32(ace.Mask) != 0x1f0001 && uint32(ace.Mask) != 0x10000000 {
			return fmt.Errorf("unexpected install mutex access mask")
		}
		seen[sid.String()] = true
	}
	if len(seen) != 2 {
		return fmt.Errorf("incomplete install mutex DACL")
	}
	return nil
}

// Called only with the shared mutex held. A pre-existing marker or legacy
// recovery record needs operator reconciliation before beginning a candidate.
func assertNoPendingExecution(parent string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return fmt.Errorf("recovery_required: staging inventory unavailable: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(strings.ToLower(name), "tokentimer-staging-") && strings.HasSuffix(strings.ToLower(name), ".intent") {
			return ErrExecutionRecoveryPending
		}
	}
	_, err = os.Lstat(`C:\ProgramData\TokenTimerAgent\state\upgrade-recovery.json`)
	if err == nil || !os.IsNotExist(err) {
		return ErrExecutionRecoveryPending
	}
	return nil
}

func nativeProgramFiles() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
}

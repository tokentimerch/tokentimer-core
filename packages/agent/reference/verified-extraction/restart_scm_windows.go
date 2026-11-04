//go:build windows

package verifiedextraction

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// nativeRestartController requires an independently established process
// environment/loader policy before any SCM operation. No production provider
// for this proof is wired; constructing one with nil fails closed.
type nativeRestartController struct {
	service          *mgr.Service
	app              string
	proveEnvironment func(context.Context) error
	old              []windows.Handle
	oldHostPID       uint32
	oldNodePID       uint32
}

func (c *nativeRestartController) Close() {
	for _, h := range c.old {
		windows.CloseHandle(h)
	}
	c.old = nil
}
func (c *nativeRestartController) VerifyBefore(ctx context.Context) error {
	if c.service == nil || c.proveEnvironment == nil {
		return fmt.Errorf("qualified process environment unavailable")
	}
	cfg, err := c.service.Config()
	if err != nil {
		return err
	}
	if err := validateSCMConfig(cfg, c.app, runtime.GOARCH); err != nil {
		return err
	}
	return c.proveEnvironment(ctx)
}
func (c *nativeRestartController) RequestStop(ctx context.Context) error {
	status, err := c.service.Query()
	if err != nil {
		return err
	}
	if err := validateStopEntryStatus(status); err != nil {
		return err
	}
	host, node, err := captureServiceProcesses(status.ProcessId, c.app)
	if err != nil {
		return err
	}
	c.old = append(c.old, host, node)
	c.oldHostPID = status.ProcessId
	c.oldNodePID, err = windows.GetProcessId(node)
	if err != nil {
		return fmt.Errorf("service child identity unavailable")
	}
	if children, e := hasDirectChildren(c.oldNodePID); e != nil || children {
		return fmt.Errorf("service child has active descendants")
	}
	status2, err := c.service.Query()
	if err != nil || status2.State != svc.Running || status2.ProcessId != status.ProcessId {
		return fmt.Errorf("service changed during inspection")
	}
	_, err = c.service.Control(svc.Stop)
	return err
}
func (c *nativeRestartController) WaitStoppedAndOldProcessesExited(ctx context.Context) error {
	if len(c.old) != 2 || c.oldHostPID == 0 || c.oldNodePID == 0 {
		return fmt.Errorf("prior process handles unavailable; manual review required")
	}
	for {
		status, err := c.service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			break
		}
		if status.State != svc.StopPending {
			return fmt.Errorf("service state changed while stopping")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	for _, h := range c.old {
		for {
			state, err := windows.WaitForSingleObject(h, 0)
			if err != nil {
				return err
			}
			if state == windows.WAIT_OBJECT_0 {
				break
			}
			if state != uint32(windows.WAIT_TIMEOUT) {
				return fmt.Errorf("old process state unavailable")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	for _, pid := range []uint32{c.oldHostPID, c.oldNodePID} {
		if pid != 0 {
			if children, e := hasDirectChildren(pid); e != nil || children {
				return fmt.Errorf("old service descendants remain")
			}
		}
	}
	return nil
}
func (c *nativeRestartController) RequestStart(ctx context.Context) error {
	if err := c.VerifyBefore(ctx); err != nil {
		return err
	}
	status, err := c.service.Query()
	if err != nil || status.State != svc.Stopped {
		return fmt.Errorf("service is not stopped")
	}
	return c.service.Start()
}
func (c *nativeRestartController) VerifyStarted(ctx context.Context) error {
	for {
		status, err := c.service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Running && status.ProcessId != 0 {
			host, node, e := captureServiceProcesses(status.ProcessId, c.app)
			if e == nil {
				defer windows.CloseHandle(host)
				defer windows.CloseHandle(node)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Second):
				}
				after, e := c.service.Query()
				if e != nil || after.State != svc.Running || after.ProcessId != status.ProcessId {
					return fmt.Errorf("service changed after start")
				}
				for _, h := range []windows.Handle{host, node} {
					state, e := windows.WaitForSingleObject(h, 0)
					if e != nil || state != uint32(windows.WAIT_TIMEOUT) {
						return fmt.Errorf("new service process exited")
					}
				}
				return c.VerifyBefore(ctx)
			}
		} else if status.State != svc.StartPending {
			return fmt.Errorf("service failed to start")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
func captureServiceProcesses(hostPID uint32, app string) (windows.Handle, windows.Handle, error) {
	host, err := openSystemProcess(hostPID, filepath.Join(app, "bin", "tokentimer-agent-host-"+runtime.GOARCH+".exe"))
	if err != nil {
		return 0, 0, err
	}
	fail := func(e error) (windows.Handle, windows.Handle, error) { windows.CloseHandle(host); return 0, 0, e }
	childPID, snapshotCreated, err := snapshotSingleChild(hostPID)
	if err != nil {
		return fail(err)
	}
	node, err := openSystemProcess(childPID, filepath.Join(app, "runtime", runtime.GOARCH, "node.exe"))
	if err != nil {
		return fail(err)
	}
	openedPID, e0 := windows.GetProcessId(node)
	observedPID, observedCreated, eSnapshot := snapshotSingleChild(hostPID)
	nodeState, eNode := windows.WaitForSingleObject(node, 0)
	hostState, eHost := windows.WaitForSingleObject(host, 0)
	hostCreated, e1 := processCreationTime(host)
	nodeCreated, e2 := processCreationTime(node)
	if e0 != nil || eSnapshot != nil || eNode != nil || eHost != nil || e1 != nil || e2 != nil || !validProcessAssociation(childPID, openedPID, observedPID, hostCreated, nodeCreated, snapshotCreated, observedCreated, hostState, nodeState) {
		windows.CloseHandle(node)
		return fail(fmt.Errorf("service process association changed"))
	}
	return host, node, nil
}
func openSystemProcess(pid uint32, expected string) (windows.Handle, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return 0, err
	}
	fail := func(e error) (windows.Handle, error) { windows.CloseHandle(h); return 0, e }
	var token windows.Token
	if err = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return fail(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid == nil || user.User.Sid.String() != "S-1-5-18" {
		return fail(fmt.Errorf("service process is not LocalSystem"))
	}
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil || !strings.EqualFold(filepath.Clean(windows.UTF16ToString(buf[:size])), filepath.Clean(expected)) {
		return fail(fmt.Errorf("service process image path mismatch"))
	}
	return h, nil
}

func validateSCMConfig(cfg mgr.Config, app, architecture string) error {
	if cfg.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || !strings.EqualFold(cfg.ServiceStartName, "LocalSystem") || !strings.EqualFold(cfg.BinaryPathName, expectedKeptServiceCommand(app, architecture)) {
		return fmt.Errorf("service account, type or command rejected")
	}
	return nil
}

func processCreationTime(h windows.Handle) (uint64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}
func hasDirectChildren(pid uint32) (bool, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		if entry.ParentProcessID == pid {
			return true, nil
		}
		err = windows.Process32Next(snapshot, &entry)
	}
	if err != nil && !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return false, err
	}
	return false, nil
}

func validateStopEntryStatus(status svc.Status) error {
	if status.State != svc.Running || status.ProcessId == 0 {
		return fmt.Errorf("prior process handles unavailable; manual review required")
	}
	return nil
}

// snapshotSingleChild binds parent and process creation time in one kernel
// snapshot. This internal Windows API must be qualified per supported OS.
func snapshotSingleChild(parent uint32) (uint32, uint64, error) {
	size := uint32(1 << 20)
	var buffer []byte
	for {
		if size > 32<<20 {
			return 0, 0, fmt.Errorf("process snapshot exceeds limit")
		}
		buffer = make([]byte, size)
		var needed uint32
		err := windows.NtQuerySystemInformation(windows.SystemProcessInformation, unsafe.Pointer(&buffer[0]), size, &needed)
		if err == windows.STATUS_INFO_LENGTH_MISMATCH || err == windows.STATUS_BUFFER_TOO_SMALL {
			if needed <= size {
				size *= 2
			} else {
				size = needed
			}
			continue
		}
		if err != nil {
			return 0, 0, fmt.Errorf("process snapshot unavailable")
		}
		if needed > 0 && needed <= size {
			buffer = buffer[:needed]
		}
		break
	}
	return parseProcessSnapshot(buffer, parent)
}

func parseProcessSnapshot(buffer []byte, parent uint32) (uint32, uint64, error) {
	var found uint32
	var created uint64
	offset := 0
	minimum := int(unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{}))
	for {
		if offset < 0 || offset+minimum > len(buffer) {
			return 0, 0, fmt.Errorf("invalid process snapshot")
		}
		entry := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))
		if entry.InheritedFromUniqueProcessID == uintptr(parent) {
			if found != 0 || entry.UniqueProcessID == 0 || uint64(entry.UniqueProcessID) > uint64(^uint32(0)) || entry.CreateTime <= 0 {
				return 0, 0, fmt.Errorf("ambiguous service child")
			}
			found = uint32(entry.UniqueProcessID)
			created = uint64(entry.CreateTime)
		}
		next := int(entry.NextEntryOffset)
		if next == 0 {
			break
		}
		if next < minimum || next%int(unsafe.Alignof(windows.SYSTEM_PROCESS_INFORMATION{})) != 0 || next > len(buffer)-offset {
			return 0, 0, fmt.Errorf("invalid process snapshot offset")
		}
		offset += next
	}
	if found == 0 {
		return 0, 0, fmt.Errorf("service child unavailable")
	}
	return found, created, nil
}
func validProcessAssociation(first, opened, second uint32, hostCreated, nodeCreated, firstCreated, secondCreated uint64, hostState, nodeState uint32) bool {
	return first != 0 && first == opened && first == second && hostCreated != 0 && nodeCreated >= hostCreated && nodeCreated == firstCreated && nodeCreated == secondCreated && hostState == uint32(windows.WAIT_TIMEOUT) && nodeState == uint32(windows.WAIT_TIMEOUT)
}

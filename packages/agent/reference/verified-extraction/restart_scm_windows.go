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
	if status.State == svc.Stopped {
		return nil
	}
	if status.State != svc.Running || status.ProcessId == 0 {
		return fmt.Errorf("ambiguous service state")
	}
	host, node, err := captureServiceProcesses(status.ProcessId, c.app)
	if err != nil {
		return err
	}
	c.old = append(c.old, host, node)
	status2, err := c.service.Query()
	if err != nil || status2.State != svc.Running || status2.ProcessId != status.ProcessId {
		return fmt.Errorf("service changed during inspection")
	}
	_, err = c.service.Control(svc.Stop)
	return err
}
func (c *nativeRestartController) WaitStoppedAndOldProcessesExited(ctx context.Context) error {
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
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fail(err)
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = windows.Process32First(snapshot, &entry)
	var childPID uint32
	for err == nil {
		if entry.ParentProcessID == hostPID {
			if childPID != 0 {
				return fail(fmt.Errorf("unexpected multiple service children"))
			}
			childPID = entry.ProcessID
		}
		err = windows.Process32Next(snapshot, &entry)
	}
	if err != nil && !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return fail(err)
	}
	if childPID == 0 {
		return fail(fmt.Errorf("service child unavailable"))
	}
	node, err := openSystemProcess(childPID, filepath.Join(app, "runtime", runtime.GOARCH, "node.exe"))
	if err != nil {
		return fail(err)
	}
	state, err := windows.WaitForSingleObject(host, 0)
	if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		windows.CloseHandle(node)
		return fail(fmt.Errorf("service host exited"))
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

//go:build windows

package verifiedextraction

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type jobAccounting struct {
	totalUserTime, totalKernelTime, periodUserTime, periodKernelTime               int64
	totalPageFaultCount, totalProcesses, activeProcesses, totalTerminatedProcesses uint32
}

// runContained terminates the Windows job on completion or cancellation. Job
// accounting does not prove that all processes, including WMI/SCM actors, have
// exited; callers must quarantine every path that the child could access.
func runContained(ctx context.Context, cmd *exec.Cmd) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create process job: %w", err)
	}
	defer windows.CloseHandle(job)
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return fmt.Errorf("configure process job: %w", err)
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	if err = cmd.Start(); err != nil {
		return err
	}
	// Until assignment succeeds the only child is suspended and cannot create
	// descendants. Terminate it and wait if any setup step fails.
	attached := false
	defer func() {
		if !attached {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("open suspended process: %w", err)
	}
	err = windows.AssignProcessToJobObject(job, process)
	windows.CloseHandle(process)
	if err != nil {
		return fmt.Errorf("assign suspended process to job: %w", err)
	}
	attached = true
	// Termination is best effort. Protected staging must remain quarantined even
	// when this succeeds: external actors and process teardown can outlive it.
	defer func() {
		_ = windows.TerminateJobObject(job, 1)
	}()
	thread, err := primaryThread(uint32(cmd.Process.Pid))
	if err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = cmd.Wait()
		return err
	}
	prior, resumeErr := windows.ResumeThread(thread)
	windows.CloseHandle(thread)
	if resumeErr != nil || prior != 1 {
		_ = windows.TerminateJobObject(job, 1)
		_ = cmd.Wait()
		return fmt.Errorf("resume suspended process (count %d): %v", prior, resumeErr)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
		return err
	case <-ctx.Done():
		// Terminate members on a best-effort basis and wait only for the direct
		// child. Protected paths remain quarantined regardless of this result.
		return waitCanceledChild(ctx.Err(), done, func() error { return windows.TerminateJobObject(job, 1) }, func() {
			fmt.Fprintln(os.Stderr, "agent launcher: process job termination failed; protected staging remains locked while waiting for the installer")
		})
	}
}

// Do not return on a failed termination: RunCandidate retains its locked
// staging until the direct child has exited. Surface the failure afterwards;
// neither a successful call nor child exit proves SCM/WMI actors have ended.
func waitCanceledChild(cause error, done <-chan error, terminate func() error, report func()) error {
	err := terminate()
	if err != nil {
		report()
	}
	<-done
	if err != nil {
		return errors.Join(cause, fmt.Errorf("process job termination failed: %w", err))
	}
	return cause
}

func primaryThread(pid uint32) (windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, fmt.Errorf("enumerate suspended thread: %w", err)
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	err = windows.Thread32First(snapshot, &entry)
	var id uint32
	for err == nil {
		if entry.OwnerProcessID == pid {
			if id != 0 {
				return 0, fmt.Errorf("suspended process has multiple threads")
			}
			id = entry.ThreadID
		}
		err = windows.Thread32Next(snapshot, &entry)
	}
	if err != windows.ERROR_NO_MORE_FILES {
		return 0, fmt.Errorf("enumerate suspended thread: %w", err)
	}
	if id == 0 {
		return 0, fmt.Errorf("suspended process thread missing")
	}
	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, id)
	if err != nil {
		return 0, fmt.Errorf("open suspended thread: %w", err)
	}
	return thread, nil
}

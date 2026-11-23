//go:build windows

package verifiedextraction

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type jobAccounting struct {
	totalUserTime, totalKernelTime, periodUserTime, periodKernelTime               int64
	totalPageFaultCount, totalProcesses, activeProcesses, totalTerminatedProcesses uint32
}

// ProcessJob owns a non-inheritable Windows job with kill-on-close and no
// breakaway. It covers its member processes, including normally spawned
// descendants. External work delegated through SCM or WMI is outside the job.
type ProcessJob struct {
	handle     windows.Handle
	processes  []windows.Handle
	prepared   bool
	prepareErr error
}

var isProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// StartProcessInJob assigns a suspended child before it can execute. On
// success the caller must wait on cmd and close the job.
func StartProcessInJob(ctx context.Context, cmd *exec.Cmd, beforeResume func() error) (*ProcessJob, error) {
	return startProcessInJob(ctx, cmd, beforeResume, 5*time.Second)
}

func startProcessInJob(ctx context.Context, cmd *exec.Cmd, beforeResume func() error, failedStartWait time.Duration) (_ *ProcessJob, startErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create process job: %w", err)
	}
	job := &ProcessJob{handle: handle}
	started := false
	defer func() {
		if !started {
			job.Close()
		}
	}()
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(handle, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, fmt.Errorf("configure process job: %w", err)
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() {
		if started {
			return
		}
		terminateErr := job.Terminate()
		job.Close()                   // Apply kill-on-close before waiting, even if termination failed.
		killErr := cmd.Process.Kill() // The child may not belong to the job yet.
		if failedStartWait == 0 {
			_ = cmd.Wait()
			return
		}
		reaped := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(reaped)
		}()
		timer := time.NewTimer(failedStartWait)
		defer timer.Stop()
		select {
		case <-reaped:
		case <-timer.C:
			startErr = errors.Join(startErr, terminateErr, killErr, fmt.Errorf("suspended child cleanup unverified"))
		}
	}()
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		return nil, fmt.Errorf("open suspended process: %w", err)
	}
	err = windows.AssignProcessToJobObject(handle, process)
	_ = windows.CloseHandle(process)
	if err != nil {
		return nil, fmt.Errorf("assign suspended process to job: %w", err)
	}
	thread, err := primaryThread(uint32(cmd.Process.Pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(thread)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if beforeResume != nil {
		if err := beforeResume(); err != nil {
			return nil, err
		}
	}
	prior, err := windows.ResumeThread(thread)
	if err != nil || prior != 1 {
		return nil, fmt.Errorf("resume suspended process (count %d): %v", prior, err)
	}
	started = true
	return job, nil
}

func (j *ProcessJob) Close() {
	for _, process := range j.processes {
		_ = windows.CloseHandle(process)
	}
	j.processes = nil
	if j.handle != 0 {
		_ = windows.CloseHandle(j.handle)
		j.handle = 0
	}
}

// Terminate requests immediate termination without waiting for job accounting.
func (j *ProcessJob) Terminate() error {
	return windows.TerminateJobObject(j.handle, 1)
}

// PrepareStop fences new child starts and retains the current job members.
// The job's owning caller must serialize this with Terminate, Stop and Close.
func (j *ProcessJob) PrepareStop() error {
	if !j.prepared {
		j.prepared = true
		j.prepareErr = j.retainProcesses()
	}
	return j.prepareErr
}

func (j *ProcessJob) retainProcesses() error {
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	// A process that could start another child already occupies this slot.
	limits.BasicLimitInformation.ActiveProcessLimit = 1
	if _, err := windows.SetInformationJobObject(j.handle, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return fmt.Errorf("fence process job starts: %w", err)
	}
	var list struct {
		assigned uint32
		count    uint32
		pids     [256]uintptr
	}
	if err := windows.QueryInformationJobObject(j.handle, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&list)), uint32(unsafe.Sizeof(list)), nil); err != nil {
		return fmt.Errorf("list contained processes: %w", err)
	}
	if list.count != list.assigned || list.count > uint32(len(list.pids)) {
		return fmt.Errorf("incomplete contained process inventory")
	}
	for _, pid := range list.pids[:list.count] {
		process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return fmt.Errorf("retain contained process %d: %w", pid, err)
		}
		j.processes = append(j.processes, process)
		var member uint32
		ok, _, err := isProcessInJob.Call(uintptr(process), uintptr(j.handle), uintptr(unsafe.Pointer(&member)))
		if ok == 0 {
			return fmt.Errorf("verify contained process %d: %w", pid, err)
		}
		if member == 0 {
			return fmt.Errorf("process %d no longer belongs to the job", pid)
		}
	}
	return nil
}

// Stop verifies both job accounting and the exit of each retained member.
func (j *ProcessJob) Stop(timeout time.Duration) error {
	prepareErr := j.PrepareStop()
	if err := j.Terminate(); err != nil {
		return errors.Join(prepareErr, fmt.Errorf("terminate process job: %w", err))
	}
	deadline := time.Now().Add(timeout)
	for {
		var count jobAccounting
		if err := windows.QueryInformationJobObject(j.handle, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&count)), uint32(unsafe.Sizeof(count)), nil); err != nil {
			return fmt.Errorf("query process job accounting: %w", err)
		}
		if count.activeProcesses == 0 {
			drained := true
			for _, process := range j.processes {
				state, err := windows.WaitForSingleObject(process, 0)
				if err != nil {
					return errors.Join(prepareErr, fmt.Errorf("wait for contained process: %w", err))
				}
				if state != windows.WAIT_OBJECT_0 {
					drained = false
					break
				}
			}
			if drained {
				return prepareErr
			}
		}
		if !time.Now().Before(deadline) {
			return errors.Join(prepareErr, fmt.Errorf("process job did not drain (%d active)", count.activeProcesses))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func runContained(ctx context.Context, cmd *exec.Cmd, beforeResume func() error) error {
	// The installer must retain protected staging until its direct child exits.
	job, err := startProcessInJob(ctx, cmd, beforeResume, 0)
	if err != nil {
		return err
	}
	defer job.Close()
	defer job.Terminate()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// External actors may remain active. Keep protected paths quarantined.
		return waitCanceledChild(ctx.Err(), done, job.Terminate, func() {
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

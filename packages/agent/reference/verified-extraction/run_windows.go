//go:build windows

package verifiedextraction

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RunResult distinguishes the installer's result from the mandatory manual
// reconciliation of paths potentially used by out-of-job processes.
type RunResult struct {
	InstallerErr   error
	CleanupPending bool
}

type preparedForRun interface {
	BeginExecutionIntent(string) (ExecutionIntent, error)
	InstallerPath() (string, error)
	Cleanup() error
	Close()
}
type scratchForRun interface {
	Root() string
	BeginScratchIntent(string, string, string, string) error
	Cleanup() error
	Close()
}
type executionDependencies struct {
	nativeArch        func() (string, error)
	prepare           func(Candidate) (preparedForRun, error)
	scratch           func() (scratchForRun, error)
	beginGuard        func(context.Context) (func() error, error)
	scmDigest         func() (string, error)
	invoke            func(context.Context, string, string, []string, string, string, string) error
	abortBeforeInvoke func(preparedForRun, scratchForRun, ExecutionIntent) error
}

// RunCandidate requires the caller to independently authenticate the launcher
// executable and select trusted publisher pins before it starts. It must only
// be used with an installer that honors the shared install mutex and the
// protected-intent recovery protocol. Quarantine always requires reconciliation.
func RunCandidate(ctx context.Context, candidate Candidate, args []string, token string) (RunResult, error) {
	d := executionDependencies{
		nativeArch: nativeSystemArchitecture,
		prepare:    func(c Candidate) (preparedForRun, error) { return PrepareCandidate(c) },
		scratch:    func() (scratchForRun, error) { return NewPrivateStaging() },
		beginGuard: beginInstallGuard,
		scmDigest:  currentSCMDigest,
		invoke:     invokeInstaller,
		abortBeforeInvoke: func(p preparedForRun, s scratchForRun, intent ExecutionIntent) error {
			return abortBeforeInvocation(p.(*Prepared).staging, s.(*PrivateStaging), intent)
		},
	}
	return runCandidate(ctx, candidate, args, token, d)
}

// runCandidate keeps both private directories on every path after either
// intent may have been created. WMI and SCM can outlive the original process,
// so neither normal exit nor job termination authorizes automatic deletion.
func runCandidate(ctx context.Context, candidate Candidate, args []string, token string, d executionDependencies) (result RunResult, err error) {
	if d.nativeArch == nil || d.prepare == nil || d.scratch == nil || d.beginGuard == nil || d.scmDigest == nil || d.invoke == nil {
		return result, fmt.Errorf("incomplete execution dependencies")
	}
	nativeArch, err := d.nativeArch()
	if err != nil {
		return result, err
	}
	if candidate.Architecture != runtime.GOARCH || candidate.Architecture != nativeArch {
		return result, fmt.Errorf("launcher and package architectures differ")
	}
	p, err := d.prepare(candidate)
	if err != nil {
		return result, err
	}
	var scratch scratchForRun
	attempted := false
	defer func() {
		if attempted {
			result.CleanupPending = true
			if scratch != nil {
				scratch.Close()
			}
			p.Close()
			return
		}
		if scratch != nil {
			if e := scratch.Cleanup(); e != nil {
				scratch.Close()
				err = fmt.Errorf("%v; scratch cleanup: %w", err, e)
			}
		}
		if p == nil {
			return
		}
		if e := p.Cleanup(); e != nil {
			p.Close()
			err = fmt.Errorf("%v; payload cleanup: %w", err, e)
		}
	}()
	scratch, err = d.scratch()
	if err != nil {
		return result, err
	}
	release, err := d.beginGuard(ctx)
	if err != nil {
		return result, err
	}
	if release == nil {
		return result, fmt.Errorf("install guard unavailable")
	}
	guardHeld := true
	defer func() {
		if guardHeld {
			if e := release(); e != nil {
				err = fmt.Errorf("%v; release install guard: %w", err, e)
			}
		}
	}()
	scmDigest, err := d.scmDigest()
	if err != nil {
		return result, fmt.Errorf("inspect service before execution: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	attempted = true
	intent, err := p.BeginExecutionIntent(scmDigest)
	if err != nil {
		return result, fmt.Errorf("protected intent not established: %w", err)
	}
	if !stageNamePattern.MatchString("TokenTimer-Staging-" + intent.Transaction) {
		return result, fmt.Errorf("invalid protected intent transaction")
	}
	if err := scratch.BeginScratchIntent(intent.ArchiveSHA256, scmDigest, intent.Transaction, intent.Secret); err != nil {
		return result, fmt.Errorf("scratch intent not established: %w", err)
	}
	if err := ctx.Err(); err != nil && d.abortBeforeInvoke != nil {
		if cleanupErr := d.abortBeforeInvoke(p, scratch, intent); cleanupErr == nil {
			attempted = false
			scratch = nil
			p = nil
			return result, err
		}
		return result, fmt.Errorf("%w; pre-invocation cleanup failed; quarantine retained", err)
	}
	if err := release(); err != nil {
		guardHeld = false
		return result, fmt.Errorf("release install guard: %w", err)
	}
	guardHeld = false
	installer, err := p.InstallerPath()
	if err != nil {
		return result, err
	}
	result.InstallerErr = d.invoke(ctx, installer, scratch.Root(), args, token, intent.Transaction, intent.Secret)
	return result, nil
}

func beginInstallGuard(ctx context.Context) (func() error, error) {
	// Windows mutex ownership belongs to an OS thread, not a Go goroutine.
	runtime.LockOSThread()
	h, err := lockInstall(ctx)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	parent, err := nativeProgramFiles()
	if err == nil {
		err = assertNoPendingExecution(parent)
	}
	if err != nil {
		_ = unlockInstall(h)
		runtime.UnlockOSThread()
		return nil, err
	}
	return func() error { err := unlockInstall(h); runtime.UnlockOSThread(); return err }, nil
}

func (s *PrivateStaging) BeginScratchIntent(archive, scm, transaction, secret string) error {
	if err := s.LockPayload(); err != nil {
		return err
	}
	_, err := s.beginExecutionIntentForTransaction(archive, scm, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", transaction, secret, defaultIntentIO())
	return err
}

func systemPowerShellPath() (string, string, error) {
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", "", err
	}
	return filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe"), systemDir, nil
}

func invokeInstaller(ctx context.Context, installer, scratch string, args []string, token, transaction, secret string) error {
	if !digest.MatchString(secret) {
		return fmt.Errorf("invalid protected execution secret")
	}
	var readPipe, writePipe windows.Handle
	if err := windows.CreatePipe(&readPipe, &writePipe, nil, 0); err != nil {
		return err
	}
	defer windows.CloseHandle(readPipe)
	defer windows.CloseHandle(writePipe)
	if err := windows.SetHandleInformation(readPipe, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		return err
	}
	var written uint32
	if err := windows.WriteFile(writePipe, []byte(secret), &written, nil); err != nil || written != uint32(len(secret)) {
		return fmt.Errorf("protected intent pipe unavailable")
	}
	ps, systemDir, err := systemPowerShellPath()
	if err != nil {
		return err
	}
	argv := append([]string{"-NoProfile", "-File", installer}, args...)
	cmd := exec.Command(ps, argv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(readPipe)}}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Dir = filepath.Dir(installer)
	root := filepath.Dir(systemDir)
	architecture := "AMD64"
	if runtime.GOARCH == "arm64" {
		architecture = "ARM64"
	}
	cmd.Env = []string{"SystemRoot=" + root, "WINDIR=" + root, "PATH=" + systemDir + string(os.PathListSeparator) + filepath.Dir(ps), "PATHEXT=.COM;.EXE;.BAT;.CMD", "PSModulePath=" + filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "Modules"), "TEMP=" + scratch, "TMP=" + scratch, "PROCESSOR_ARCHITECTURE=" + architecture, "TOKENTIMER_AGENT_EXECUTION_INTENT=" + transaction, "TOKENTIMER_AGENT_INTENT_HANDLE=" + strconv.FormatUint(uint64(readPipe), 10)}
	if token != "" {
		cmd.Env = append(cmd.Env, "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN="+token)
	}
	return runContained(ctx, cmd)
}

type systemInfo struct {
	architecture                                             uint16
	reserved                                                 uint16
	pageSize                                                 uint32
	minimumAddress, maximumAddress, activeProcessorMask      uintptr
	numberOfProcessors, processorType, allocationGranularity uint32
	processorLevel, processorRevision                        uint16
}

func nativeSystemArchitecture() (string, error) {
	var info systemInfo
	syscall.NewLazyDLL("kernel32.dll").NewProc("GetNativeSystemInfo").Call(uintptr(unsafe.Pointer(&info)))
	switch info.architecture {
	case 9:
		return "amd64", nil
	case 12:
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported native Windows architecture")
	}
}

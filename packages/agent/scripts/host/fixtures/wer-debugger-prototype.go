//go:build windows

// Diagnostic only: runs a fresh benign child without reading its memory.
// This is not a production service-host implementation.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type debugEvent struct {
	Code, ProcessID, ThreadID uint32
	Data                      [20]uintptr // 64-bit DEBUG_EVENT union, aligned at byte 16
}

func run() error {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("CERTOPS_WER_EXPERIMENTAL_PROBE") != "1" {
		return fmt.Errorf("disposable experimental host required")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid.String() != "S-1-5-18" {
		return fmt.Errorf("SYSTEM required")
	}
	if len(os.Args) != 3 || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return fmt.Errorf("expected native executable and bounded benign mode")
	}
	if unsafe.Sizeof(debugEvent{}) != 176 || unsafe.Offsetof(debugEvent{}.Data) != 16 {
		return fmt.Errorf("unsupported native debug event layout")
	}
	scripts := map[string]string{"abort": "process.abort()", "exit17": "process.exit(17)", "exit86": "process.exit(86)", "handled": "try{throw Error('benign')}catch{};process.exit(0)"}
	script, ok := scripts[os.Args[2]]
	if !ok {
		return fmt.Errorf("unknown diagnostic mode")
	}
	// A debugger must create and pump events on the same native thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	application, err := windows.UTF16PtrFromString(os.Args[1])
	if err != nil {
		return err
	}
	line, err := windows.UTF16PtrFromString(strings.Join([]string{syscall.EscapeArg(os.Args[1]), "-e", syscall.EscapeArg(script)}, " "))
	if err != nil {
		return err
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var process windows.ProcessInformation
	// The caller passes only a minimal, non-agent environment to this helper.
	if err := windows.CreateProcess(application, line, nil, nil, false, 0x2|windows.CREATE_NO_WINDOW, nil, nil, &startup, &process); err != nil {
		return fmt.Errorf("benign debug child creation failed")
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	completed := false
	defer func() {
		if !completed {
			_ = windows.TerminateProcess(process.Process, 1)
		}
	}()
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	wait := kernel.NewProc("WaitForDebugEvent")
	resume := kernel.NewProc("ContinueDebugEvent")
	deadline := time.Now().Add(60 * time.Second)
	initialBreakpoint := true
	secondChance := false
	for time.Now().Before(deadline) {
		var event debugEvent
		success, _, waitErr := wait.Call(uintptr(unsafe.Pointer(&event)), 1000)
		if success == 0 {
			if waitErr == syscall.Errno(121) { // ERROR_SEM_TIMEOUT
				continue
			}
			return fmt.Errorf("debug event wait failed")
		}
		if event.ProcessID != process.ProcessId {
			return fmt.Errorf("unexpected diagnostic child identity")
		}
		status := uintptr(0x00010002) // DBG_CONTINUE
		switch event.Code {
		case 3, 6: // CREATE_PROCESS / LOAD_DLL: only image file handle is ours to close.
			if event.Data[0] != 0 {
				_ = windows.CloseHandle(windows.Handle(event.Data[0]))
			}
		case 1: // EXCEPTION_DEBUG_EVENT
			code := *(*uint32)(unsafe.Pointer(&event.Data[0]))
			firstChance := *(*uint32)(unsafe.Add(unsafe.Pointer(&event.Data[0]), 152))
			if code == 0x80000003 && firstChance == 1 && initialBreakpoint {
				initialBreakpoint = false
			} else if firstChance == 0 {
				secondChance = true
				if err := windows.TerminateProcess(process.Process, 1); err != nil {
					return fmt.Errorf("second-chance termination failed")
				}
			} else {
				status = 0x80010001 // DBG_EXCEPTION_NOT_HANDLED: preserve child handlers.
			}
		}
		continued, _, _ := resume.Call(uintptr(event.ProcessID), uintptr(event.ThreadID), status)
		if continued == 0 {
			return fmt.Errorf("debug event continuation failed")
		}
		if event.Code == 5 { // EXIT_PROCESS_DEBUG_EVENT
			completed = true
			code := uint32(event.Data[0])
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"diagnosticOnly": true, "mode": os.Args[2], "secondChanceTerminated": secondChance, "childExitCode": code, "productionQualified": false})
		}
	}
	return fmt.Errorf("bounded diagnostic debug loop expired")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

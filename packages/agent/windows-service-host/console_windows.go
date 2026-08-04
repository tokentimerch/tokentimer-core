//go:build windows

package main

// AttachConsole/FreeConsole/SetConsoleCtrlHandler are not exposed by
// golang.org/x/sys/windows (only GenerateConsoleCtrlEvent is), so they are
// bound here directly from kernel32.dll via the same LazyDLL/LazyProc
// mechanism x/sys/windows itself uses internally. This keeps the only
// dependency at build.go.mod's declared version (golang.org/x/sys) while
// still reaching the three additional kernel32 exports this host needs.
//
// Why these three calls exist at all: GenerateConsoleCtrlEvent delivers
// CTRL_BREAK_EVENT to every process in a console process group, but the
// calling process must itself be attached to a console (or a pseudo-console
// association) for the call to succeed. A Windows service runs in session 0
// with no console of its own, so without this attach/detach dance every
// GenerateConsoleCtrlEvent call from the service fails with
// ERROR_INVALID_HANDLE. Attaching to the child's console group (the child
// was started with CREATE_NEW_PROCESS_GROUP, so it has one even though
// nothing ever allocated a visible window), sending the event, then
// detaching again is the documented workaround and is the same technique
// other Windows service wrappers use to deliver a soft-stop signal to a
// console-subsystem child.

import (
	"golang.org/x/sys/windows"
)

var (
	modkernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole             = modkernel32.NewProc("AttachConsole")
	procFreeConsole               = modkernel32.NewProc("FreeConsole")
	procSetConsoleCtrlHandlerProc = modkernel32.NewProc("SetConsoleCtrlHandler")
)

// attachConsole attaches the calling process to the console of the process
// group identified by pid. Passing 0xFFFFFFFF (ATTACH_PARENT_PROCESS) is not
// used here; this always attaches to a specific child's group.
func attachConsole(pid uint32) error {
	r1, _, err := procAttachConsole.Call(uintptr(pid))
	if r1 == 0 {
		return err
	}
	return nil
}

// freeConsole detaches the calling process from whatever console it is
// currently attached to. Safe to call even if not attached to anything.
func freeConsole() error {
	r1, _, err := procFreeConsole.Call()
	if r1 == 0 {
		return err
	}
	return nil
}

// ignoreOwnConsoleCtrlEvents installs the "no handler" ctrl handler for this
// process (SetConsoleCtrlHandler(NULL, TRUE)), so the CTRL_BREAK_EVENT this
// host is about to raise for the child's process group does not also cause
// the host's own process to react to it while briefly attached to that
// group's pseudo-console.
func ignoreOwnConsoleCtrlEvents(ignore bool) error {
	var setIgnore uintptr
	if ignore {
		setIgnore = 1
	}
	r1, _, err := procSetConsoleCtrlHandlerProc.Call(0, setIgnore)
	if r1 == 0 {
		return err
	}
	return nil
}

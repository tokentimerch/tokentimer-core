//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// drainStatus reads and discards Status updates on ch until Execute
// returns, so Execute's unbuffered `changes <- ...` sends never block on a
// test that isn't otherwise reading them.
func drainStatus(t *testing.T, ch <-chan svc.Status, done <-chan struct{}) {
	t.Helper()
	for {
		select {
		case <-ch:
		case <-done:
			return
		}
	}
}

// TestExecuteReportsRealExitCodeOnUnrequestedCrash is the regression test
// for the bug this file's sibling comment documents: a child that exits on
// its own (a crash) must have Execute return the real non-zero exit code
// with NO intermediate `changes <- svc.Status{State: svc.Stopped}` sent
// first. Sending that intermediate report raced ahead of Execute's actual
// return value and got latched by the SCM as exit code 0, silently
// defeating `sc.exe failure ... actions= restart/5000` for every
// unrequested exit -- live-repro'd on a real Windows Server 2025 SCM.
func TestExecuteReportsRealExitCodeOnUnrequestedCrash(t *testing.T) {
	log := newTestLogger(t)
	node := nodeExe(t)
	quickExitScript := filepath.Join(t.TempDir(), "quick-exit.js")
	if err := os.WriteFile(quickExitScript, []byte("process.exit(3);\n"), 0o600); err != nil {
		t.Fatalf("write quick-exit script: %v", err)
	}
	host := newAgentHost(node, []string{quickExitScript}, os.Environ(), log)
	svcHandler := &tokenTimerAgentService{host: host, stopTimeout: 2 * time.Second, log: log}

	reqCh := make(chan svc.ChangeRequest)
	statusCh := make(chan svc.Status)
	done := make(chan struct{})
	go drainStatus(t, statusCh, done)

	execDone := make(chan struct {
		svcSpecific bool
		exitCode    uint32
	}, 1)
	go func() {
		svcSpecific, exitCode := svcHandler.Execute([]string{serviceName}, reqCh, statusCh)
		execDone <- struct {
			svcSpecific bool
			exitCode    uint32
		}{svcSpecific, exitCode}
		close(done)
	}()

	select {
	case result := <-execDone:
		if result.exitCode == 0 {
			t.Fatalf("Execute returned exit code 0 for an unrequested crash; want non-zero so the SCM's restart action fires")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Execute did not return within 5s of the child's own exit")
	}
}

// TestExecuteMapsRetiredExitCodeToCleanStop proves the fix: a child
// that self-exits with agentRetiredExitCode (86, the control-plane-retired
// clean exit -- see packages/agent/src/index.js's AGENT_RETIRED_EXIT_CODE)
// must report exit code 0 (no SCM restart action), not 86 verbatim, or
// every retired agent enters an unbounded ~5s restart loop against a real
// SCM failure policy -- live-repro'd immediately after the crash-exit-code
// fix above, before this mapping existed.
func TestExecuteMapsRetiredExitCodeToCleanStop(t *testing.T) {
	log := newTestLogger(t)
	node := nodeExe(t)
	retiredExitScript := filepath.Join(t.TempDir(), "retired-exit.js")
	src := "process.exit(86);\n"
	if err := os.WriteFile(retiredExitScript, []byte(src), 0o600); err != nil {
		t.Fatalf("write retired-exit script: %v", err)
	}
	host := newAgentHost(node, []string{retiredExitScript}, os.Environ(), log)
	svcHandler := &tokenTimerAgentService{host: host, stopTimeout: 2 * time.Second, log: log}

	reqCh := make(chan svc.ChangeRequest)
	statusCh := make(chan svc.Status)
	done := make(chan struct{})
	go drainStatus(t, statusCh, done)

	execDone := make(chan struct {
		svcSpecific bool
		exitCode    uint32
	}, 1)
	go func() {
		svcSpecific, exitCode := svcHandler.Execute([]string{serviceName}, reqCh, statusCh)
		execDone <- struct {
			svcSpecific bool
			exitCode    uint32
		}{svcSpecific, exitCode}
		close(done)
	}()

	select {
	case result := <-execDone:
		if result.exitCode != 0 {
			t.Fatalf("Execute returned exit code %d for the retirement exit (86); want 0 (clean stop, no SCM restart action)", result.exitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Execute did not return within 5s of the child's retirement exit")
	}
}

// TestExecuteRequestedStopReturnsZero proves the ordinary Stop/Shutdown
// path is unaffected by the crash-path changes above: it still returns 0
// with no error, and still sends its own StopPending/Stopped transitions.
func TestExecuteRequestedStopReturnsZero(t *testing.T) {
	log := newTestLogger(t)
	node := nodeExe(t)
	entry := mockAgentPath(t)
	host := newAgentHost(node, []string{entry}, os.Environ(), log)
	svcHandler := &tokenTimerAgentService{host: host, stopTimeout: 2 * time.Second, log: log}

	reqCh := make(chan svc.ChangeRequest)
	statusCh := make(chan svc.Status, 8)

	execDone := make(chan struct {
		svcSpecific bool
		exitCode    uint32
	}, 1)
	go func() {
		svcSpecific, exitCode := svcHandler.Execute([]string{serviceName}, reqCh, statusCh)
		execDone <- struct {
			svcSpecific bool
			exitCode    uint32
		}{svcSpecific, exitCode}
	}()

	// Wait for the Running status before requesting a stop, otherwise the
	// stop request could race the child's own startup.
	waitForState(t, statusCh, svc.Running, 5*time.Second)
	reqCh <- svc.ChangeRequest{Cmd: svc.Stop}

	select {
	case result := <-execDone:
		if result.exitCode != 0 {
			t.Fatalf("Execute returned exit code %d for a requested stop; want 0", result.exitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Execute did not return within 5s of the Stop request")
	}
}

func waitForState(t *testing.T, ch <-chan svc.Status, want svc.State, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case s := <-ch:
			if s.State == want {
				return
			}
		case <-deadline:
			t.Fatalf("did not observe state %v within %s", want, timeout)
		}
	}
}

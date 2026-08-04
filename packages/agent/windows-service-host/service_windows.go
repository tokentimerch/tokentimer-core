//go:build windows

package main

import (
	"time"

	"golang.org/x/sys/windows/svc"
)

// serviceName must equal install-agent.ps1's $ServiceName exactly: the SCM
// dispatcher table windows/svc builds from Execute's registration is keyed
// by this string, and a mismatch here means StartServiceCtrlDispatcher
// simply never routes control requests to this process at all - the exact
// silent failure mode this host exists to eliminate.
const serviceName = "TokenTimerAgent"

// tokenTimerAgentService implements svc.Handler. It owns no state of its
// own beyond the already-started agentHost and stop timeout; every actual
// decision (how to signal the child, how long to wait) lives in host.go
// so it stays unit-testable without a real SCM.
type tokenTimerAgentService struct {
	host        *agentHost
	stopTimeout time.Duration
	log         *hostLogger
}

// Execute implements svc.Handler. Its control flow follows the documented
// SCM contract precisely:
//  1. report StartPending immediately (the SCM already granted a startup
//     window via the service's own start timeout; this host does not
//     additionally manage that budget)
//  2. start the child
//  3. report Running, accepting Stop/Shutdown/Interrogate
//  4. loop on the two events that can end the service: an SCM control
//     request, or the child exiting on its own
//  5. report StopPending, perform the graceful-then-forced stop, report
//     Stopped
func (s *tokenTimerAgentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	if err := s.host.start(); err != nil {
		s.log.Printf("service start failed: %v", err)
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	childExitCh := make(chan error, 1)
	go func() { childExitCh <- s.host.wait() }()

	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				_ = s.host.stopGracefully(s.stopTimeout)
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				// Pause/Continue/ParamChange/etc. are not offered
				// (Accepts above never advertises them), so the SCM
				// should never deliver one; if it somehow does,
				// reporting current status is the documented safe
				// response rather than silently dropping it.
				changes <- req.CurrentStatus
			}
		case err := <-childExitCh:
			// The child exited without this host asking it to: a crash,
			// or the agent's own clean self-exit. Report Stopped with a
			// non-zero specific error so SCM's configured failure
			// action (sc.exe failure ... actions= restart/5000) fires
			// exactly as it would have for a bare node.exe binPath,
			// which is the behavior the install script's failure
			// policy was already written to expect.
			exitCode := uint32(0)
			if err != nil {
				exitCode = 1
			}
			s.log.Printf("child exited without a stop request (err=%v); stopping service so the configured failure action can react", err)
			changes <- svc.Status{State: svc.Stopped}
			return false, exitCode
		}
	}
}

// runAsService blocks for the lifetime of the service by calling
// svc.Run, which internally calls StartServiceCtrlDispatcher and blocks
// until Execute returns.
func runAsService(host *agentHost, stopTimeout time.Duration, log *hostLogger) {
	handler := &tokenTimerAgentService{host: host, stopTimeout: stopTimeout, log: log}
	if err := svc.Run(serviceName, handler); err != nil {
		log.Printf("svc.Run failed: %v", err)
	}
}

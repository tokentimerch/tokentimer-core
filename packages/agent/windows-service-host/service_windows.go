//go:build windows

package main

import (
	"errors"
	"os/exec"
	"time"

	"golang.org/x/sys/windows/svc"
)

// Default dispatcher registration label matches install-agent.ps1. Windows
// ignores the SERVICE_TABLE_ENTRY name for SERVICE_WIN32_OWN_PROCESS, but the
// host must still call StartServiceCtrlDispatcher and report its lifecycle.
// Qualification uses a temporary Go source overlay for a uniquely named
// disposable SCM service without changing this released default.
const serviceName = "TokenTimerAgent"

// agentRetiredExitCode must equal AGENT_RETIRED_EXIT_CODE in
// packages/agent/src/index.js: the agent's own deliberate, clean self-exit
// when the control plane has retired it (heartbeat HTTP 410), so it never
// respawns into a heartbeat 410 loop. The Linux systemd unit pairs
// `Restart=always` with `RestartPreventExitStatus=86` to name this one
// exit code as "not a failure, don't restart" while still restarting on
// every other (genuinely crashed) exit.
//
// Live-repro'd on a real Windows
// Server 2025 SCM: `sc.exe failure ... actions= restart/5000` has no
// per-exit-code exemption at all, unlike systemd's
// RestartPreventExitStatus -- every non-zero Win32ExitCode this host
// reports, retirement included, is "a failure" to the SCM. Once the
// sibling bug above (silently reporting exit code 0 for every
// unrequested exit, real crash or not) was fixed so a real crash
// actually triggers the configured restart, a retire immediately became
// a live crash-restart loop: node exits 86, SCM restarts it 5s later, it
// heartbeats again, gets 410 again, exits 86 again -- observed
// hammering the control plane every ~6s indefinitely in this host's own
// log until manually stopped. This constant is this host's only
// substitute for RestartPreventExitStatus: it maps this one specific
// exit code to a reported Win32ExitCode of 0 (success, no failure
// action), while every other non-zero exit still reports through
// unchanged and still restarts.
const agentRetiredExitCode = 86

// tokenTimerAgentService implements svc.Handler. It owns no state of its
// own beyond the already-started agentHost and stop timeout; every actual
// decision (how to signal the child, how long to wait) lives in host.go
// so it stays unit-testable without a real SCM.
type tokenTimerAgentService struct {
	host            *agentHost
	stopTimeout     time.Duration
	log             *hostLogger
	openObservation func() (serviceObservation, error)
	observationRun  string
	observationDir  string
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

	var lost <-chan error
	var admission *observedAdmission
	if s.openObservation == nil {
		if err := s.host.start(); err != nil {
			s.log.Printf("service start failed: %v", err)
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
		}
	} else {
		observer, err := s.openObservation()
		if err != nil {
			s.log.Printf("required observation unavailable; worker not started: %v", err)
			return false, 0
		}
		defer observer.close()
		if err := observer.check(); err != nil {
			s.log.Printf("required observation unavailable; worker not started: %v", err)
			return false, 0
		}
		if err := observer.reserve(); err != nil {
			s.log.Printf("observation run not admitted; worker not started: %v", err)
			return false, 0
		}
		admission = &observedAdmission{observer: observer, failure: make(chan error, 1), onLoss: s.host.interruptObservedChild}
		var binding string
		if s.observationRun != "" {
			journal, release, err := openAdmissionJournal(s.observationDir, s.observationRun)
			if err != nil {
				s.log.Printf("observation journal unavailable; worker not started: %v", err)
				return false, 0
			}
			defer release()
			defer journal.Close()
			broker, err := startAdmissionBroker(admission, s.observationRun, journal, s.host.pid)
			if err != nil {
				s.log.Printf("observation admission unavailable; worker not started: %v", err)
				return false, 0
			}
			defer broker.close()
			binding = broker.binding()
		}
		armed := make(chan struct{})
		stop := make(chan struct{})
		done := make(chan struct{})
		go watchServiceObservation(admission, armed, stop, done)
		defer func() {
			close(stop)
			<-done
		}()
		if err := s.host.startChild(func() error {
			if err := admission.check(); err != nil {
				return err
			}
			close(armed)
			return nil
		}, binding); err != nil {
			s.log.Printf("observed worker start refused: %v", err)
			return false, 0
		}
		lost = admission.failure
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
				if admission != nil {
					admission.revoke()
					s.stopObserved(changes, lost)
					return false, 0
				}
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
		case err := <-lost:
			s.stopObserved(changes, nil)
			s.log.Printf("required observation lost: %v", err)
			return false, 0
		case err := <-childExitCh:
			if admission != nil {
				admission.revoke()
				s.stopObserved(changes, nil)
				s.log.Printf("observed worker exited; new observation run required: %v", err)
				return false, 0
			}
			// The child exited without this host asking it to: a crash,
			// or the agent's own clean self-exit (including the
			// AGENT_RETIRED_EXIT_CODE=86 self-exit paired with
			// RestartPreventExitStatus=86 in the Linux systemd unit).
			// This must report Stopped with a non-zero specific error
			// so SCM's configured failure action (sc.exe failure
			// ... actions= restart/5000) fires exactly as it would have
			// for a bare node.exe binPath -- which is the behavior the
			// install script's failure policy was already written to
			// expect, and the only thing that makes an unattended
			// service self-heal from a real crash at all.
			//
			// Live-repro'd against
			// a real Windows Server 2025 SCM: sending
			// `changes <- svc.Status{State: svc.Stopped}` here (as this
			// code previously did) reports the FIRST of two Stopped
			// transitions with exit code 0 -- ec is {isSvcSpecific:
			// true, errno: 0} in golang.org/x/sys/windows/svc's
			// serviceMain loop until AFTER Execute returns, so that
			// manual send always races ahead of this function's actual
			// return value. The SCM latches onto that first report
			// (confirmed live: `Get-CimInstance Win32_Service` and
			// `sc.exe` both showed ExitCode=0 after a real crash, and no
			// restart ever fired despite `actions= restart/5000` and
			// FailureActionsOnNonCrashFailures=TRUE being verified
			// correctly configured) and never acts on the second,
			// correct-exit-code Stopped report serviceMain sends
			// automatically once Execute returns -- silently defeating
			// the install script's entire crash-recovery contract for
			// every unrequested exit, not just retirement. The fix:
			// never send an intermediate Stopped status from this
			// branch at all; return directly and let serviceMain's own
			// post-Execute updateStatus call be the one and only Stopped
			// report, carrying the real exit code the whole way through.
			exitCode := uint32(0)
			if err != nil {
				exitCode = 1
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
					exitCode = uint32(exitErr.ExitCode())
				}
			}
			if exitCode == agentRetiredExitCode {
				s.log.Printf("child exited with the retirement code (%d); stopping service cleanly, not as a failure, so it does not respawn into a heartbeat-410 loop", agentRetiredExitCode)
				return false, 0
			}
			s.log.Printf("child exited without a stop request (err=%v); stopping service (exit %d) so the configured failure action can react", err, exitCode)
			return false, exitCode
		}
	}
}

// watchServiceObservation keeps one session and never reconnects after loss.
func watchServiceObservation(admission *observedAdmission, armed, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	select {
	case <-armed:
	case <-stop:
		return
	}
	ticker := time.NewTicker(observationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := admission.check(); err != nil {
				return
			}
		}
	}
}

// stopObserved honors a requested graceful stop only while observation is
// available. Every path then terminates and checks the job, even if Node exited.
func (s *tokenTimerAgentService) stopObserved(changes chan<- svc.Status, lost <-chan error) {
	fenced := s.host.prepareObservedStop()
	changes <- svc.Status{State: svc.StopPending}
	var observationErr error
	if lost != nil && fenced {
		select {
		case observationErr = <-lost:
		case <-s.host.exited:
		default:
			if err := s.host.sendCtrlBreak(s.host.pid()); err == nil {
				timer := time.NewTimer(s.stopTimeout)
				select {
				case observationErr = <-lost:
				case <-s.host.exited:
				case <-timer.C:
				}
				timer.Stop()
			}
		}
	}
	if err := s.host.stopObservedChild(); err != nil {
		s.log.Printf("observed worker drainage unverified: %v", err)
	} else {
		s.log.Printf("observed job empty and retained processes exited; service stopping without automatic retry")
	}
	if observationErr != nil {
		s.log.Printf("required observation lost during SCM stop: %v", observationErr)
	}
}

// runAsService blocks for the lifetime of the service by calling
// svc.Run, which internally calls StartServiceCtrlDispatcher and blocks
// until Execute returns.
func runAsService(handler *tokenTimerAgentService) {
	log := handler.log
	if err := svc.Run(serviceName, handler); err != nil {
		log.Printf("svc.Run failed: %v", err)
	}
}

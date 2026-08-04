//go:build windows

// Command tokentimer-agent-host is the Windows Service Control Manager
// (SCM) dispatcher for the TokenTimer CertOps Agent.
//
// Why this exists: the SCM start protocol requires the process named in a
// service's binPath to call StartServiceCtrlDispatcher and answer
// start/stop/interrogate control requests itself. A plain "node.exe
// bin\tokentimer-agent.js" process never does that - Node has no SCM
// awareness - so sc.exe create/start against that binPath directly starts
// a service the SCM cannot confirm is alive, which fails after Windows'
// own service-start timeout (error 1053) and then loops on whatever
// failure/restart policy is configured. This binary is a small, purpose-
// built host that speaks the SCM protocol on the agent's behalf: it is
// what the installer's binPath now points at, and its only job is to
// register with SCM, start the real Node agent as a child process,
// forward SCM stop/shutdown requests to it as a graceful shutdown signal,
// and propagate the child's own exit if it crashes on its own (so the
// existing `sc.exe failure ... restart/5000` policy still restarts a
// crashed agent exactly as it did before this host existed).
//
// Usage (what install-agent.ps1 puts in binPath):
//
//	tokentimer-agent-host.exe <node.exe path> <agent entrypoint .js path>
//
// Everything after the host's own argv[0] is passed through to the child
// unchanged; this host has no flags of its own beyond that, on purpose -
// it must never need its own separate configuration surface distinct from
// the agent's.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows/svc"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "tokentimer-agent-host: usage: tokentimer-agent-host.exe <child-exe> [child-args...]")
		os.Exit(2)
	}
	childExe := os.Args[1]
	childArgs := os.Args[2:]

	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tokentimer-agent-host: could not determine session type: %v\n", err)
		os.Exit(1)
	}

	log := newHostLogger(os.Getenv("TOKENTIMER_AGENT_CONFIG_DIR"))
	defer log.Close()
	stopTimeout := resolveStopTimeout(os.Getenv)
	host := newAgentHost(childExe, childArgs, os.Environ(), log)

	if isService {
		runAsService(host, stopTimeout, log)
		return
	}
	os.Exit(runInteractive(host, stopTimeout, log))
}

// runInteractive supports `tokentimer-agent-host.exe <node> <entry.js>` run
// directly from a console (manual testing, or an operator diagnosing a
// service install without touching the SCM at all): it starts the child,
// forwards this process's own Ctrl+C to the child as a graceful stop, and
// exits with the child's exit status once it terminates either way.
func runInteractive(host *agentHost, stopTimeout time.Duration, log *hostLogger) int {
	if err := host.start(); err != nil {
		log.Printf("%v", err)
		return 1
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	childErrCh := make(chan error, 1)
	go func() { childErrCh <- host.wait() }()

	select {
	case <-sigCh:
		log.Printf("interactive mode: Ctrl+C received; requesting graceful child stop")
		_ = host.stopGracefully(stopTimeout)
		return 0
	case err := <-childErrCh:
		log.Printf("child exited on its own: %v", err)
		if err == nil {
			return 0
		}
		return 1
	}
}

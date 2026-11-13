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
// A service prepared from restored state also carries --prepared-server-url
// before the child path. The host applies the validated origin to the child's
// environment before starting Node.
package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
)

const preparedServerFlag = "--prepared-server-url"
const serverURLEnv = "TOKENTIMER_AGENT_SERVER_URL"
const insecureLocalHTTPEnv = "TOKENTIMER_AGENT_ALLOW_INSECURE_LOCAL_HTTP"

func parseHostLaunch(args, env []string) ([]string, []string, error) {
	if len(args) == 0 {
		return nil, nil, fmt.Errorf("missing child executable")
	}
	if args[0] != preparedServerFlag {
		return args, env, nil
	}
	if len(args) < 3 || args[2] == "" {
		return nil, nil, fmt.Errorf("prepared server origin and child executable are required")
	}
	origin := args[1]
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") ||
		parsed.Path != "" || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" ||
		strings.ContainsAny(origin, "\"#") {
		return nil, nil, fmt.Errorf("invalid prepared server origin")
	}
	// The installer emits HTTP only when loopback HTTP was explicitly allowed.
	allowLoopbackHTTP := parsed.Scheme == "http"
	if allowLoopbackHTTP {
		hostname := strings.ToLower(parsed.Hostname())
		if hostname != "localhost" && !strings.HasSuffix(hostname, ".localhost") &&
			hostname != "::1" && !(strings.HasPrefix(hostname, "127.") && net.ParseIP(hostname) != nil) {
			return nil, nil, fmt.Errorf("prepared HTTP origin must be loopback")
		}
	}
	childEnv := make([]string, 0, len(env)+2)
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, serverURLEnv) ||
			(allowLoopbackHTTP && strings.EqualFold(name, insecureLocalHTTPEnv)) {
			continue
		}
		childEnv = append(childEnv, entry)
	}
	childEnv = append(childEnv, serverURLEnv+"="+origin)
	if allowLoopbackHTTP {
		childEnv = append(childEnv, insecureLocalHTTPEnv+"=true")
	}
	return args[2:], childEnv, nil
}

func main() {
	childArgs, env, err := parseHostLaunch(os.Args[1:], os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "tokentimer-agent-host: %v; usage: tokentimer-agent-host.exe [%s <origin>] <child-exe> [child-args...]\n", err, preparedServerFlag)
		os.Exit(2)
	}

	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tokentimer-agent-host: could not determine session type: %v\n", err)
		os.Exit(1)
	}

	log := newHostLogger(os.Getenv("TOKENTIMER_AGENT_CONFIG_DIR"))
	defer log.Close()
	stopTimeout := resolveStopTimeout(os.Getenv)
	host := newAgentHost(childArgs[0], childArgs[1:], env, log)

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

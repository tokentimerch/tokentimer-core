//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// defaultStopTimeout bounds how long a graceful stop waits for the child
// agent to drain outstanding work (job leases, outbox entries) before this
// host forces termination. It matches the install script's own
// Test-ServiceHealthy start horizon (20s) as a starting point that an
// operator can override without a rebuild.
const defaultStopTimeout = 20 * time.Second

// stopTimeoutEnvVar overrides defaultStopTimeout. Read once at process
// start (via resolveStopTimeout), never mutated afterward.
const stopTimeoutEnvVar = "TOKENTIMER_AGENT_HOST_STOP_TIMEOUT_MS"

// resolveStopTimeout parses stopTimeoutEnvVar out of the given environment
// lookup function, falling back to defaultStopTimeout for an absent,
// empty, non-numeric, or non-positive value. Kept as a pure function (no
// direct os.Getenv call) so a test can supply a fake environment without
// mutating process-global state.
func resolveStopTimeout(getenv func(string) string) time.Duration {
	raw := getenv(stopTimeoutEnvVar)
	if raw == "" {
		return defaultStopTimeout
	}
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ms <= 0 {
		return defaultStopTimeout
	}
	return time.Duration(ms) * time.Millisecond
}

// agentHost owns the child agent process and the two operations the
// service control handler and the interactive runner both need: start it,
// and ask it to stop gracefully within a bounded window. It has no
// dependency on svc.Handler or on any Windows Service Control Manager
// concept, so both runService (main_windows.go) and the interactive
// fallback can share and test it identically.
type agentHost struct {
	childExe  string
	childArgs []string
	env       []string
	log       *hostLogger

	mu  sync.Mutex
	cmd *exec.Cmd
	// exited is closed exactly once, when cmd.Wait() returns. Closing
	// (rather than sending a value) lets every interested goroutine -
	// the service handler's own exit-watcher and stopGracefully's timeout
	// race - observe the same event without racing each other for the
	// single delivery a buffered channel send would otherwise provide.
	exited  chan struct{}
	exitErr error
}

func newAgentHost(childExe string, childArgs []string, env []string, log *hostLogger) *agentHost {
	return &agentHost{childExe: childExe, childArgs: childArgs, env: env, log: log}
}

// start launches the child in its own console process group
// (CREATE_NEW_PROCESS_GROUP), which is required both for
// GenerateConsoleCtrlEvent to target the child specifically (rather than
// this host too) and to isolate the child's own Ctrl+Break handling from
// this host's.
func (h *agentHost) start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cmd != nil {
		return fmt.Errorf("agentHost: start called twice")
	}
	cmd := exec.Command(h.childExe, h.childArgs...)
	cmd.Env = h.env
	cmd.Stdout = h.log.childWriter("stdout")
	cmd.Stderr = h.log.childWriter("stderr")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// CREATE_NO_WINDOW gives the child its own dedicated (never
		// visible) console rather than inheriting this host's - which,
		// running as a Windows service, usually has none at all. Without
		// an actual console object backing the child's process group,
		// GenerateConsoleCtrlEvent below has nothing to deliver to.
		// CREATE_NEW_PROCESS_GROUP makes the child the root of its own
		// process group so the same event never also reaches this host.
		CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("agentHost: failed to start %s: %w", h.childExe, err)
	}
	h.cmd = cmd
	h.exited = make(chan struct{})
	go func() {
		err := cmd.Wait()
		h.mu.Lock()
		h.exitErr = err
		h.mu.Unlock()
		close(h.exited)
	}()
	h.log.Printf("started child pid=%d exe=%s args=%v", cmd.Process.Pid, h.childExe, h.childArgs)
	return nil
}

// wait blocks until the child exits on its own (crash or clean exit not
// requested by stopGracefully) and returns its Wait() error. Used by the
// caller to distinguish an unrequested child exit (which should propagate
// as this host's own exit code, so SCM's existing failure/restart policy
// on the service still fires) from a requested stop.
func (h *agentHost) wait() error {
	h.mu.Lock()
	exited := h.exited
	h.mu.Unlock()
	if exited == nil {
		return fmt.Errorf("agentHost: wait called before start")
	}
	<-exited
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.exitErr
}

// pid returns the child's process id, or 0 if not started.
func (h *agentHost) pid() uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cmd == nil || h.cmd.Process == nil {
		return 0
	}
	return uint32(h.cmd.Process.Pid)
}

// stopGracefully asks the child to shut itself down by delivering
// CTRL_BREAK_EVENT to its process group (Node's libuv maps this to a
// "SIGBREAK" process event the agent listens for, the same way it already
// listens for SIGINT/SIGTERM on POSIX), waits up to timeout for it to exit
// on its own, and force-terminates it if it does not. It never returns an
// error for "child already exited" - that is success, not failure.
func (h *agentHost) stopGracefully(timeout time.Duration) error {
	h.mu.Lock()
	cmd := h.cmd
	exited := h.exited
	h.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	select {
	case <-exited:
		return nil // already exited before we got here
	default:
	}

	pid := uint32(cmd.Process.Pid)
	if err := h.sendCtrlBreak(pid); err != nil {
		h.log.Printf("could not deliver a graceful stop signal to pid=%d: %v; forcing termination", pid, err)
		return h.forceKill(cmd, exited)
	}

	select {
	case <-exited:
		h.mu.Lock()
		err := h.exitErr
		h.mu.Unlock()
		h.log.Printf("child pid=%d exited gracefully: %v", pid, err)
		return nil
	case <-time.After(timeout):
		h.log.Printf("child pid=%d did not exit within %s of the stop signal; forcing termination", pid, timeout)
		return h.forceKill(cmd, exited)
	}
}

// sendCtrlBreak performs the attach/raise/detach sequence described in
// console_windows.go. It always frees the console again, even on error,
// so this host never keeps a stray console attachment past the call.
//
// AttachConsole fails with ERROR_ACCESS_DENIED whenever the calling
// process is already attached to a console of its own (documented Win32
// behavior: a process may be attached to at most one console at a time).
// A Windows service host running under SCM (session 0) has no console at
// all, so this never triggers in production, but the interactive/test
// runner inherits the launching terminal's console, so this host must
// give that console up first. Losing it is safe here: this host's own
// logging goes through hostLogger, which holds its output file/stderr
// handle independently of console attachment state, and the interactive
// runner never reads from stdin after startup.
func (h *agentHost) sendCtrlBreak(pid uint32) error {
	// Best-effort: only relevant when already attached to a console;
	// ERROR_INVALID_PARAMETER when not attached to anything is expected
	// and harmless here.
	_ = freeConsole()
	// AttachConsole against a just-created child's auto-allocated console
	// is occasionally transiently unavailable (observed empirically as a
	// spurious ERROR_INVALID_HANDLE/ERROR_ACCESS_DENIED immediately after
	// a prior attach/detach cycle in the same process); a short bounded
	// retry is the documented mitigation other implementations of this
	// same technique use, rather than failing straight to a force-kill
	// for what is usually a few-millisecond race.
	var attachErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attachErr = attachConsole(pid); attachErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
		_ = freeConsole()
	}
	if attachErr != nil {
		return fmt.Errorf("AttachConsole(%d): %w", pid, attachErr)
	}
	defer func() {
		if err := freeConsole(); err != nil {
			h.log.Printf("FreeConsole after signaling pid=%d failed (non-fatal): %v", pid, err)
		}
	}()
	// Ignore the event in this host's own (temporarily attached) context;
	// only the child's process group should react to it.
	if err := ignoreOwnConsoleCtrlEvents(true); err != nil {
		h.log.Printf("SetConsoleCtrlHandler(ignore) failed (non-fatal): %v", err)
	}
	defer func() {
		if err := ignoreOwnConsoleCtrlEvents(false); err != nil {
			h.log.Printf("SetConsoleCtrlHandler(restore) failed (non-fatal): %v", err)
		}
	}()
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, pid); err != nil {
		return fmt.Errorf("GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, %d): %w", pid, err)
	}
	return nil
}

func (h *agentHost) forceKill(cmd *exec.Cmd, exited chan struct{}) error {
	if err := cmd.Process.Kill(); err != nil {
		h.log.Printf("TerminateProcess for pid=%d failed: %v", cmd.Process.Pid, err)
	}
	<-exited // Kill() only requests termination; wait for Wait() to observe it.
	return nil
}

// hostLogger is a tiny best-effort logger: it writes lifecycle lines to a
// file when TOKENTIMER_AGENT_CONFIG_DIR is set (the same directory the
// installer already points the agent's own config/state at, via the
// registry Environment value install-agent.ps1 writes), and falls back to
// stderr otherwise (the useful case for interactive/dev runs, where stderr
// is actually visible). A logger that cannot open its file never blocks
// startup: it silently falls back to stderr instead.
type hostLogger struct {
	mu  sync.Mutex
	out io.Writer
	f   *os.File
}

func newHostLogger(configDir string) *hostLogger {
	l := &hostLogger{out: os.Stderr}
	if configDir == "" {
		return l
	}
	f, err := os.OpenFile(configDir+string(os.PathSeparator)+"host.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return l
	}
	l.f = f
	l.out = f
	return l
}

func (l *hostLogger) Printf(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s tokentimer-agent-host: %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

// childWriter returns a writer that prefixes each line the child writes to
// stdout/stderr with a stream label, sharing the same destination as
// Printf so operator-visible host and child lifecycle lines interleave in
// one file/stream instead of two.
func (l *hostLogger) childWriter(stream string) io.Writer {
	return &prefixWriter{logger: l, stream: stream}
}

type prefixWriter struct {
	logger *hostLogger
	stream string
}

func (w *prefixWriter) Write(p []byte) (int, error) {
	w.logger.mu.Lock()
	defer w.logger.mu.Unlock()
	fmt.Fprintf(w.logger.out, "%s tokentimer-agent (%s): %s", time.Now().UTC().Format(time.RFC3339), w.stream, p)
	if len(p) == 0 || p[len(p)-1] != '\n' {
		fmt.Fprintln(w.logger.out)
	}
	return len(p), nil
}

func (l *hostLogger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
}

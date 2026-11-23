//go:build windows

package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

type simulatedObservation struct {
	probe    func() error
	reserved bool
	closed   bool
}

func (o *simulatedObservation) check() error { return o.probe() }
func (o *simulatedObservation) close()       { o.closed = true }
func (o *simulatedObservation) reserve() error {
	if o.reserved {
		return errors.New("simulated run already used")
	}
	o.reserved = true
	return nil
}

func runObservedServiceForTest(t *testing.T, host *agentHost, observer *simulatedObservation) (chan<- svc.ChangeRequest, <-chan svc.Status, <-chan uint32) {
	t.Helper()
	handler := &tokenTimerAgentService{
		host: host, log: host.log, stopTimeout: 10 * time.Second,
		openObservation: func() (serviceObservation, error) { return observer, nil },
	}
	req := make(chan svc.ChangeRequest, 1)
	status := make(chan svc.Status, 6)
	exit := make(chan uint32, 1)
	done := make(chan struct{})
	go func() {
		_, code := handler.Execute(nil, req, status)
		exit <- code
		close(done)
	}()
	t.Cleanup(func() {
		select {
		case req <- svc.ChangeRequest{Cmd: svc.Stop}:
		default:
		}
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("observed service test did not stop")
		}
	})
	return req, status, exit
}

func waitObservedStop(t *testing.T, exit <-chan uint32) {
	t.Helper()
	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("service would request SCM failure handling: exit code %d", code)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("service did not fail closed")
	}
}

func TestObservedServiceRefusesStartupWithoutFreshObservation(t *testing.T) {
	for _, allowedChecks := range []int{0, 1} {
		t.Run(strconv.Itoa(allowedChecks), func(t *testing.T) {
			flag := filepath.Join(t.TempDir(), "worker-ran")
			log := newTestLogger(t)
			host := newAgentHost(nodeExe(t), []string{"-e", "require('node:fs').writeFileSync(process.argv[1], 'started')", flag}, os.Environ(), log)
			calls := 0
			observer := &simulatedObservation{probe: func() error {
				calls++
				if calls > allowedChecks {
					return errors.New("simulated observation loss")
				}
				return nil
			}}
			_, status, exit := runObservedServiceForTest(t, host, observer)
			waitObservedStop(t, exit)
			if len(status) != 1 || (<-status).State != svc.StartPending {
				t.Fatal("service reported running without fresh observation")
			}
			if host.pid() != 0 || !observer.closed || calls != allowedChecks+1 {
				t.Fatalf("incomplete startup rejection: pid=%d checks=%d observerClosed=%v", host.pid(), calls, observer.closed)
			}
			if _, err := os.Stat(flag); !os.IsNotExist(err) {
				t.Fatalf("unapproved worker executed: %v", err)
			}
		})
	}
}

func TestObservedServiceLossDrainsWorkerAndGrandchild(t *testing.T) {
	for _, scmStop := range []bool{false, true} {
		t.Run(strconv.FormatBool(scmStop), func(t *testing.T) {
			const script = "const {spawn} = require('node:child_process'); " +
				"const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {stdio: 'ignore', windowsHide: true}); " +
				"process.on('SIGBREAK', () => {}); " +
				"child.once('spawn', () => require('node:fs').writeFileSync(process.argv[1], process.pid + ',' + child.pid)); " +
				"setInterval(() => {}, 1000);"
			pids := filepath.Join(t.TempDir(), "pids")
			var logs bytes.Buffer
			log := &hostLogger{out: io.MultiWriter(&testWriter{t: t}, &logs)}
			host := newAgentHost(nodeExe(t), []string{"-e", script, pids}, os.Environ(), log)
			var unavailable atomic.Bool
			observer := &simulatedObservation{probe: func() error {
				if unavailable.Load() {
					return errors.New("simulated observation loss")
				}
				return nil
			}}
			req, status, exit := runObservedServiceForTest(t, host, observer)
			waitForState(t, status, svc.Running, 10*time.Second)
			handles := waitObservedProcesses(t, pids)
			if scmStop {
				req <- svc.ChangeRequest{Cmd: svc.Stop}
				waitForState(t, status, svc.StopPending, 3*time.Second)
			}
			unavailable.Store(true)
			waitObservedStop(t, exit)
			for _, handle := range handles {
				if state, err := windows.WaitForSingleObject(handle, 0); err != nil || state != windows.WAIT_OBJECT_0 {
					t.Fatalf("original process still active: wait result=%d err=%v", state, err)
				}
			}
			if !observer.closed || !strings.Contains(logs.String(), "observed job empty and retained processes exited") {
				t.Fatalf("service did not verify the drain or close the observer: %s", &logs)
			}

			// A fresh response on the same run cannot rearm the worker.
			unavailable.Store(false)
			restarted := newAgentHost(host.childExe, host.childArgs, host.env, log)
			_, _, refused := runObservedServiceForTest(t, restarted, observer)
			waitObservedStop(t, refused)
			if restarted.pid() != 0 {
				t.Fatal("restart reused the consumed observation run")
			}
		})
	}
}

func waitObservedProcesses(t *testing.T, pids string) []windows.Handle {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pids)
		parts := strings.Split(string(data), ",")
		if err == nil && len(parts) == 2 {
			var handles []windows.Handle
			for _, part := range parts {
				pid, err := strconv.ParseUint(part, 10, 32)
				if err != nil || pid == 0 {
					t.Fatalf("invalid fixture pid: %q", part)
				}
				handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
				if err != nil {
					t.Fatalf("retain original fixture process: %v", err)
				}
				t.Cleanup(func() { _ = windows.CloseHandle(handle) })
				handles = append(handles, handle)
			}
			return handles
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("worker and grandchild did not report their identity")
	return nil
}

func TestObservationRejectsReplay(t *testing.T) {
	host, observer := net.Pipe()
	defer host.Close()
	defer observer.Close()
	done := make(chan error, 1)
	go func() {
		var current, previous [32]byte
		if _, err := io.ReadFull(observer, previous[:]); err != nil {
			done <- err
			return
		}
		if _, err := observer.Write(previous[:]); err != nil {
			done <- err
			return
		}
		if _, err := io.ReadFull(observer, current[:]); err != nil {
			done <- err
			return
		}
		_, err := observer.Write(previous[:])
		done <- err
	}()
	if err := verifyObservationReply(host); err != nil {
		t.Fatalf("fresh observer refused: %v", err)
	}
	if err := verifyObservationReply(host); err == nil {
		t.Fatal("replayed observer response accepted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// This exercises the actual overlapped Windows pipe transport without
// installing an SCM service, starting a LocalSystem process, or writing HKLM.
func TestObservationWindowsPipe(t *testing.T) {
	name, err := windows.UTF16PtrFromString(observationPipeName(strconv.FormatInt(time.Now().UnixNano(), 16)))
	if err != nil {
		t.Fatal(err)
	}
	serverHandle, err := windows.CreateNamedPipe(name,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 128, 128, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	observer := os.NewFile(uintptr(serverHandle), "test-observation-server")
	defer observer.Close()
	clientHandle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatal(err)
	}
	host := os.NewFile(uintptr(clientHandle), "test-observation-client")
	defer host.Close()
	if peer, err := openObservationPeer(clientHandle); err == nil {
		_ = windows.CloseHandle(peer)
		t.Fatal("in-process pipe incorrectly accepted as independent")
	}

	done := make(chan error, 1)
	go func() {
		if err := observer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			done <- err
			return
		}
		var challenge [32]byte
		if _, err := io.ReadFull(observer, challenge[:]); err != nil {
			done <- err
			return
		}
		_, err := observer.Write(challenge[:])
		done <- err
	}()
	if err := verifyObservationReply(host); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := verifyObservationReply(host); err == nil {
		t.Fatal("stalled observer renewed the run")
	}
}

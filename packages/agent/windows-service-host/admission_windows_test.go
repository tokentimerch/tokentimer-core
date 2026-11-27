//go:build windows

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func admissionFixture(t *testing.T, observer serviceObservation, onLoss func(), workerPID func() uint32) (*observedAdmission, *admissionBroker) {
	t.Helper()
	if onLoss == nil {
		onLoss = func() {}
	}
	gate := &observedAdmission{observer: observer, failure: make(chan error, 1), onLoss: onLoss}
	journal, err := os.Create(filepath.Join(t.TempDir(), "admission.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	if workerPID == nil {
		workerPID = func() uint32 { return uint32(os.Getpid()) }
	}
	broker, err := startAdmissionBroker(gate, "0123456789abcdef0123456789abcdef", journal, workerPID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broker.close)
	return gate, broker
}

func exchangeAdmission(t *testing.T, b *admissionBroker, operation byte, nonce byte) ([]byte, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", b.listener.Addr().String(), time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}
	request := bytes.Repeat([]byte{nonce}, admissionRequestBytes)
	request[0] = operation
	if _, err := conn.Write(append(request, admissionMAC(b.key[:], "request", request)...)); err != nil {
		return nil, err
	}
	return io.ReadAll(conn)
}

func readAdmissionRecords(t *testing.T, broker *admissionBroker) []map[string]any {
	t.Helper()
	file, err := os.Open(broker.journal.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var records []map[string]any
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

func TestAdmissionRevokedWhileProbeIsSuspended(t *testing.T) {
	for _, kind := range []string{"loss", "scm-stop"} {
		t.Run(kind, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var first, unblock sync.Once
			_, broker := admissionFixture(t, &simulatedObservation{probe: func() error {
				first.Do(func() {
					close(entered)
					<-release
				})
				if kind == "loss" {
					return errors.New("simulated observer loss")
				}
				return nil
			}}, nil, nil)
			// Unblock before the broker cleanup waits for its request goroutine.
			t.Cleanup(func() { unblock.Do(func() { close(release) }) })
			type response struct {
				data []byte
				err  error
			}
			done := make(chan response, 1)
			go func() {
				data, err := exchangeAdmission(t, broker, 3, 1)
				done <- response{data, err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("admission did not reach observation")
			}
			if kind == "scm-stop" {
				broker.gate.revoke()
			}
			unblock.Do(func() { close(release) })
			result := <-done
			if result.err != nil || len(result.data) != 0 {
				t.Fatalf("revoked operation received a permit: replyBytes=%d err=%v", len(result.data), result.err)
			}
			records := readAdmissionRecords(t, broker)
			if len(records) != 1 || records[0]["decision"] != "denied" || records[0]["operation"] != "cng-create" || records[0]["run"] != broker.run {
				t.Fatalf("denial missing from synced journal: %v", records)
			}
		})
	}
}

func TestAdmissionNodeWorkerUsesAuthenticatedPermit(t *testing.T) {
	_, broker := admissionFixture(t, &simulatedObservation{probe: func() error { return nil }}, nil, nil)
	module, err := filepath.Abs("../src/observation-admission.js")
	if err != nil {
		t.Fatal(err)
	}
	const script = "const m = require(process.argv[1]); " +
		"const b = m.takeAdmissionBinding(); " +
		"if (process.env.TOKENTIMER_AGENT_HOST_ADMISSION !== undefined) process.exit(3); " +
		"m.createOperationAdmission(b, () => {})('store-accept').catch((error) => { console.error(error.message); process.exitCode = 2; });"
	cmd := exec.Command(nodeExe(t), "-e", script, module)
	cmd.Env = append(os.Environ(), admissionEnv+"="+broker.binding())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Node admission handshake: %v: %s", err, output)
	}
	records := readAdmissionRecords(t, broker)
	if len(records) != 1 || records[0]["decision"] != "eligible" || records[0]["operation"] != "store-accept" ||
		records[0]["sequence"] != float64(1) || records[0]["run"] != broker.run {
		t.Fatalf("durable permit eligibility missing: %v", records)
	}
}

func TestAdmissionJournalFailureRevokesBeforePermit(t *testing.T) {
	gate, broker := admissionFixture(t, &simulatedObservation{probe: func() error { return nil }}, nil, nil)
	if err := broker.journal.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := exchangeAdmission(t, broker, 4, 2)
	if err != nil || len(data) != 0 {
		t.Fatalf("unrecorded permit escaped: replyBytes=%d err=%v", len(data), err)
	}
	select {
	case <-gate.failure:
	case <-time.After(time.Second):
		t.Fatal("journal failure did not revoke admission")
	}
	if !gate.stopped.Load() {
		t.Fatal("admission remains open after journal failure")
	}
}

func TestAdmissionSecureJournalRejectsNonlocalRoot(t *testing.T) {
	const run = "0123456789abcdef0123456789abcdef"
	for _, dir := range []string{"relative-state", "\\\\observer\\share"} {
		if file, release, err := openAdmissionJournal(dir, run); err == nil {
			_ = file.Close()
			release()
			t.Fatalf("unprotected state directory accepted: %s", dir)
		}
	}
}

// Exercise a real child_process.execFile inside the Windows job. The test
// lets the permitted Node worker live long enough to attempt the launch
// after the fence, instead of relying on killing Node first.
func TestIssuedPermitCannotStartToolAfterWindowsJobFence(t *testing.T) {
	module, err := filepath.Abs("../src/observation-admission.js")
	if err != nil {
		t.Fatal(err)
	}
	const script = "const fs = require('node:fs'); " +
		"const {guardNativeExec, takeAdmissionBinding, createOperationAdmission} = require(process.argv[1]); " +
		"const [ready, resume, started, result] = process.argv.slice(2); " +
		"const admit = createOperationAdmission(takeAdmissionBinding(), () => {}); " +
		"const exec = guardNativeExec(async (stage, signal) => { " +
		"await admit(stage, signal); fs.writeFileSync(ready, 'permitted'); " +
		"while (!fs.existsSync(resume)) await new Promise(r => setTimeout(r, 10)); " +
		"}); " +
		"exec(process.execPath, ['-e', \"require('node:fs').writeFileSync(process.argv[1], 'started')\", started], {}) " +
		".then(() => fs.writeFileSync(result, 'launched'), () => fs.writeFileSync(result, 'blocked'));"

	for _, fence := range []bool{false, true} {
		name := "live-observation"
		if fence {
			name = "revoked-before-exec"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			ready, resume := filepath.Join(dir, "permit"), filepath.Join(dir, "resume")
			started, outcome := filepath.Join(dir, "effect"), filepath.Join(dir, "outcome")
			host := newAgentHost(nodeExe(t), []string{"-e", script, module, ready, resume, started, outcome}, nil, newTestLogger(t))
			var unavailable atomic.Bool
			var fenceApplied bool
			gate, broker := admissionFixture(t, &simulatedObservation{probe: func() error {
				if unavailable.Load() {
					return errors.New("simulated observer loss after grant")
				}
				return nil
			}}, func() { fenceApplied = host.prepareObservedStop() }, host.pid)
			if err := host.startChild(func() error { return nil }, nil, broker.binding()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := host.stopObservedChild(); err != nil {
					t.Errorf("drain fixture: %v", err)
				}
			})

			if got := readAdmissionMarker(t, ready); got != "permitted" {
				t.Fatalf("worker never obtained the initial permit: %q", got)
			}
			records := readAdmissionRecords(t, broker)
			if len(records) != 1 || records[0]["decision"] != "eligible" ||
				records[0]["workerPid"] != float64(host.pid()) {
				t.Fatalf("initial permit was not backed by this worker's durable admission check: %v", records)
			}
			if fence {
				unavailable.Store(true)
				if err := gate.check(); err == nil {
					t.Fatal("observer loss was ignored")
				}
				select {
				case <-gate.failure:
					if !fenceApplied {
						t.Fatal("host notified observer loss without a successful job fence")
					}
				default:
					t.Fatal("loss notification missing after fencing")
				}
			}

			if err := os.WriteFile(resume, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			got := readAdmissionMarker(t, outcome)
			if fence {
				if _, err := os.Stat(started); got != "blocked" || !os.IsNotExist(err) {
					t.Fatalf("native child ran after the job fence: outcome=%q markerError=%v", got, err)
				}
			} else if got != "launched" || readAdmissionMarker(t, started) != "started" {
				t.Fatalf("healthy control did not start the same child: %q", got)
			}
			select {
			case <-host.exited:
				if err := host.wait(); err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("fixture worker did not exit")
			}
		})
	}
}

func readAdmissionMarker(t *testing.T, file string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(file)
		if err == nil && len(data) > 0 {
			return string(data)
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("worker did not write %s", filepath.Base(file))
	return ""
}

func TestAdmissionLossNotificationWaitsForHostFence(t *testing.T) {
	entered, done := make(chan struct{}), make(chan struct{})
	var finish sync.Once
	t.Cleanup(func() { finish.Do(func() { close(done) }) })
	gate := &observedAdmission{
		failure: make(chan error, 1),
		onLoss: func() {
			close(entered)
			<-done
		},
	}
	fault := errors.New("simulated observer loss")
	go gate.fail(fault)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("host interruption was not invoked")
	}
	if !gate.stopped.Load() {
		t.Fatal("new permits remained open during the job interruption")
	}
	select {
	case <-gate.failure:
		t.Fatal("loss notification preceded the host interruption")
	default:
	}
	finish.Do(func() { close(done) })
	select {
	case err := <-gate.failure:
		if !errors.Is(err, fault) {
			t.Fatalf("wrong observation failure: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("loss was not delivered after the host interruption")
	}
}

func TestRecordedRevocationBlocksSuspendedWorkerResume(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "worker-ran")
	host := newAgentHost(nodeExe(t), []string{
		"-e", "require('node:fs').writeFileSync(process.argv[1], 'started')", marker,
	}, nil, newTestLogger(t))

	startupReady, continueStartup, interrupting := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(continueStartup) }) })
	var unavailable atomic.Bool
	observerLoss := errors.New("simulated observer loss while startup is armed")
	observer := &simulatedObservation{probe: func() error {
		if unavailable.Load() {
			return observerLoss
		}
		return nil
	}}
	gate := &observedAdmission{
		observer: observer,
		failure:  make(chan error, 1),
		onLoss: func() {
			close(interrupting)
			host.interruptObservedChild()
		},
	}
	started := make(chan error, 1)
	go func() {
		started <- host.startChild(func() error {
			if err := observer.check(); err != nil {
				return err
			}
			close(startupReady)
			<-continueStartup
			return nil
		}, gate.lockResume, "")
	}()
	select {
	case <-startupReady:
	case err := <-started:
		t.Fatalf("child failed before arming: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("suspended startup did not reach arming")
	}

	unavailable.Store(true)
	go gate.check()
	select {
	case <-interrupting:
		if !gate.stopped.Load() {
			t.Fatal("observer loss was not recorded before host interruption")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failed to acquire revocation during suspended startup")
	}
	// The loss handler is waiting for the host lock. The child must remain
	// suspended even though interruption and its notification cannot finish.
	release.Do(func() { close(continueStartup) })
	var startupErr error
	select {
	case startupErr = <-started:
	case <-time.After(8 * time.Second):
		t.Fatal("suspended startup did not release the host lock")
	}
	select {
	case err := <-gate.failure:
		if !errors.Is(err, observerLoss) {
			t.Fatalf("unexpected observation failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("host interruption remained blocked")
	}
	if startupErr == nil {
		_ = host.stopObservedChild()
		t.Fatal("revoked startup reached the native resume")
	}
	if !strings.HasSuffix(startupErr.Error(), "observation admission closed during startup") {
		t.Fatalf("unexpected startup refusal or unverified cleanup: %v", startupErr)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("revoked worker code ran or could not be verified: %v", err)
	}
}

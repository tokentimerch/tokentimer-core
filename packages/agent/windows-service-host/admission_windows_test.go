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
	"sync"
	"testing"
	"time"
)

func admissionFixture(t *testing.T, observer serviceObservation) (*observedAdmission, *admissionBroker) {
	t.Helper()
	gate := &observedAdmission{observer: observer, failure: make(chan error, 1), onLoss: func() {}}
	journal, err := os.Create(filepath.Join(t.TempDir(), "admission.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	broker, err := startAdmissionBroker(gate, "0123456789abcdef0123456789abcdef", journal, func() uint32 { return uint32(os.Getpid()) })
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
			}})
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
	_, broker := admissionFixture(t, &simulatedObservation{probe: func() error { return nil }})
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
	gate, broker := admissionFixture(t, &simulatedObservation{probe: func() error { return nil }})
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

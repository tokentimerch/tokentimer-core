//go:build windows

package verifiedextraction

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

const fixtureArchive = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const fixtureSCM = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// The current-user fixture performs real file I/O and DACL validation, but its
// Locks are stand-ins. It does not qualify SYSTEM/Admin or ancestor locking.
func intentFixture(t *testing.T) (*PrivateStaging, string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sddl := "O:" + sid + "G:" + sid + "D:P(A;OICI;FA;;;" + sid + ")"
	parent := t.TempDir()
	root := filepath.Join(parent, "TokenTimer-Staging-"+strings.Repeat("a", 32))
	if err := createRestrictedDirectory(root, sddl); err != nil {
		t.Fatal(err)
	}
	id, err := getDirectoryIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	return &PrivateStaging{freshOwned: true, path: root, parent: parent, identity: id, policy: bootstraplock.Policy{Owners: map[string]bool{sid: true}, Writers: map[string]bool{sid: true}}, ancestors: &bootstraplock.Locks{}, staging: &bootstraplock.Locks{}, payload: &bootstraplock.Locks{}}, sddl
}

func TestRecoveredStagingWithoutIntentRemainsQuarantined(t *testing.T) {
	s, _ := intentFixture(t)
	recovered := &PrivateStaging{path: s.path, parent: s.parent, identity: s.identity, policy: s.policy, ancestors: s.ancestors, staging: s.staging}
	if err := recovered.Cleanup(); !errors.Is(err, ErrExecutionRecoveryPending) {
		t.Fatalf("recovered stage authorized cleanup: %v", err)
	}
	if _, err := os.Stat(s.path); err != nil {
		t.Fatalf("recovered staging removed: %v", err)
	}
}

func TestExecutionIntentPairSharesOnlyExplicitSecretAndTransaction(t *testing.T) {
	payload, pSDDL := intentFixture(t)
	scratch, sSDDL := intentFixture(t)
	first, err := payload.beginExecutionIntent(fixtureArchive, fixtureSCM, pSDDL, defaultIntentIO())
	if err != nil {
		t.Fatal(err)
	}
	second, err := scratch.beginExecutionIntentForTransaction(fixtureArchive, fixtureSCM, sSDDL, first.Transaction, first.Secret, defaultIntentIO())
	if err != nil {
		t.Fatal(err)
	}
	if first.Transaction != second.Transaction || first.Secret != second.Secret || first.Secret == "" {
		t.Fatal("paired intent identity mismatch")
	}
	if first.Volume == second.Volume && first.IndexHigh == second.IndexHigh && first.IndexLow == second.IndexLow {
		t.Fatal("distinct stages share identity")
	}
	for _, stage := range []*PrivateStaging{payload, scratch} {
		if err := stage.Cleanup(); !errors.Is(err, ErrExecutionRecoveryPending) {
			t.Fatalf("stage escaped quarantine: %v", err)
		}
	}
}

func TestExecutionIntentIsFlushedOutsidePayloadAndBlocksCleanup(t *testing.T) {
	s, sddl := intentFixture(t)
	intent, err := s.beginExecutionIntent(fixtureArchive, fixtureSCM, sddl, defaultIntentIO())
	if err != nil {
		t.Fatal(err)
	}
	journal := s.path + ".intent"
	if filepath.Dir(journal) != s.parent || filepath.Dir(journal) == s.path {
		t.Fatal("journal must be sibling of payload")
	}
	data, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("bootstrap_token")) {
		t.Fatal("unexpected sensitive content")
	}
	var observed ExecutionIntent
	if err := json.Unmarshal(data, &observed); err != nil || observed != intent {
		t.Fatalf("unexpected record: %v", err)
	}
	if _, valid, err := s.inspectExecutionIntent(fixtureArchive, fixtureSCM); !valid || !errors.Is(err, ErrExecutionRecoveryPending) {
		t.Fatalf("validated journal must remain quarantined: %v", err)
	}
	if err := s.Cleanup(); !errors.Is(err, ErrExecutionRecoveryPending) {
		t.Fatalf("cleanup must remain blocked: %v", err)
	}
	if _, err := os.Stat(s.path); err != nil {
		t.Fatalf("staging unexpectedly removed: %v", err)
	}
}

func TestExecutionIntentPartialWriteAndFlushFailurePreserveQuarantine(t *testing.T) {
	for _, mode := range []string{"partial-write", "flush"} {
		t.Run(mode, func(t *testing.T) {
			s, sddl := intentFixture(t)
			io := defaultIntentIO()
			if mode == "partial-write" {
				io.write = func(h windows.Handle, b []byte) error {
					var written uint32
					if err := windows.WriteFile(h, b[:len(b)/2], &written, nil); err != nil {
						return err
					}
					return errors.New("injected partial write")
				}
			} else {
				io.flush = func(windows.Handle) error { return errors.New("injected flush failure") }
			}
			if _, err := s.beginExecutionIntent(fixtureArchive, fixtureSCM, sddl, io); err == nil {
				t.Fatal("expected I/O failure")
			}
			if _, err := os.Lstat(s.path + ".intent"); err != nil {
				t.Fatalf("partial intent missing: %v", err)
			}
			if err := s.Cleanup(); !errors.Is(err, ErrExecutionRecoveryPending) {
				t.Fatalf("cleanup must refuse uncertain write: %v", err)
			}
			if _, err := os.Stat(s.path); err != nil {
				t.Fatalf("staging unexpectedly removed: %v", err)
			}
		})
	}
}

func TestExistingOrInvalidExecutionIntentNeverAuthorizesCleanup(t *testing.T) {
	s, sddl := intentFixture(t)
	intent, err := s.beginExecutionIntent(fixtureArchive, fixtureSCM, sddl, defaultIntentIO())
	if err != nil {
		t.Fatal(err)
	}
	// Exercise CREATE_NEW even if a fresh owner encounters an unexpected marker.
	restarted := PrivateStaging{freshOwned: true, path: s.path, parent: s.parent, identity: s.identity, policy: s.policy, ancestors: s.ancestors, staging: s.staging, payload: s.payload}
	if _, err := restarted.beginExecutionIntent(fixtureArchive, fixtureSCM, sddl, defaultIntentIO()); err == nil {
		t.Fatal("existing journal was overwritten")
	}
	data, err := os.ReadFile(s.path + ".intent")
	if err != nil {
		t.Fatal(err)
	}
	var observed ExecutionIntent
	if err := json.Unmarshal(data, &observed); err != nil || observed != intent {
		t.Fatal("journal changed")
	}
	if err := os.WriteFile(s.path+".intent", []byte(`{"schemaVersion":1,"schemaVersion":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, valid, err := restarted.inspectExecutionIntent(fixtureArchive, fixtureSCM); valid || !errors.Is(err, ErrExecutionRecoveryPending) {
		t.Fatalf("invalid journal must remain quarantined: %v", err)
	}
	if err := restarted.Cleanup(); !errors.Is(err, ErrExecutionRecoveryPending) {
		t.Fatalf("invalid journal authorized cleanup: %v", err)
	}
}

func TestExecutionIntentRejectsAlteredIdentityAndDigests(t *testing.T) {
	for _, field := range []string{"stageName", "volume", "archiveSha256", "previousScmSha256", "transaction", "unknown"} {
		t.Run(field, func(t *testing.T) {
			s, sddl := intentFixture(t)
			if _, err := s.beginExecutionIntent(fixtureArchive, fixtureSCM, sddl, defaultIntentIO()); err != nil {
				t.Fatal(err)
			}
			path := s.path + ".intent"
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]any
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatal(err)
			}
			if field == "volume" {
				record[field] = float64(4294967295)
			} else {
				record[field] = "altered"
			}
			data, err = json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			got, valid, err := s.inspectExecutionIntent(fixtureArchive, fixtureSCM)
			if valid || !errors.Is(err, ErrExecutionRecoveryPending) || got != (ExecutionIntent{}) {
				t.Fatalf("altered record accepted: %+v, %v", got, err)
			}
			if err := s.Cleanup(); !errors.Is(err, ErrExecutionRecoveryPending) {
				t.Fatalf("altered record authorized cleanup: %v", err)
			}
		})
	}
}

func TestExecutionIntentHoldsStagingLocksUntilFlushCompletes(t *testing.T) {
	s, sddl := intentFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	io := defaultIntentIO()
	flush := io.flush
	io.flush = func(h windows.Handle) error { close(entered); <-release; return flush(h) }
	result := make(chan error, 1)
	go func() { _, err := s.beginExecutionIntent(fixtureArchive, fixtureSCM, sddl, io); result <- err }()
	<-entered
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close released staging locks during intent flush")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close remained blocked after intent completed")
	}
}

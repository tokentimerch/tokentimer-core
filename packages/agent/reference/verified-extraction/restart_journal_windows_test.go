//go:build windows

package verifiedextraction

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProtectedRestartJournalFlushAndRetry(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	archive := filepath.Join(f.parent, "protected-review")
	if err := createRestrictedDirectory(archive, f.sddl); err != nil {
		t.Fatal(err)
	}
	binding := upgradeJournalBinding{Volume: 1, IndexHigh: 2, IndexLow: 3, SHA256: strings.Repeat("a", 64)}
	j, err := openProtectedRestartJournal(archive, f.sddl, f.txn, binding, f.stagePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.FlushStep("stop-requested"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(archive, "restart-review.log")
	if err = os.WriteFile(path, []byte("tamper"), 0600); err == nil {
		t.Fatal("write while journal locked succeeded")
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = openProtectedRestartJournal(archive, f.sddl, f.txn, binding, f.stagePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.FlushStep("verify-before"); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	other := binding
	other.SHA256 = strings.Repeat("b", 64)
	if j, err = openProtectedRestartJournal(archive, f.sddl, f.txn, other, f.stagePolicy); err == nil {
		j.Close()
		t.Fatal("changed journal binding accepted")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(raw, []byte("partial")...), 0600); err != nil {
		t.Fatal(err)
	}
	if j, err = openProtectedRestartJournal(archive, f.sddl, f.txn, binding, f.stagePolicy); err == nil {
		j.Close()
		t.Fatal("partial write accepted")
	}
}

type pauseRestartJournal struct {
	inner *protectedRestartJournal
	stop  string
	ready string
}

func (j pauseRestartJournal) FlushStep(step string) error {
	if err := j.inner.FlushStep(step); err != nil {
		return err
	}
	if step == j.stop {
		if err := os.WriteFile(j.ready, []byte("ready"), 0600); err != nil {
			return err
		}
		for {
			time.Sleep(time.Second)
		}
	}
	return nil
}
func TestRestartJournalSurvivesKilledProcess(t *testing.T) {
	binding := upgradeJournalBinding{Volume: 1, IndexHigh: 2, IndexLow: 3, SHA256: strings.Repeat("a", 64)}
	if os.Getenv("TT_RESTART_CRASH_CHILD") == "1" {
		var w releaseFixtureWire
		if err := json.Unmarshal([]byte(os.Getenv("TT_RESTART_CRASH_FIXTURE")), &w); err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(w.Parent, "protected-review")
		j, err := openProtectedRestartJournal(archive, w.SDDL, w.Transaction, binding, w.StagePolicy)
		if err != nil {
			t.Fatal(err)
		}
		defer j.Close()
		err = restartUnderVerifiedLock(context.Background(), &fakeRestart{}, pauseRestartJournal{inner: j, stop: os.Getenv("TT_RESTART_CRASH_STEP"), ready: filepath.Join(w.Parent, "restart-ready")})
		t.Fatalf("unexpected return: %v", err)
	}
	for _, step := range []string{"verify-before", "stop-requested", "verify-stopped", "start-requested", "verify-started", "verified"} {
		t.Run(step, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			archive := filepath.Join(f.parent, "protected-review")
			if err := createRestrictedDirectory(archive, f.sddl); err != nil {
				t.Fatal(err)
			}
			wire, _ := json.Marshal(releaseFixtureWire{f.parent, f.journal, f.sddl, f.txn, f.parentPolicy, f.stagePolicy})
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestRestartJournalSurvivesKilledProcess$")
			cmd.Env = append(os.Environ(), "TT_RESTART_CRASH_CHILD=1", "TT_RESTART_CRASH_FIXTURE="+string(wire), "TT_RESTART_CRASH_STEP="+step)
			var out strings.Builder
			cmd.Stdout = &out
			cmd.Stderr = &out
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			deadline := time.Now().Add(15 * time.Second)
			ready := filepath.Join(f.parent, "restart-ready")
			for time.Now().Before(deadline) {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if _, err = os.Stat(ready); err != nil {
				t.Fatalf("child did not reach checkpoint: %s", out.String())
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			j, err := openProtectedRestartJournal(archive, f.sddl, f.txn, binding, f.stagePolicy)
			if err != nil {
				t.Fatalf("journal not recoverable: %v", err)
			}
			defer j.Close()
			c := &fakeRestart{}
			if err = restartUnderVerifiedLock(context.Background(), c, j); err != nil {
				t.Fatalf("retry failed: %v", err)
			}
		})
	}
}

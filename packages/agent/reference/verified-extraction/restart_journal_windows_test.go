//go:build windows

package verifiedextraction

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/windows"
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
	if err = j.FlushStep("verify-before"); err != nil {
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
	if j.CanRestart() {
		t.Fatal("interrupted stop was marked restartable")
	}
	if err = j.FlushStep("verify-before"); err == nil {
		t.Fatal("interrupted stop accepted new steps")
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

func TestProtectedRestartJournalWriteFailureDisablesReuse(t *testing.T) {
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
	if err := j.FlushStep("verify-before"); err != nil {
		t.Fatal(err)
	}
	// A closed OS handle deterministically exercises the I/O failure path.
	if err := j.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.FlushStep("stop-requested"); err == nil {
		t.Fatal("expected failed checkpoint write")
	}
	if j.CanRestart() {
		t.Fatal("failed checkpoint incorrectly allowed restart")
	}
	if err := j.FlushStep("verify-before"); err == nil {
		t.Fatal("failed journal instance accepted another checkpoint")
	}
}

func TestProtectedRestartJournalSyncFailureDisablesReuse(t *testing.T) {
	// Windows NUL accepts a write but cannot flush file buffers, exercising a
	// distinct failure after the checkpoint write returned successfully.
	f, err := os.OpenFile("NUL", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	j := &protectedRestartJournal{file: f}
	if err := j.FlushStep("verify-before"); err == nil || !strings.Contains(err.Error(), "flush failed") {
		t.Fatalf("expected sync failure after write, got %v", err)
	}
	if j.CanRestart() {
		t.Fatal("failed journal flush incorrectly allowed restart")
	}
	if err := j.FlushStep("verify-before"); err == nil {
		t.Fatal("failed journal instance accepted another checkpoint")
	}
}

type pauseRestartJournal struct {
	inner *protectedRestartJournal
	stop  string
	ready string
}

func (j pauseRestartJournal) CanRestart() bool { return j.inner.CanRestart() }
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
			err = restartUnderVerifiedLock(context.Background(), c, j)
			if step == "verify-before" && err != nil {
				t.Fatalf("safe retry refused: %v", err)
			}
			if step != "verify-before" && err == nil {
				t.Fatal("retry after stop request accepted without old process handles")
			}
			if step != "verify-before" && len(c.calls) != 0 {
				t.Fatal("SCM acted after interrupted stop")
			}
		})
	}
}

func TestRestartJournalRejectsInvalidSequences(t *testing.T) {
	sequences := [][]string{{"stop-requested"}, {"verify-stopped"}, {"start-requested"}, {"verify-started"}, {"verified"}, {"stopped-verified"}, {"verify-before", "verify-stopped"}, {"verify-before", "stop-requested", "stop-requested"}, {"verify-before", "stop-requested", "start-requested"}, {"verify-before", "stop-requested", "verify-stopped", "verify-stopped"}, {"verify-before", "stop-requested", "verify-stopped", "start-requested", "verified"}}
	for _, sequence := range sequences {
		p := restartProgress{}
		accepted := true
		for _, step := range sequence {
			next, err := advanceRestartProgress(p, step)
			if err != nil {
				accepted = false
				break
			}
			p = next
		}
		if accepted {
			t.Fatalf("invalid sequence accepted: %v", sequence)
		}
	}
	stop := restartProgress{}
	for _, step := range []string{"verify-before", "stop-requested", "verify-stopped", "stopped-verified"} {
		next, err := advanceRestartProgress(stop, step)
		if err != nil {
			t.Fatal(err)
		}
		stop = next
	}
	if _, err := advanceRestartProgress(stop, "start-requested"); err == nil {
		t.Fatal("service start accepted after stop-only decision")
	}
	p := restartProgress{}
	for _, step := range []string{"verify-before", "verify-before", "stop-requested", "verify-stopped", "start-requested", "verify-started", "verified"} {
		next, err := advanceRestartProgress(p, step)
		if err != nil {
			t.Fatal(err)
		}
		p = next
	}
}
func TestProtectedRestartJournalRejectsCorruptStepOrdering(t *testing.T) {
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
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(archive, "restart-review.log")
	header, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"stop-requested\n", "verify-stopped\n", "start-requested\n", "verified\n", "verify-before\nstop-requested\nstop-requested\n", "verify-before\nstop-requested\nstart-requested\n", "verify-before\nstop-requested\nverify-stopped\nverified\n", "verify-before\nstop-requested"} {
		raw := append(append([]byte{}, header...), []byte(bad)...)
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if j, err = openProtectedRestartJournal(archive, f.sddl, f.txn, binding, f.stagePolicy); err == nil {
			j.Close()
			t.Fatalf("corrupt journal accepted: %q", bad)
		}
	}
}
func TestStopOnlyJournalFailsClosedAfterForcedTermination(t *testing.T) {
	binding := upgradeJournalBinding{Volume: 1, IndexHigh: 2, IndexLow: 3, SHA256: strings.Repeat("a", 64)}
	if os.Getenv("TT_STOP_REVIEW_CHILD") == "1" {
		var w releaseFixtureWire
		if err := json.Unmarshal([]byte(os.Getenv("TT_STOP_REVIEW_FIXTURE")), &w); err != nil {
			t.Fatal(err)
		}
		j, err := openProtectedRestartJournal(filepath.Join(w.Parent, "protected-review"), w.SDDL, w.Transaction, binding, w.StagePolicy)
		if err != nil {
			t.Fatal(err)
		}
		defer j.Close()
		err = stopUnderVerifiedLock(context.Background(), &fakeRestart{}, pauseRestartJournal{inner: j, stop: os.Getenv("TT_STOP_REVIEW_STEP"), ready: filepath.Join(w.Parent, "stop-ready")})
		t.Fatalf("unexpected return: %v", err)
	}
	for _, step := range []string{"verify-before", "stop-requested", "verify-stopped", "stopped-verified"} {
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
			cmd := exec.Command(exe, "-test.run=^TestStopOnlyJournalFailsClosedAfterForcedTermination$")
			cmd.Env = append(os.Environ(), "TT_STOP_REVIEW_CHILD=1", "TT_STOP_REVIEW_FIXTURE="+string(wire), "TT_STOP_REVIEW_STEP="+step)
			var output strings.Builder
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			ready := filepath.Join(f.parent, "stop-ready")
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if _, err = os.Stat(ready); err != nil {
				t.Fatalf("checkpoint not reached: %s", output.String())
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			j, err := openProtectedRestartJournal(archive, f.sddl, f.txn, binding, f.stagePolicy)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			c := &fakeRestart{}
			err = stopUnderVerifiedLock(context.Background(), c, j)
			if step == "verify-before" && err != nil {
				t.Fatalf("pre-stop retry rejected: %v", err)
			}
			if step != "verify-before" && (err == nil || len(c.calls) != 0) {
				t.Fatal("stop-only retry performed SCM action after interruption")
			}
		})
	}
}
func TestDisableStopJournalBindsOriginalStartType(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	archive := filepath.Join(f.parent, "disable-review")
	if err := createRestrictedDirectory(archive, f.sddl); err != nil {
		t.Fatal(err)
	}
	binding := upgradeJournalBinding{Volume: 1, IndexHigh: 2, IndexLow: 3, SHA256: strings.Repeat("a", 64)}
	if j, err := openDisableStopJournal(archive, f.sddl, f.txn, binding, f.stagePolicy, windows.SERVICE_DISABLED); err == nil {
		j.Close()
		t.Fatal("disabled initial start accepted")
	}
	j, err := openDisableStopJournal(archive, f.sddl, f.txn, binding, f.stagePolicy, windows.SERVICE_AUTO_START)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.FlushStep("verify-before"); err != nil {
		t.Fatal(err)
	}
	if err = j.FlushStep("stop-requested"); err == nil {
		t.Fatal("stop accepted before disable")
	}
	if err = j.FlushStep("disable-requested"); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	if j, err = openDisableStopJournal(archive, f.sddl, f.txn, binding, f.stagePolicy, windows.SERVICE_DEMAND_START); err == nil {
		j.Close()
		t.Fatal("changed start type accepted")
	}
	j, err = openDisableStopJournal(archive, f.sddl, f.txn, binding, f.stagePolicy, windows.SERVICE_AUTO_START)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if j.CanRestart() {
		t.Fatal("interrupted disable can restart automatically")
	}
}
func TestDisableStopJournalFailsClosedAfterForcedTermination(t *testing.T) {
	binding := upgradeJournalBinding{Volume: 1, IndexHigh: 2, IndexLow: 3, SHA256: strings.Repeat("a", 64)}
	if os.Getenv("TT_DISABLE_REVIEW_CHILD") == "1" {
		var w releaseFixtureWire
		if err := json.Unmarshal([]byte(os.Getenv("TT_DISABLE_REVIEW_FIXTURE")), &w); err != nil {
			t.Fatal(err)
		}
		j, err := openDisableStopJournal(filepath.Join(w.Parent, "disable-review"), w.SDDL, w.Transaction, binding, w.StagePolicy, windows.SERVICE_AUTO_START)
		if err != nil {
			t.Fatal(err)
		}
		defer j.Close()
		err = disableAndStopUnderVerifiedLock(context.Background(), &fakeDisableStop{}, pauseRestartJournal{inner: j, stop: os.Getenv("TT_DISABLE_REVIEW_STEP"), ready: filepath.Join(w.Parent, "disable-ready")})
		t.Fatalf("unexpected return: %v", err)
	}
	for _, step := range []string{"verify-before", "disable-requested", "verify-disabled", "stop-requested", "verify-stopped", "stopped-verified"} {
		t.Run(step, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			archive := filepath.Join(f.parent, "disable-review")
			if err := createRestrictedDirectory(archive, f.sddl); err != nil {
				t.Fatal(err)
			}
			wire, _ := json.Marshal(releaseFixtureWire{f.parent, f.journal, f.sddl, f.txn, f.parentPolicy, f.stagePolicy})
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestDisableStopJournalFailsClosedAfterForcedTermination$")
			cmd.Env = append(os.Environ(), "TT_DISABLE_REVIEW_CHILD=1", "TT_DISABLE_REVIEW_FIXTURE="+string(wire), "TT_DISABLE_REVIEW_STEP="+step)
			var output strings.Builder
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			ready := filepath.Join(f.parent, "disable-ready")
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if _, err = os.Stat(ready); err != nil {
				t.Fatalf("checkpoint not reached: %s", output.String())
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			j, err := openDisableStopJournal(archive, f.sddl, f.txn, binding, f.stagePolicy, windows.SERVICE_AUTO_START)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			c := &fakeDisableStop{}
			err = disableAndStopUnderVerifiedLock(context.Background(), c, j)
			if step == "verify-before" && err != nil {
				t.Fatalf("pre-disable retry rejected: %v", err)
			}
			if step != "verify-before" && (err == nil || len(c.calls) != 0) {
				t.Fatal("retry performed SCM action after interrupted disable")
			}
		})
	}
}

func TestDisableStopJournalCannotTransitionToStart(t *testing.T) {
	p := restartProgress{mode: "disable-and-stop-v1"}
	for _, step := range []string{"verify-before", "disable-requested", "verify-disabled", "stop-requested", "verify-stopped"} {
		next, err := advanceRestartProgress(p, step)
		if err != nil {
			t.Fatal(err)
		}
		p = next
	}
	if _, err := advanceRestartProgress(p, "start-requested"); err == nil {
		t.Fatal("disable-and-stop journal accepted start")
	}
	if _, err := advanceRestartProgress(p, "stopped-verified"); err != nil {
		t.Fatal(err)
	}
}
func TestDisableStopProtectedJournalRejectsStart(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	archive := filepath.Join(f.parent, "disable-review")
	if err := createRestrictedDirectory(archive, f.sddl); err != nil {
		t.Fatal(err)
	}
	binding := upgradeJournalBinding{Volume: 1, IndexHigh: 2, IndexLow: 3, SHA256: strings.Repeat("a", 64)}
	j, err := openDisableStopJournal(archive, f.sddl, f.txn, binding, f.stagePolicy, windows.SERVICE_AUTO_START)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"verify-before", "disable-requested", "verify-disabled", "stop-requested", "verify-stopped"} {
		if err = j.FlushStep(step); err != nil {
			t.Fatal(err)
		}
	}
	if err = j.FlushStep("start-requested"); err == nil {
		t.Fatal("protected disable-and-stop journal accepted start")
	}
	if err = j.FlushStep("stopped-verified"); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(archive, "restart-review.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "start-requested") {
		t.Fatal("refused start was persisted")
	}
	reopened, err := openDisableStopJournal(archive, f.sddl, f.txn, binding, f.stagePolicy, windows.SERVICE_AUTO_START)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.CanRestart() {
		t.Fatal("completed disable-and-stop resumed automatically")
	}
}

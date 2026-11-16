//go:build windows

package verifiedextraction

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

type releaseFixture struct {
	parent, journal, sddl, txn string
	parentPolicy, stagePolicy  bootstraplock.Policy
	stages                     []string
}

type releaseFixtureWire struct {
	Parent, Journal, SDDL, Transaction string
	ParentPolicy, StagePolicy          bootstraplock.Policy
}

func TestManualQuarantineReleaseSurvivesKilledProcess(t *testing.T) {
	if os.Getenv("TT_RELEASE_CRASH_CHILD") == "1" {
		var w releaseFixtureWire
		if err := json.Unmarshal([]byte(os.Getenv("TT_RELEASE_CRASH_FIXTURE")), &w); err != nil {
			t.Fatal(err)
		}
		step := os.Getenv("TT_RELEASE_CRASH_STEP")
		signal := func() {
			if err := os.WriteFile(filepath.Join(w.Parent, "crash-ready"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
			for {
				time.Sleep(time.Second)
			}
		}
		calls := 0
		rename := func(h windows.Handle, from, to string) error {
			calls++
			if calls == 1 && step == "before-first" {
				signal()
			}
			err := renameOpenFile(h, to)
			if err != nil {
				return err
			}
			if calls == 1 && step == "after-first" || calls == 2 && step == "after-second" {
				signal()
			}
			return nil
		}
		handleCalls := 0
		renameHandle := func(h windows.Handle, destination string) error {
			handleCalls++
			if err := renameOpenFile(h, destination); err != nil {
				return err
			}
			if handleCalls == 1 && step == "after-sentinel" || handleCalls == 2 && step == "after-barrier" {
				signal()
			}
			return nil
		}
		_, err := releaseQuarantinePair(w.Parent, w.Journal, w.Transaction, w.ParentPolicy, w.StagePolicy, w.SDDL, rename, renameHandle)
		t.Fatalf("fixture unexpectedly returned: %v", err)
	}
	for _, step := range []string{"before-first", "after-first", "after-second", "after-sentinel", "after-barrier"} {
		t.Run(step, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			w := releaseFixtureWire{f.parent, f.journal, f.sddl, f.txn, f.parentPolicy, f.stagePolicy}
			b, err := json.Marshal(w)
			if err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestManualQuarantineReleaseSurvivesKilledProcess$")
			cmd.Env = append(os.Environ(), "TT_RELEASE_CRASH_CHILD=1", "TT_RELEASE_CRASH_FIXTURE="+string(b), "TT_RELEASE_CRASH_STEP="+step)
			var output strings.Builder
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(filepath.Join(f.parent, "crash-ready")); err == nil {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if _, err := os.Stat(filepath.Join(f.parent, "crash-ready")); err != nil {
				t.Fatalf("child did not reach boundary: %s", output.String())
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			sentinel := filepath.Join(f.parent, "TokenTimer-Staging-"+f.txn+".intent")
			if _, err := os.Stat(f.journal); err != nil && step != "after-barrier" {
				t.Fatal("killed process did not retain upgrade barrier")
			}
			if step != "after-sentinel" && step != "after-barrier" {
				if _, err := os.Stat(sentinel); err != nil {
					t.Fatal("killed process did not retain sentinel")
				}
			}
			if _, err := f.release(renameProtectedMarker); err != nil {
				t.Fatalf("resume after process termination: %v", err)
			}
			if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
				t.Fatal("sentinel remains after reviewed completion")
			}
		})
	}
}

func newReleaseFixture(t *testing.T, transaction string) releaseFixture {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sddl := "O:" + sid + "G:" + sid + "D:P(A;OICI;FA;;;" + sid + ")"
	parent := filepath.Join(t.TempDir(), "protected-parent")
	if err := createRestrictedDirectory(parent, sddl); err != nil {
		t.Fatal(err)
	}
	agentRoot := filepath.Join(parent, "TokenTimerAgent")
	stateDir := filepath.Join(agentRoot, "state")
	if err := createRestrictedDirectory(agentRoot, sddl); err != nil {
		t.Fatal(err)
	}
	if err := createRestrictedDirectory(stateDir, sddl); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]bool{sid: true, "S-1-5-18": true, "S-1-5-32-544": true, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true}
	// This non-elevated fixture accepts ambient test-runner ancestors only;
	// the actual private parent/stages remain owned and writable by this SID.
	for cursor := filepath.Dir(parent); ; cursor = filepath.Dir(cursor) {
		sd, err := windows.GetNamedSecurityInfo(cursor, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := sd.Owner()
		if err != nil {
			t.Fatal(err)
		}
		trusted[owner.String()] = true
		acl, _, err := sd.DACL()
		if err != nil || acl == nil {
			t.Fatal("fixture ancestor DACL unavailable")
		}
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, i, &ace); err != nil {
				t.Fatal(err)
			}
			if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
				s := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
				trusted[s.String()] = true
			}
		}
		if filepath.Dir(cursor) == cursor {
			break
		}
	}
	parentPolicy := bootstraplock.Policy{Owners: trusted, Writers: trusted}
	stagePolicy := bootstraplock.Policy{Owners: map[string]bool{sid: true}, Writers: map[string]bool{sid: true}}
	secret := strings.Repeat("d", 64)
	var stages []string
	for _, digit := range []string{"a", "b"} {
		root := filepath.Join(parent, "TokenTimer-Staging-"+strings.Repeat(digit, 32))
		if err := createRestrictedDirectory(root, sddl); err != nil {
			t.Fatal(err)
		}
		id, err := getDirectoryIdentity(root)
		if err != nil {
			t.Fatal(err)
		}
		stage := &PrivateStaging{freshOwned: true, path: root, parent: parent, identity: id, policy: stagePolicy, ancestors: &bootstraplock.Locks{}, staging: &bootstraplock.Locks{}, payload: &bootstraplock.Locks{}}
		if _, err := stage.beginExecutionIntentForTransaction(fixtureArchive, fixtureSCM, sddl, transaction, secret, defaultIntentIO()); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "retained.txt"), []byte("retained"), 0600); err != nil {
			t.Fatal(err)
		}
		stages = append(stages, root)
	}
	return releaseFixture{parent: parent, journal: filepath.Join(stateDir, "upgrade-recovery.json"), sddl: sddl, txn: transaction, parentPolicy: parentPolicy, stagePolicy: stagePolicy, stages: stages}
}

func (f releaseFixture) release(rename func(windows.Handle, string, string) error) (string, error) {
	return f.releaseWithHandles(rename, renameOpenFile)
}

func (f releaseFixture) releaseWithHandles(rename func(windows.Handle, string, string) error, renameHandle func(windows.Handle, string) error) (string, error) {
	return releaseQuarantinePair(f.parent, f.journal, f.txn, f.parentPolicy, f.stagePolicy, f.sddl, rename, renameHandle)
}

func TestManualQuarantineReleaseRequiresOperatorAcknowledgement(t *testing.T) {
	if _, err := ReleaseQuarantineAfterOperatorReview(context.Background(), strings.Repeat("f", 32), false); err == nil {
		t.Fatal("operator acknowledgement not enforced")
	}
}

func TestManualQuarantineReleaseRejectsAcknowledgementWithoutQueuedActionProof(t *testing.T) {
	archive, err := ReleaseQuarantineAfterOperatorReview(context.Background(), strings.Repeat("f", 32), true)
	if archive != "" || !errors.Is(err, ErrQueuedSCMActionProofUnavailable) {
		t.Fatalf("operator acknowledgement must not replace queued action proof: archive=%q err=%v", archive, err)
	}
}

// This opt-in test creates only a new, empty agent fixture at the real product
// path. It refuses an existing installation and is for disposable VMs only.
func TestManualQuarantineReleaseRefusesRealUpgradeJournal(t *testing.T) {
	if os.Getenv("TT_REQUIRE_QUARANTINE_NATIVE") != "1" {
		t.Skip("authorized disposable Windows VM required")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("elevated token required")
	}
	root := `C:\ProgramData\TokenTimerAgent`
	if filepath.Clean(root) != root || !filepath.IsAbs(root) {
		t.Fatal("invalid fixture root")
	}
	sddl := "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if err := createRestrictedDirectory(root, sddl); err != nil {
		t.Fatalf("refusing pre-existing or inaccessible agent root: %v", err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	if err := createRestrictedDirectory(state, sddl); err != nil {
		t.Fatal(err)
	}
	stateInfo, err := os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(state, "upgrade-recovery.json")
	f, err := os.OpenFile(journal, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("fixture"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	journalInfo, err := os.Stat(journal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		current, err := os.Lstat(journal)
		if err != nil || !os.SameFile(journalInfo, current) {
			t.Error("journal fixture identity changed; retained")
			return
		}
		if err := os.Remove(journal); err != nil {
			t.Errorf("remove journal fixture: %v", err)
			return
		}
		current, err = os.Lstat(state)
		if err != nil || !os.SameFile(stateInfo, current) {
			t.Error("state fixture identity changed; retained")
			return
		}
		if err := os.Remove(state); err != nil {
			t.Errorf("remove empty fixture state: %v", err)
			return
		}
		current, err = os.Lstat(root)
		if err != nil || !os.SameFile(rootInfo, current) {
			t.Error("agent fixture identity changed; retained")
			return
		}
		if err := os.Remove(root); err != nil {
			t.Errorf("remove empty fixture root: %v", err)
		}
	}()
	_, err = ReleaseQuarantineAfterOperatorReview(context.Background(), strings.Repeat("f", 32), true)
	if !errors.Is(err, ErrQueuedSCMActionProofUnavailable) {
		t.Fatalf("missing queued-action proof not refused: %v", err)
	}
	if b, err := os.ReadFile(journal); err != nil || string(b) != "fixture" {
		t.Fatal("real upgrade journal was modified")
	}
}

func TestManualQuarantineReleaseArchivesOnlyAfterReview(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	archive, err := f.release(renameProtectedMarker)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range f.stages {
		if _, err := os.Stat(filepath.Join(stage, "retained.txt")); err != nil {
			t.Fatal("stage content was removed")
		}
		if _, err := os.Stat(stage + ".intent"); !os.IsNotExist(err) {
			t.Fatal("live marker remains")
		}
		if _, err := os.Stat(filepath.Join(f.parent, archive, filepath.Base(stage)+".intent")); err != nil {
			t.Fatal("marker not archived")
		}
	}
	b, err := os.ReadFile(filepath.Join(f.parent, archive, "review-approved.json"))
	if err != nil {
		t.Fatal("operator declaration missing")
	}
	var declaration releaseDeclaration
	if err := json.Unmarshal(b, &declaration); err != nil || declaration.Transaction != f.txn || declaration.Statement != "operator-reviewed-external-actor-risk" || len(declaration.Stages) != 2 || strings.Contains(string(b), strings.Repeat("d", 64)) {
		t.Fatal("operator declaration invalid or leaked secret")
	}
	if _, err := os.Stat(filepath.Join(f.parent, archive, "review-barrier.json")); err != nil {
		t.Fatal("upgrade barrier evidence missing")
	}
	if _, err := os.Stat(f.journal); !os.IsNotExist(err) {
		t.Fatal("upgrade barrier remains after completed review")
	}
}

func TestManualQuarantineReleaseBlocksConcurrentJournalCreateOrRemoval(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	calls := 0
	rename := func(h windows.Handle, from, to string) error {
		calls++
		if calls == 1 {
			file, err := os.OpenFile(f.journal, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err == nil {
				_ = file.Close()
				t.Error("concurrent journal CREATE_NEW succeeded")
			}
			if err := os.Remove(f.journal); err == nil {
				t.Error("concurrent journal barrier removal succeeded")
			}
		}
		return renameOpenFile(h, to)
	}
	if _, err := f.release(rename); err != nil {
		t.Fatal(err)
	}
}

func TestManualQuarantineReleaseLocksMarkersAgainstReplacement(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	checked := 0
	rename := func(h windows.Handle, from, to string) error {
		checked++
		if err := os.Remove(from); err == nil {
			t.Error("marker removed while open")
		}
		if err := os.Rename(from, from+"-replaced"); err == nil {
			t.Error("marker renamed while open")
		}
		if err := os.WriteFile(from, []byte("replacement"), 0600); err == nil {
			t.Error("marker overwritten while open")
		}
		return renameOpenFile(h, to)
	}
	if _, err := f.release(rename); err != nil {
		t.Fatal(err)
	}
	if checked != 2 {
		t.Fatalf("expected two marker moves, got %d", checked)
	}
}

func TestManualQuarantineReleaseRenamesOpenBarrierWithoutReplacementWindow(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	checked := 0
	renameHandle := func(h windows.Handle, destination string) error {
		checked++
		if err := os.Remove(f.journal); err == nil {
			t.Error("barrier removed while open")
		}
		if err := os.Rename(f.journal, f.journal+"-replaced"); err == nil {
			t.Error("barrier renamed by concurrent actor")
		}
		if err := os.WriteFile(f.journal, []byte("replacement"), 0600); err == nil {
			t.Error("barrier overwritten by concurrent actor")
		}
		return renameOpenFile(h, destination)
	}
	archive, err := f.releaseWithHandles(renameProtectedMarker, renameHandle)
	if err != nil {
		t.Fatal(err)
	}
	if checked != 2 {
		t.Fatal("open-handle rename was not exercised")
	}
	if _, err := os.Stat(filepath.Join(f.parent, archive, "review-barrier.json")); err != nil {
		t.Fatal("barrier evidence missing")
	}
}

func TestManualQuarantineReleaseRejectsJournalAndCollision(t *testing.T) {
	t.Run("journal", func(t *testing.T) {
		f := newReleaseFixture(t, strings.Repeat("f", 32))
		original := []byte(`{"version":1,"pid":123,"launcherIntent":"authenticated"}`)
		if err := os.WriteFile(f.journal, original, 0600); err != nil {
			t.Fatal(err)
		}
		sd, err := windows.SecurityDescriptorFromString(f.sddl)
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(f.journal, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := f.release(renameProtectedMarker); err == nil {
			t.Fatal("upgrade journal accepted")
		}
		if got, err := os.ReadFile(f.journal); err != nil || string(got) != string(original) {
			t.Fatal("upgrade journal was modified")
		}
		if _, err := os.Stat(filepath.Join(f.parent, "TokenTimer-Quarantine-"+f.txn)); !os.IsNotExist(err) {
			t.Fatal("archive created despite existing upgrade journal")
		}
		for _, stage := range f.stages {
			if _, err := os.Stat(stage + ".intent"); err != nil {
				t.Fatal("marker changed")
			}
		}
	})
	t.Run("sentinel collision", func(t *testing.T) {
		f := newReleaseFixture(t, strings.Repeat("a", 32))
		if _, err := f.release(renameProtectedMarker); err == nil {
			t.Fatal("sentinel collision accepted")
		}
		for _, stage := range f.stages {
			if _, err := os.Stat(stage + ".intent"); err != nil {
				t.Fatal("marker changed")
			}
		}
	})
}

func TestManualQuarantineReleaseRejectsUnverifiableState(t *testing.T) {
	for _, mode := range []string{"missing-state", "untrusted-acl", "junction"} {
		t.Run(mode, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			state := filepath.Dir(f.journal)
			switch mode {
			case "missing-state":
				if err := os.Remove(state); err != nil {
					t.Fatal(err)
				}
			case "untrusted-acl":
				sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
				if err != nil {
					t.Fatal(err)
				}
				acl, _, err := sd.DACL()
				if err != nil {
					t.Fatal(err)
				}
				if err := windows.SetNamedSecurityInfo(state, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
					t.Fatal(err)
				}
			case "junction":
				if err := os.Remove(state); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(f.parent, "other-state")
				if err := createRestrictedDirectory(target, f.sddl); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "New-Item -ItemType Junction -Path $env:TT_JUNCTION -Target $env:TT_TARGET -ErrorAction Stop | Out-Null")
				cmd.Env = append(os.Environ(), "TT_JUNCTION="+state, "TT_TARGET="+target)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Skipf("junction unavailable: %v: %s", err, out)
				}
			}
			if _, err := f.release(renameProtectedMarker); err == nil {
				t.Fatal("unverifiable state accepted")
			}
			for _, stage := range f.stages {
				if _, err := os.Stat(stage + ".intent"); err != nil {
					t.Fatal("marker changed")
				}
			}
		})
	}
}

func TestAbsentUpgradeJournalLocksStateAgainstReplacement(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	unlock, err := lockUpgradeState(f.journal, f.parentPolicy, f.stagePolicy)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Dir(f.journal)
	replacement := state + "-moved"
	if err := os.Rename(state, replacement); err == nil {
		unlock()
		t.Fatal("locked state directory was replaced")
	}
	unlock()
	if err := os.Rename(state, replacement); err != nil {
		t.Fatalf("state remained locked after inspection: %v", err)
	}
	if err := os.Rename(replacement, state); err != nil {
		t.Fatal(err)
	}
}

func TestAbsentUpgradeJournalAllowsAncestorChildCreationWithoutStateReplacement(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	state := filepath.Dir(f.journal)
	root := filepath.Dir(state)
	sid := mustCurrentSID(t)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")(A;;0x00000004;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockUpgradeState(f.journal, f.parentPolicy, f.stagePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "concurrent-child"), 0700); err != nil {
		unlock()
		t.Fatalf("unrelated child creation blocked: %v", err)
	}
	if err := os.Rename(state, state+"-moved"); err == nil {
		unlock()
		t.Fatal("protected state was replaced")
	}
	unlock()
}

func TestManualQuarantineReleaseRollbackAndCrashRemainBlocked(t *testing.T) {
	for _, mode := range []string{"second-fails", "rollback-fails", "crash-before-first", "crash-after-first", "crash-after-second", "crash-after-sentinel", "crash-after-barrier"} {
		t.Run(mode, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			calls := 0
			rename := func(h windows.Handle, from, to string) error {
				calls++
				if calls == 1 && mode == "crash-before-first" {
					panic("simulated crash")
				}
				if calls == 2 {
					if mode == "crash-after-first" {
						panic("simulated crash")
					}
					if mode == "crash-after-second" {
						if err := renameOpenFile(h, to); err != nil {
							return err
						}
						panic("simulated crash")
					}
					return errors.New("injected failure")
				}
				if calls == 3 && mode == "rollback-fails" {
					return errors.New("rollback failure")
				}
				return renameOpenFile(h, to)
			}
			func() {
				defer func() {
					if r := recover(); r != nil && !strings.HasPrefix(mode, "crash-") {
						panic(r)
					}
				}()
				handleCalls := 0
				renameHandle := func(h windows.Handle, destination string) error {
					handleCalls++
					if err := renameOpenFile(h, destination); err != nil {
						return err
					}
					if handleCalls == 1 && mode == "crash-after-sentinel" || handleCalls == 2 && mode == "crash-after-barrier" {
						panic("simulated crash")
					}
					return nil
				}
				if _, err := f.releaseWithHandles(rename, renameHandle); err == nil {
					t.Error("injected failure accepted")
				}
			}()
			entries, err := os.ReadDir(f.parent)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, entry := range entries {
				n := strings.ToLower(entry.Name())
				if strings.HasPrefix(n, "tokentimer-staging-") && strings.HasSuffix(n, ".intent") {
					count++
				}
			}
			if count == 0 && mode != "crash-after-barrier" {
				if _, err := os.Stat(f.journal); err != nil {
					t.Fatal("failure allowed new installation")
				}
			}
			sentinel := filepath.Join(f.parent, "TokenTimer-Staging-"+f.txn+".intent")
			if _, err := os.Stat(sentinel); err != nil && mode != "crash-after-sentinel" && mode != "crash-after-barrier" {
				t.Fatal("crash did not retain sentinel")
			}
			for _, stage := range f.stages {
				if _, err := os.Stat(filepath.Join(stage, "retained.txt")); err != nil {
					t.Fatal(fmt.Errorf("stage removed: %w", err))
				}
			}
			archive, err := f.release(renameProtectedMarker)
			if err != nil {
				t.Fatalf("retry after interruption: %v", err)
			}
			if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
				t.Fatal("sentinel remains after successful retry")
			}
			if _, err := os.Stat(filepath.Join(f.parent, archive, "review-approved.json")); err != nil {
				t.Fatal("review evidence missing after retry")
			}
		})
	}
}

func TestManualQuarantineReleaseRetriesEmptyArchiveBeforeSentinel(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	archive := filepath.Join(f.parent, "TokenTimer-Quarantine-"+f.txn)
	if err := createRestrictedDirectory(archive, f.sddl); err != nil {
		t.Fatal(err)
	}
	if _, err := f.release(renameProtectedMarker); err != nil {
		t.Fatalf("retry after archive creation: %v", err)
	}
}

func TestManualQuarantineReleaseRefusesTamperedSentinelOnRetry(t *testing.T) {
	for _, mode := range []string{"operator", "stage-identity", "transaction", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			calls := 0
			func() {
				defer func() { _ = recover() }()
				_, _ = f.release(func(h windows.Handle, from, to string) error {
					calls++
					if calls == 2 {
						panic("simulated interruption")
					}
					return renameOpenFile(h, to)
				})
			}()
			sentinel := filepath.Join(f.parent, "TokenTimer-Staging-"+f.txn+".intent")
			b, err := os.ReadFile(sentinel)
			if err != nil {
				t.Fatal(err)
			}
			var declaration releaseDeclaration
			if err := json.Unmarshal(b, &declaration); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "operator":
				declaration.OperatorSID = "S-1-5-18"
				if declaration.OperatorSID == mustCurrentSID(t) {
					declaration.OperatorSID = "S-1-5-32-544"
				}
			case "stage-identity":
				declaration.Stages[0].IndexLow++
			case "transaction":
				declaration.Transaction = strings.Repeat("e", 32)
			}
			if mode == "malformed" {
				b = []byte(`{"schemaVersion":`)
			} else {
				b, err = json.Marshal(declaration)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(sentinel, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := f.release(renameProtectedMarker); err == nil {
				t.Fatal("tampered sentinel accepted")
			}
			if _, err := os.Stat(sentinel); err != nil {
				t.Fatal("tampered sentinel did not retain quarantine")
			}
		})
	}
}

func mustCurrentSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

//go:build windows

package verifiedextraction

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tokentimer-verified-extraction/bootstraplock"
)

func TestKeepCurrentLayoutRequiresExactIdentitiesAndNoStaging(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		record                 upgradeRecord
		app, previous, staging string
		ok                     bool
	}{
		{"candidate", upgradeRecord{PreviousIdentity: "11:22", StagingIdentity: "11:33"}, "11:33", "11:22", "absent", true},
		{"same identity", upgradeRecord{PreviousIdentity: "11:22", StagingIdentity: "11:22"}, "11:22", "11:22", "absent", false},
		{"unexpected app", upgradeRecord{PreviousIdentity: "11:22", StagingIdentity: "11:33"}, "11:44", "11:22", "absent", false},
		{"old app", upgradeRecord{PreviousIdentity: "11:22", StagingIdentity: "11:33"}, "11:22", "11:22", "absent", false},
		{"missing backup", upgradeRecord{PreviousIdentity: "11:22", StagingIdentity: "11:33"}, "11:33", "absent", "absent", false},
		{"wrong backup", upgradeRecord{PreviousIdentity: "11:22", StagingIdentity: "11:33"}, "11:33", "11:44", "absent", false},
		{"staging present", upgradeRecord{PreviousIdentity: "11:22", StagingIdentity: "11:33"}, "11:33", "11:22", "11:33", false},
		{"staging unobserved", upgradeRecord{PreviousIdentity: "11:22", StagingIdentity: "11:33"}, "11:33", "11:22", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkKeepCurrentLayout(tc.record, tc.app, tc.previous, tc.staging)
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected result %v", err)
			}
		})
	}
}

func TestUpgradeJournalExclusiveBarrier(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	journal := []byte(`{"version":1,"pid":321,"previousIdentity":"11:22","stagingIdentity":"11:33","previousServicePath":"private","previousServiceDisplayName":"private","previousServiceStartMode":"Manual","hadPreviousServiceEnvironment":false,"previousServiceEnvironment":[],"launcherIntent":"` + f.txn + `"}`)
	writeProtectedUpgradeFixture(t, f, journal)
	h, rec, err := openUpgradeJournalForReview(f.journal, f.stagePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if rec.LauncherIntent != f.txn {
		t.Fatal("wrong transaction")
	}
	if _, err := os.ReadFile(f.journal); err == nil {
		t.Error("concurrent read accepted")
	}
	if err := os.Remove(f.journal); err == nil {
		t.Error("concurrent removal accepted")
	}
	if err := os.WriteFile(f.journal, []byte("overwrite"), 0600); err == nil {
		t.Error("concurrent overwrite accepted")
	}
	if err := windows.CloseHandle(h); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(f.journal)
	if err != nil || string(after) != string(journal) {
		t.Fatal("journal not preserved")
	}
}

func reviewedUpgradeFixture(t *testing.T) (releaseFixture, string, []byte) {
	t.Helper()
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	root := filepath.Dir(filepath.Dir(f.journal))
	app := filepath.Join(root, "app")
	previous := app + ".previous.321"
	if err := createRestrictedDirectory(app, f.sddl); err != nil {
		t.Fatal(err)
	}
	if err := createRestrictedDirectory(previous, f.sddl); err != nil {
		t.Fatal(err)
	}
	aid, err := getDirectoryIdentity(app)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := getDirectoryIdentity(previous)
	if err != nil {
		t.Fatal(err)
	}
	native := func(id directoryIdentity) string {
		return fmt.Sprintf("%d:%d", id.volume, uint64(id.indexHigh)<<32|uint64(id.indexLow))
	}
	record := upgradeRecord{Version: 1, PID: 321, PreviousIdentity: native(pid), StagingIdentity: native(aid), PreviousServicePath: "private", PreviousServiceDisplayName: "private", PreviousServiceStartMode: "Automatic", PreviousServiceEnvironment: json.RawMessage(`[]`), LauncherIntent: f.txn, IdentityContract: &fixtureIdentityPin}
	b, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeProtectedUpgradeFixture(t, f, b)
	return f, root, b
}
func testReviewedUpgrade(f releaseFixture, actors, keep bool, marker func(windows.Handle, string, string) error, rename func(windows.Handle, string) error) (string, error) {
	return releaseReviewedUpgrade(f.parent, f.journal, f.txn, f.parentPolicy, f.stagePolicy, f.sddl, actors, keep, fixtureIdentityPin, func(string, string, identityContract, bootstraplock.Policy) error { return nil }, func(string) error { return nil }, testActiveVerifier, marker, rename)
}
func TestReviewedUpgradePreservesDataAndRequiresBothDecisions(t *testing.T) {
	f, root, journal := reviewedUpgradeFixture(t)
	for _, ack := range [][2]bool{{false, false}, {true, false}, {false, true}} {
		if _, err := testReviewedUpgrade(f, ack[0], ack[1], renameProtectedMarker, renameOpenFile); err == nil {
			t.Fatal("missing decision accepted")
		}
	}
	archive, err := testReviewedUpgrade(f, true, true, renameProtectedMarker, renameOpenFile)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(f.parent, archive, "upgrade-recovery.json"))
	if err != nil || string(data) != string(journal) {
		t.Fatal("journal was not preserved")
	}
	for _, path := range append([]string{filepath.Join(root, "app"), filepath.Join(root, "app.previous.321")}, f.stages...) {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("retained path unavailable: %v", err)
		}
	}
	if _, err := os.Stat(f.journal); !os.IsNotExist(err) {
		t.Fatal("journal still at original location")
	}
}
func TestReviewedUpgradeRejectsAmbiguousLayoutBeforeMutation(t *testing.T) {
	f, root, journal := reviewedUpgradeFixture(t)
	if err := createRestrictedDirectory(filepath.Join(root, "app.staging.321"), f.sddl); err != nil {
		t.Fatal(err)
	}
	if _, err := testReviewedUpgrade(f, true, true, renameProtectedMarker, renameOpenFile); err == nil {
		t.Fatal("staging present accepted")
	}
	data, err := os.ReadFile(f.journal)
	if err != nil || string(data) != string(journal) {
		t.Fatal("journal changed")
	}
	if _, err = os.Stat(filepath.Join(f.parent, "TokenTimer-UpgradeReview-"+f.txn)); !os.IsNotExist(err) {
		t.Fatal("archive created before conditions")
	}
}
func TestReviewedUpgradeResumesAfterInterruptedMoves(t *testing.T) {
	for _, step := range []string{"second-marker", "sentinel", "journal"} {
		t.Run(step, func(t *testing.T) {
			f, _, journal := reviewedUpgradeFixture(t)
			count := 0
			marker := func(h windows.Handle, from, to string) error {
				count++
				if step == "second-marker" && count == 2 {
					return fmt.Errorf("injected marker failure")
				}
				return renameOpenFile(h, to)
			}
			handle := func(h windows.Handle, to string) error {
				if step == "sentinel" && strings.HasSuffix(to, "review-approved.json") {
					return fmt.Errorf("injected sentinel failure")
				}
				if step == "journal" && strings.HasSuffix(to, "upgrade-recovery.json") {
					return fmt.Errorf("injected journal failure")
				}
				return renameOpenFile(h, to)
			}
			if _, err := testReviewedUpgrade(f, true, true, marker, handle); err == nil {
				t.Fatal("injection did not fail")
			}
			data, err := os.ReadFile(f.journal)
			if err != nil || string(data) != string(journal) {
				t.Fatal("journal not retained after interruption")
			}
			if _, err = testReviewedUpgrade(f, true, true, renameProtectedMarker, renameOpenFile); err != nil {
				t.Fatalf("retry failed: %v", err)
			}
		})
	}
}

func TestReviewedUpgradeSurvivesKilledProcess(t *testing.T) {
	if os.Getenv("TT_UPGRADE_REVIEW_CHILD") == "1" {
		var w releaseFixtureWire
		if err := json.Unmarshal([]byte(os.Getenv("TT_UPGRADE_REVIEW_FIXTURE")), &w); err != nil {
			t.Fatal(err)
		}
		step := os.Getenv("TT_UPGRADE_REVIEW_STEP")
		signal := func() {
			if err := os.WriteFile(filepath.Join(w.Parent, "upgrade-crash-ready"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
			for {
				time.Sleep(time.Second)
			}
		}
		count := 0
		marker := func(h windows.Handle, from, to string) error {
			count++
			if count == 1 && step == "before-first" {
				signal()
			}
			if err := renameOpenFile(h, to); err != nil {
				return err
			}
			if count == 1 && step == "after-first" || count == 2 && step == "after-second" {
				signal()
			}
			return nil
		}
		rename := func(h windows.Handle, to string) error {
			if err := renameOpenFile(h, to); err != nil {
				return err
			}
			if strings.HasSuffix(to, "review-approved.json") && step == "after-sentinel" || strings.HasSuffix(to, "upgrade-recovery.json") && step == "after-journal" {
				signal()
			}
			return nil
		}
		_, err := releaseReviewedUpgrade(w.Parent, w.Journal, w.Transaction, w.ParentPolicy, w.StagePolicy, w.SDDL, true, true, fixtureIdentityPin, func(string, string, identityContract, bootstraplock.Policy) error { return nil }, func(string) error { return nil }, testActiveVerifier, marker, rename)
		t.Fatalf("unexpected return: %v", err)
	}
	for _, step := range []string{"before-first", "after-first", "after-second", "after-sentinel", "after-journal"} {
		t.Run(step, func(t *testing.T) {
			f, _, journal := reviewedUpgradeFixture(t)
			wire, _ := json.Marshal(releaseFixtureWire{f.parent, f.journal, f.sddl, f.txn, f.parentPolicy, f.stagePolicy})
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestReviewedUpgradeSurvivesKilledProcess$")
			cmd.Env = append(os.Environ(), "TT_UPGRADE_REVIEW_CHILD=1", "TT_UPGRADE_REVIEW_FIXTURE="+string(wire), "TT_UPGRADE_REVIEW_STEP="+step)
			var output strings.Builder
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(filepath.Join(f.parent, "upgrade-crash-ready")); err == nil {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if _, err = os.Stat(filepath.Join(f.parent, "upgrade-crash-ready")); err != nil {
				t.Fatalf("child did not reach boundary: %s", output.String())
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			if step != "after-journal" {
				data, err := os.ReadFile(f.journal)
				if err != nil || string(data) != string(journal) {
					t.Fatal("journal lost after process kill")
				}
				if _, err = testReviewedUpgrade(f, true, true, renameProtectedMarker, renameOpenFile); err != nil {
					t.Fatalf("resume failed: %v", err)
				}
			}
			archived, err := os.ReadFile(filepath.Join(f.parent, "TokenTimer-UpgradeReview-"+f.txn, "upgrade-recovery.json"))
			if err != nil || string(archived) != string(journal) {
				t.Fatal("archive missing after resume")
			}
		})
	}
}

func TestReviewedUpgradeRejectsChangedJournalOnRetry(t *testing.T) {
	for _, mode := range []string{"replace-same-bytes", "modify-in-place"} {
		t.Run(mode, func(t *testing.T) {
			f, _, journal := reviewedUpgradeFixture(t)
			moves := 0
			marker := func(h windows.Handle, from, to string) error {
				moves++
				if moves == 2 {
					return fmt.Errorf("stop")
				}
				return renameOpenFile(h, to)
			}
			if _, err := testReviewedUpgrade(f, true, true, marker, renameOpenFile); err == nil {
				t.Fatal("interruption did not fire")
			}
			if mode == "replace-same-bytes" {
				other := f.journal + ".replacement"
				if err := os.WriteFile(other, journal, 0600); err != nil {
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
				if err = windows.SetNamedSecurityInfo(other, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(f.journal, f.journal+".old"); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(other, f.journal); err != nil {
					t.Fatal(err)
				}
			} else {
				var rec upgradeRecord
				if err := json.Unmarshal(journal, &rec); err != nil {
					t.Fatal(err)
				}
				rec.PreviousServicePath = "changed"
				changed, _ := json.Marshal(rec)
				if err := os.WriteFile(f.journal, changed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := testReviewedUpgrade(f, true, true, renameProtectedMarker, renameOpenFile); err == nil {
				t.Fatal("changed journal accepted")
			}
			if _, err := os.Stat(f.journal); err != nil {
				t.Fatal("journal was removed after refused retry")
			}
		})
	}
}

var fixtureIdentityPin = identityContract{Scheme: "node-fs-win32-v1", NodeVersion: "24.18.0", Architecture: "amd64", NodeSHA256: strings.Repeat("a", 64)}

func TestIdentityContractRequiresIndependentPin(t *testing.T) {
	good := fixtureIdentityPin
	for _, tc := range []struct {
		name   string
		record *identityContract
		pin    identityContract
		ok     bool
	}{
		{"match", &good, good, true}, {"legacy", nil, good, false},
		{"untrusted policy", &good, identityContract{}, false},
		{"different hash", &good, identityContract{Scheme: good.Scheme, NodeVersion: good.NodeVersion, Architecture: good.Architecture, NodeSHA256: strings.Repeat("b", 64)}, false},
		{"different version", &good, identityContract{Scheme: good.Scheme, NodeVersion: "23.0.0", Architecture: good.Architecture, NodeSHA256: good.NodeSHA256}, false},
		{"different architecture", &good, identityContract{Scheme: good.Scheme, NodeVersion: good.NodeVersion, Architecture: "arm64", NodeSHA256: good.NodeSHA256}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIdentityContract(tc.record, tc.pin)
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected: %v", err)
			}
		})
	}
}
func TestReviewedUpgradeRefusesUnverifiedRuntimeBeforeMutation(t *testing.T) {
	f, _, journal := reviewedUpgradeFixture(t)
	_, err := releaseReviewedUpgrade(f.parent, f.journal, f.txn, f.parentPolicy, f.stagePolicy, f.sddl, true, true, fixtureIdentityPin, func(string, string, identityContract, bootstraplock.Policy) error { return fmt.Errorf("bad runtime") }, func(string) error { return nil }, testActiveVerifier, renameProtectedMarker, renameOpenFile)
	if err == nil {
		t.Fatal("unverified runtime accepted")
	}
	after, err := os.ReadFile(f.journal)
	if err != nil || string(after) != string(journal) {
		t.Fatal("journal changed")
	}
	if _, err = os.Stat(filepath.Join(f.parent, "TokenTimer-UpgradeReview-"+f.txn)); !os.IsNotExist(err) {
		t.Fatal("archive created before runtime verification")
	}
}
func TestReviewedUpgradeRejectsUntrustedContractBeforeMutation(t *testing.T) {
	for _, field := range []string{"missing", "scheme", "version", "architecture", "hash"} {
		t.Run(field, func(t *testing.T) {
			f, _, journal := reviewedUpgradeFixture(t)
			var rec upgradeRecord
			if err := json.Unmarshal(journal, &rec); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "missing":
				rec.IdentityContract = nil
			case "scheme":
				rec.IdentityContract.Scheme = "other"
			case "version":
				rec.IdentityContract.NodeVersion = "0.0.0"
			case "architecture":
				rec.IdentityContract.Architecture = "arm64"
			case "hash":
				rec.IdentityContract.NodeSHA256 = strings.Repeat("b", 64)
			}
			changed, err := json.Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(f.journal, changed, 0600); err != nil {
				t.Fatal(err)
			}
			called := false
			verify := func(string, string, identityContract, bootstraplock.Policy) error { called = true; return nil }
			if _, err = releaseReviewedUpgrade(f.parent, f.journal, f.txn, f.parentPolicy, f.stagePolicy, f.sddl, true, true, fixtureIdentityPin, verify, func(string) error { return nil }, testActiveVerifier, renameProtectedMarker, renameOpenFile); err == nil {
				t.Fatal("untrusted contract accepted")
			}
			if called {
				t.Fatal("untrusted contract reached runtime verification")
			}
			after, err := os.ReadFile(f.journal)
			if err != nil || string(after) != string(changed) {
				t.Fatal("journal changed")
			}
			if _, err = os.Stat(filepath.Join(f.parent, "TokenTimer-UpgradeReview-"+f.txn)); !os.IsNotExist(err) {
				t.Fatal("archive created for rejected contract")
			}
		})
	}
}
func TestReviewedUpgradeRejectsChangedStateBeforeArchiving(t *testing.T) {
	f, root, journal := reviewedUpgradeFixture(t)
	service := func(string) error { return createRestrictedDirectory(filepath.Join(root, "app.staging.321"), f.sddl) }
	verify := func(string, string, identityContract, bootstraplock.Policy) error { return nil }
	if _, err := releaseReviewedUpgrade(f.parent, f.journal, f.txn, f.parentPolicy, f.stagePolicy, f.sddl, true, true, fixtureIdentityPin, verify, service, testActiveVerifier, renameProtectedMarker, renameOpenFile); err == nil {
		t.Fatal("new staging location accepted")
	}
	if _, err := os.Stat(filepath.Join(f.parent, "TokenTimer-UpgradeReview-"+f.txn)); !os.IsNotExist(err) {
		t.Fatal("review archive created after staging changed")
	}
	data, err := os.ReadFile(f.journal)
	if err != nil || string(data) != string(journal) {
		t.Fatal("journal changed")
	}
}

type testClose struct{}

func (testClose) Close() error { return nil }
func testActiveVerifier(_ string, digest string) (io.Closer, error) {
	if digest != fixtureArchive {
		return nil, fmt.Errorf("wrong archive digest")
	}
	return testClose{}, nil
}
func TestReviewedUpgradeRechecksServiceUnderInventoryLockAndBeforeJournalMove(t *testing.T) {
	for _, failAt := range []int{2, 3} {
		t.Run(fmt.Sprintf("call-%d", failAt), func(t *testing.T) {
			f, _, journal := reviewedUpgradeFixture(t)
			calls := 0
			service := func(string) error {
				calls++
				if calls == failAt {
					return fmt.Errorf("changed")
				}
				return nil
			}
			verify := func(string, string, identityContract, bootstraplock.Policy) error { return nil }
			if _, err := releaseReviewedUpgrade(f.parent, f.journal, f.txn, f.parentPolicy, f.stagePolicy, f.sddl, true, true, fixtureIdentityPin, verify, service, testActiveVerifier, renameProtectedMarker, renameOpenFile); err == nil {
				t.Fatal("changed service accepted")
			}
			data, err := os.ReadFile(f.journal)
			if err != nil || string(data) != string(journal) {
				t.Fatal("journal changed")
			}
			if calls != failAt {
				t.Fatalf("expected %d checks, got %d", failAt, calls)
			}
		})
	}
}

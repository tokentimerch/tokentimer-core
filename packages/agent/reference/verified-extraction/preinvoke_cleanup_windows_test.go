//go:build windows

package verifiedextraction

import (
	"bytes"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tokentimer-verified-extraction/bootstraplock"
)

func TestPreInvokeCleanupPair(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "mismatch"}[fail], func(t *testing.T) {
			p, ps := intentFixture(t)
			s, ss := intentFixture(t)
			a, err := p.beginExecutionIntent(fixtureArchive, fixtureSCM, ps, defaultIntentIO())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.beginExecutionIntentForTransaction(fixtureArchive, fixtureSCM, ss, a.Transaction, a.Secret, defaultIntentIO()); err != nil {
				t.Fatal(err)
			}
			if fail {
				a.Transaction = "wrong"
			}
			err = abortBeforeInvocation(p, s, a)
			if (err != nil) != fail {
				t.Fatalf("cleanup: %v", err)
			}
			for _, path := range []string{p.path, s.path, p.path + ".intent", s.path + ".intent"} {
				_, err := os.Lstat(path)
				if fail && err != nil {
					t.Fatalf("removed on mismatch: %v", err)
				}
				if !fail && !os.IsNotExist(err) {
					t.Fatalf("retained: %s: %v", path, err)
				}
			}
		})
	}
}

func TestPreInvokePartialCleanupRetainsBlockingMarker(t *testing.T) {
	for _, failure := range []string{"second-stage", "second-marker"} {
		t.Run(failure, func(t *testing.T) {
			p, ps := intentFixture(t)
			s, ss := intentFixture(t)
			a, err := p.beginExecutionIntent(fixtureArchive, fixtureSCM, ps, defaultIntentIO())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.beginExecutionIntentForTransaction(fixtureArchive, fixtureSCM, ss, a.Transaction, a.Secret, defaultIntentIO()); err != nil {
				t.Fatal(err)
			}
			stageCalls, markerCalls := 0, 0
			err = abortBeforeInvocationWith(p, s, a, func(stage *PrivateStaging) error {
				stageCalls++
				if failure == "second-stage" && stageCalls == 2 {
					return errors.New("interrupted")
				}
				return stage.cleanupLocked(true)
			}, func(h windows.Handle) error {
				markerCalls++
				if failure == "second-marker" && markerCalls == 2 {
					return errors.New("interrupted")
				}
				b := byte(1)
				return windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &b, 1)
			})
			if err == nil {
				t.Fatal("interruption accepted")
			}
			if _, err := os.Lstat(s.path + ".intent"); err != nil {
				t.Fatalf("blocking marker lost: %v", err)
			}
			if failure == "second-stage" {
				if _, err := os.Lstat(p.path + ".intent"); err != nil {
					t.Fatalf("first marker lost: %v", err)
				}
			}
		})
	}
}

// The helper is killed by the parent while holding the marker handles. Its
// current-user ACL fixture does not qualify the elevated Windows Server path.
func TestPreInvokeCrashHelper(t *testing.T) {
	root := os.Getenv("TT_PREINVOKE_CRASH_ROOT")
	if root == "" {
		return
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sddl := "O:" + sid + "G:" + sid + "D:P(A;OICI;FA;;;" + sid + ")"
	makeStage := func(id string) *PrivateStaging {
		path := filepath.Join(root, "TokenTimer-Staging-"+strings.Repeat(id, 32))
		if err := createRestrictedDirectory(path, sddl); err != nil {
			t.Fatal(err)
		}
		identity, err := getDirectoryIdentity(path)
		if err != nil {
			t.Fatal(err)
		}
		return &PrivateStaging{freshOwned: true, path: path, parent: root, identity: identity, policy: bootstraplock.Policy{Owners: map[string]bool{sid: true}, Writers: map[string]bool{sid: true}}, ancestors: &bootstraplock.Locks{}, staging: &bootstraplock.Locks{}, payload: &bootstraplock.Locks{}}
	}
	p, s := makeStage("a"), makeStage("b")
	intent, err := p.beginExecutionIntent(fixtureArchive, fixtureSCM, sddl, defaultIntentIO())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.beginExecutionIntentForTransaction(fixtureArchive, fixtureSCM, sddl, intent.Transaction, intent.Secret, defaultIntentIO()); err != nil {
		t.Fatal(err)
	}
	pause := func() {
		if err := os.WriteFile(filepath.Join(root, "ready"), []byte("ready"), 0600); err != nil {
			panic(err)
		}
		select {}
	}
	stages, markers := 0, 0
	point := os.Getenv("TT_PREINVOKE_CRASH_POINT")
	err = abortBeforeInvocationWith(p, s, intent, func(stage *PrivateStaging) error {
		stages++
		if stages == 2 && point == "stage" {
			pause()
		}
		return stage.cleanupLocked(true)
	}, func(h windows.Handle) error {
		markers++
		if markers == 2 && point == "marker" {
			pause()
		}
		b := byte(1)
		return windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &b, 1)
	})
	t.Fatalf("helper unexpectedly returned: %v", err)
}

func TestPreInvokeKillRetainsBlockingMarker(t *testing.T) {
	for _, point := range []string{"stage", "marker"} {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestPreInvokeCrashHelper$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "TT_PREINVOKE_CRASH_ROOT="+root, "TT_PREINVOKE_CRASH_POINT="+point)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			deadline := time.Now().Add(15 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(root, "ready")); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("helper did not reach kill point: %s", out.String())
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			marker := filepath.Join(root, "TokenTimer-Staging-"+strings.Repeat("b", 32)+".intent")
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("last marker did not survive process kill: %v", err)
			}
			if point == "stage" {
				if _, err := os.Stat(filepath.Join(root, "TokenTimer-Staging-"+strings.Repeat("a", 32)+".intent")); err != nil {
					t.Fatalf("first marker missing after stage kill: %v", err)
				}
			}
		})
	}
}

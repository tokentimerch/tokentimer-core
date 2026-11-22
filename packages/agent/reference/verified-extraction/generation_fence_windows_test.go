//go:build windows && generationfenceexperiment

package verifiedextraction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func writeGenerationFixture(t *testing.T, f releaseFixture, data string) string {
	t.Helper()
	name := filepath.Join(filepath.Dir(f.journal), "generation-fence.json")
	sd, err := windows.SecurityDescriptorFromString(f.sddl)
	if err != nil {
		t.Fatal(err)
	}
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(path, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, &attrs, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := validateIntentACL(h, &PrivateStaging{policy: f.stagePolicy}); err != nil {
		t.Fatalf("fixture marker security: %v", err)
	}
	var n uint32
	if err := windows.WriteFile(h, []byte(data), &n, nil); err != nil || int(n) != len(data) {
		t.Fatalf("fixture marker write: %v", err)
	}
	if err := windows.FlushFileBuffers(h); err != nil {
		t.Fatal(err)
	}

	return name
}
func TestGenerationLeasePinsOnlyCooperatingMarker(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	g := strings.Repeat("a", 64)
	marker := writeGenerationFixture(t, f, `{"version":1,"generation":"`+g+`"}`)
	lease, err := lockGeneration(filepath.Dir(f.journal), g, f.parentPolicy, f.stagePolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := os.WriteFile(marker, []byte("changed"), 0600); err == nil {
		t.Fatal("marker changed while pinned")
	}
	if err := os.Rename(marker, marker+".old"); err == nil {
		t.Fatal("marker replaced while pinned")
	}
	// A legacy actor is not required to take this lease. Its ability to mutate
	// a separate shared resource demonstrates that the lease does not fence it.
	legacy := filepath.Join(filepath.Dir(f.journal), "legacy-side-effect")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestUnfencedLegacyProcess$")
	cmd.Env = append(os.Environ(), "TT_FENCE_LEGACY_PATH="+legacy)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unfenced legacy process failed: %v %s", err, out)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy side effect missing: %v", err)
	}
	lease.Close()
	if err := os.WriteFile(marker, []byte("changed"), 0600); err != nil {
		t.Fatalf("marker remained locked: %v", err)
	}
}
func TestGenerationLeaseRejectsUncertainMarkers(t *testing.T) {
	for _, tc := range []struct {
		name, data, expected string
		hardlink             bool
	}{
		{"stale", `{"version":1,"generation":"` + strings.Repeat("a", 64) + `"}`, strings.Repeat("b", 64), false},
		{"interrupted-write", `{`, strings.Repeat("a", 64), false},
		{"duplicate", `{"version":1,"version":1,"generation":"` + strings.Repeat("a", 64) + `"}`, strings.Repeat("a", 64), false},
		{"unknown", `{"version":1,"generation":"` + strings.Repeat("a", 64) + `","extra":true}`, strings.Repeat("a", 64), false},
		{"hardlink", `{"version":1,"generation":"` + strings.Repeat("a", 64) + `"}`, strings.Repeat("a", 64), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			name := writeGenerationFixture(t, f, tc.data)
			if tc.hardlink {
				if err := os.Link(name, name+".link"); err != nil {
					t.Skipf("hardlinks unavailable: %v", err)
				}
			}
			if lease, err := lockGeneration(filepath.Dir(f.journal), tc.expected, f.parentPolicy, f.stagePolicy); err == nil {
				lease.Close()
				t.Fatal("uncertain generation accepted")
			}
		})
	}
}

// This subprocess deliberately ignores generation markers, like an older
// privileged executor. Its write demonstrates that a lease alone is no fence.
func TestUnfencedLegacyProcess(t *testing.T) {
	path := os.Getenv("TT_FENCE_LEGACY_PATH")
	if path == "" {
		t.Skip("legacy subprocess fixture only")
	}
	if err := os.WriteFile(path, []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
}

func testCooperativeMutex(name string) func(context.Context) (func() error, error) {
	return func(ctx context.Context) (func() error, error) {
		runtime.LockOSThread()
		ptr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			runtime.UnlockOSThread()
			return nil, err
		}
		h, err := windows.CreateMutex(nil, false, ptr)
		if err != nil && err != windows.ERROR_ALREADY_EXISTS {
			runtime.UnlockOSThread()
			return nil, err
		}
		for {
			if err := ctx.Err(); err != nil {
				windows.CloseHandle(h)
				runtime.UnlockOSThread()
				return nil, err
			}
			state, err := windows.WaitForSingleObject(h, 50)
			if err != nil {
				windows.CloseHandle(h)
				runtime.UnlockOSThread()
				return nil, err
			}
			if state == windows.WAIT_ABANDONED {
				// WAIT_ABANDONED grants ownership; release it before failing.
				_ = windows.ReleaseMutex(h)
				windows.CloseHandle(h)
				runtime.UnlockOSThread()
				return nil, fmt.Errorf("abandoned generation mutex requires reconciliation")
			}
			if state == windows.WAIT_OBJECT_0 {
				break
			}
			if state != uint32(windows.WAIT_TIMEOUT) {
				windows.CloseHandle(h)
				runtime.UnlockOSThread()
				return nil, fmt.Errorf("unexpected generation mutex wait")
			}
		}
		return func() error {
			err := windows.ReleaseMutex(h)
			windows.CloseHandle(h)
			runtime.UnlockOSThread()
			return err
		}, nil
	}
}

func TestGenerationGuardDelayedProcess(t *testing.T) {
	if os.Getenv("TT_FENCE_GUARD_CHILD") == "1" {
		var wire releaseFixtureWire
		if err := json.Unmarshal([]byte(os.Getenv("TT_FENCE_GUARD_FIXTURE")), &wire); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Dir(wire.Journal)
		ready := filepath.Join(dir, "child-ready")
		effect := filepath.Join(dir, "child-effect")
		if err := os.WriteFile(ready, []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		err := withGenerationGuard(context.Background(), dir, strings.Repeat("a", 64), wire.ParentPolicy, wire.StagePolicy, testCooperativeMutex(os.Getenv("TT_FENCE_GUARD_MUTEX")), func() error { return os.WriteFile(effect, []byte("stale effect"), 0600) })
		if err == nil {
			t.Fatal("stale generation executed")
		}
		if _, err := os.Stat(effect); !os.IsNotExist(err) {
			t.Fatal("stale effect exists")
		}
		return
	}
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	dir := filepath.Dir(f.journal)
	old := strings.Repeat("a", 64)
	next := strings.Repeat("b", 64)
	marker := writeGenerationFixture(t, f, `{"version":1,"generation":"`+old+`"}`)
	name := fmt.Sprintf(`Local\TTGenerationFixture-%d-%d`, os.Getpid(), time.Now().UnixNano())
	acquire := testCooperativeMutex(name)
	release, err := acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_ = release()
		}
	}()
	wire := releaseFixtureWire{f.parent, f.journal, f.sddl, f.txn, f.parentPolicy, f.stagePolicy}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestGenerationGuardDelayedProcess$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "TT_FENCE_GUARD_CHILD=1", "TT_FENCE_GUARD_FIXTURE="+string(data), "TT_FENCE_GUARD_MUTEX="+name)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "child-ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString(`{"version":1,"generation":"` + next + `"}`); err != nil {
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = release(); err != nil {
		t.Fatal(err)
	}
	locked = false
	if err := cmd.Wait(); err != nil {
		t.Fatalf("delayed child: %v %s", err, out.String())
	}
	ran := false
	if err := withGenerationGuard(context.Background(), dir, next, f.parentPolicy, f.stagePolicy, acquire, func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("current generation did not run: %v", err)
	}
}

func TestGenerationGuardRejectsKilledOwner(t *testing.T) {
	if os.Getenv("TT_FENCE_ABANDON_OWNER") == "1" {
		name, ready := os.Getenv("TT_FENCE_ABANDON_MUTEX"), os.Getenv("TT_FENCE_ABANDON_READY")
		release, err := testCooperativeMutex(name)(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		if err := os.WriteFile(ready, []byte("held"), 0600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	dir := filepath.Dir(f.journal)
	g := strings.Repeat("a", 64)
	writeGenerationFixture(t, f, `{"version":1,"generation":"`+g+`"}`)
	name := fmt.Sprintf(`Local\TTAbandonedFixture-%d-%d`, os.Getpid(), time.Now().UnixNano())
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	keeper, err := windows.CreateMutex(nil, false, ptr)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(keeper)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(dir, "abandoned-owner-ready")
	cmd := exec.Command(exe, "-test.run=^TestGenerationGuardRejectsKilledOwner$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "TT_FENCE_ABANDON_OWNER=1", "TT_FENCE_ABANDON_MUTEX="+name, "TT_FENCE_ABANDON_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owner did not acquire mutex")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	ran := false
	err = withGenerationGuard(context.Background(), dir, g, f.parentPolicy, f.stagePolicy, testCooperativeMutex(name), func() error { ran = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "abandoned") || ran {
		t.Fatalf("abandoned mutex authorized effect: ran=%t err=%v", ran, err)
	}
}

func TestDirtyGenerationEffectRetainsUnsettled(t *testing.T) {
	for _, mode := range []string{"success", "effect-error", "unsettled"} {
		t.Run(mode, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			dir := filepath.Dir(f.journal)
			g := strings.Repeat("a", 64)
			writeGenerationFixture(t, f, `{"version":1,"generation":"`+g+`"}`)
			name := fmt.Sprintf(`Local\TTDirtyFixture-%d-%d`, os.Getpid(), time.Now().UnixNano())
			calls := 0
			err := withGenerationGuard(context.Background(), dir, g, f.parentPolicy, f.stagePolicy, testCooperativeMutex(name), func() error {
				return withDirtyGenerationEffect(dir, f.sddl, f.stagePolicy, func() error {
					calls++
					if mode == "effect-error" {
						return errors.New("interrupted")
					}
					return nil
				}, func() error {
					if mode == "unsettled" {
						return errors.New("network result unknown")
					}
					return nil
				})
			})
			if calls != 1 || (err != nil) != (mode != "success") {
				t.Fatalf("unexpected outcome: calls=%d err=%v", calls, err)
			}
			dirty := filepath.Join(dir, "generation-dirty.intent")
			_, statErr := os.Stat(dirty)
			if mode == "success" && !os.IsNotExist(statErr) {
				t.Fatalf("completed marker retained: %v", statErr)
			}
			if mode != "success" && statErr != nil {
				t.Fatalf("dirty marker lost: %v", statErr)
			}
			if mode != "success" {
				second := 0
				err = withGenerationGuard(context.Background(), dir, g, f.parentPolicy, f.stagePolicy, testCooperativeMutex(name), func() error {
					return withDirtyGenerationEffect(dir, f.sddl, f.stagePolicy, func() error { second++; return nil }, func() error { return nil })
				})
				if err == nil || second != 0 {
					t.Fatal("dirty marker did not block next effect")
				}
			}
		})
	}
}
func TestDirtyGenerationEffectKilledProcess(t *testing.T) {
	if os.Getenv("TT_FENCE_DIRTY_CHILD") == "1" {
		var wire releaseFixtureWire
		if err := json.Unmarshal([]byte(os.Getenv("TT_FENCE_DIRTY_FIXTURE")), &wire); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Dir(wire.Journal)
		name := os.Getenv("TT_FENCE_DIRTY_MUTEX")
		err := withGenerationGuard(context.Background(), dir, strings.Repeat("a", 64), wire.ParentPolicy, wire.StagePolicy, testCooperativeMutex(name), func() error {
			return withDirtyGenerationEffect(dir, wire.SDDL, wire.StagePolicy, func() error {
				if err := os.WriteFile(filepath.Join(dir, "dirty-child-ready"), []byte("running"), 0600); err != nil {
					return err
				}
				select {}
			}, func() error { return nil })
		})
		t.Fatalf("child unexpectedly returned: %v", err)
	}
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	dir := filepath.Dir(f.journal)
	g := strings.Repeat("a", 64)
	writeGenerationFixture(t, f, `{"version":1,"generation":"`+g+`"}`)
	name := fmt.Sprintf(`Local\TTDirtyCrash-%d-%d`, os.Getpid(), time.Now().UnixNano())
	wire := releaseFixtureWire{f.parent, f.journal, f.sddl, f.txn, f.parentPolicy, f.stagePolicy}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestDirtyGenerationEffectKilledProcess$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "TT_FENCE_DIRTY_CHILD=1", "TT_FENCE_DIRTY_FIXTURE="+string(data), "TT_FENCE_DIRTY_MUTEX="+name)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "dirty-child-ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not enter effect")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if _, err := os.Stat(filepath.Join(dir, "generation-dirty.intent")); err != nil {
		t.Fatalf("dirty marker lost after process kill: %v", err)
	}
	called := false
	err = withCooperativeDirtyEffect(context.Background(), dir, g, f.sddl, f.parentPolicy, f.stagePolicy, testCooperativeMutex(name), func() error { called = true; return nil }, func() error { return nil })
	if err == nil || called {
		t.Fatalf("dirty effect ran after crash: %v", err)
	}
}

func TestDirtyGenerationRejectsExistingOrUntrustedIntent(t *testing.T) {
	for _, mode := range []string{"existing-empty", "untrusted-acl"} {
		t.Run(mode, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			dir := filepath.Dir(f.journal)
			g := strings.Repeat("a", 64)
			writeGenerationFixture(t, f, `{"version":1,"generation":"`+g+`"}`)
			name := fmt.Sprintf(`Local\TTDirtyAdversary-%d-%d`, os.Getpid(), time.Now().UnixNano())
			dirty := filepath.Join(dir, "generation-dirty.intent")
			sddl := f.sddl
			if mode == "existing-empty" {
				if err := os.WriteFile(dirty, nil, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				sddl = "D:P(A;;FA;;;WD)"
			}
			called := false
			err := withCooperativeDirtyEffect(context.Background(), dir, g, sddl, f.parentPolicy, f.stagePolicy, testCooperativeMutex(name), func() error { called = true; return nil }, func() error { t.Fatal("settled called after rejected marker"); return nil })
			if err == nil || called {
				t.Fatalf("untrusted intent allowed effect: %v", err)
			}
			if _, err := os.Stat(dirty); err != nil {
				t.Fatalf("uncertain marker removed: %v", err)
			}
		})
	}
}

//go:build windows

package verifiedextraction

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSCMRecoveryActionNames(t *testing.T) {
	for _, tc := range []struct {
		kind int
		want string
	}{
		{mgr.NoAction, "none"}, {mgr.ServiceRestart, "restart-service"},
		{mgr.ComputerReboot, "reboot"}, {mgr.RunCommand, "run-command"}, {-1, "unknown"},
	} {
		if got := recoveryActionName(tc.kind); got != tc.want {
			t.Fatalf("action %d: got %q, want %q", tc.kind, got, tc.want)
		}
	}
}

func TestSCMInspectionMissingServiceNeverAuthorizesCleanup(t *testing.T) {
	r, err := inspectServiceRecovery("TokenTimer-Missing-SCM-Fixture-7fc940d3")
	if err != nil {
		t.Fatal(err)
	}
	if r.Service != "absent" || r.NonCrashFailures != nil || !strings.Contains(r.Notice, "queued SCM actions") {
		t.Fatalf("unsafe missing-service report: %+v", r)
	}
}
func TestSCMInspectionRealWindowsEventLogReadOnly(t *testing.T) {
	r, err := inspectServiceRecovery("EventLog")
	if err != nil {
		t.Skipf("Windows service query unavailable: %v", err)
	}
	if r.Service != "present" || r.NonCrashFailures == nil {
		t.Fatalf("invalid service report: %+v", r)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "queued SCM actions") || strings.Contains(string(raw), "commandLine") {
		t.Fatalf("unsafe report: %s", raw)
	}
}

// This fixture only configures a fresh stopped service on an authorized VM;
// it never starts the service or schedules any recovery action.
func TestSCMInspectionNativeConfiguredActions(t *testing.T) {
	if os.Getenv("TT_TEST_SCM_INSPECTION") != "1" {
		t.Skip("set TT_TEST_SCM_INSPECTION=1 on an elevated disposable Windows VM")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires an elevated token")
	}
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		t.Fatal(err)
	}
	name := "TTScmProbe-" + hex.EncodeToString(n[:])
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Delete(); err != nil {
			t.Errorf("fixture service could not be deleted: %v", err)
		}
		s.Close()
	}()
	want := []mgr.RecoveryAction{{Type: mgr.RunCommand, Delay: 11 * time.Second}, {Type: mgr.ServiceRestart, Delay: 7 * time.Second}, {Type: mgr.NoAction, Delay: 3 * time.Second}}
	if err := s.SetRecoveryActions(want, 60); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		t.Fatal(err)
	}
	r, err := inspectServiceRecovery(name)
	if err != nil {
		t.Fatal(err)
	}
	if r.Service != "present" || r.NonCrashFailures == nil || !*r.NonCrashFailures || len(r.ConfiguredActions) != 3 {
		t.Fatalf("invalid report: %+v", r)
	}
	types := []string{"run-command", "restart-service", "none"}
	for i, action := range r.ConfiguredActions {
		if action.Type != types[i] || action.DelayMilliseconds != int64(want[i].Delay/time.Millisecond) {
			t.Fatalf("unexpected action: %+v", action)
		}
	}
}

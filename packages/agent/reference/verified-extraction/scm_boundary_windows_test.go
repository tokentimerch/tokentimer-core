//go:build windows

package verifiedextraction

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type scmFixtureHandler struct{}

func (scmFixtureHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	for {
		var request svc.ChangeRequest
		select {
		case <-timer.C:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		case next, ok := <-requests:
			if !ok {
				return false, 0
			}
			request = next
		}
		if request.Cmd == svc.Stop {
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
		if request.Cmd == svc.Interrogate {
			status <- request.CurrentStatus
		}
	}
}

// This process is started by SCM, not by the test parent.
func TestSCMFixtureService(t *testing.T) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		t.Skip("service fixture only")
	}
	name := os.Args[len(os.Args)-1]
	if !strings.HasPrefix(name, "TTScmProbe-") {
		t.Fatal("invalid service name")
	}
	if err := svc.Run(name, scmFixtureHandler{}); err != nil {
		t.Fatal(err)
	}
}

func TestSCMFixtureCaller(t *testing.T) {
	name := os.Getenv("TT_SCM_CALLER_NAME")
	if name == "" {
		t.Skip("SCM job caller fixture only")
	}
	gate := os.Getenv("TT_SCM_CALLER_GATE")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(gate); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("caller gate timed out")
		}
		time.Sleep(25 * time.Millisecond)
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual}, "-test.run=^TestSCMFixtureService$", "--", name)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	for time.Now().Before(deadline) {
		state, err := s.Query()
		if err != nil {
			t.Fatal(err)
		}
		if state.State == svc.Running {
			fmt.Println("TT_SCM_FIXTURE_RUNNING")
			time.Sleep(30 * time.Second)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("service did not start")
}

// This opt-in test modifies the service database on a disposable elevated host.
// It tests a native SCM boundary, not the product installer or recovery logic.
func TestNativeSCMServiceIsOutsideCallerJob(t *testing.T) {
	if os.Getenv("TT_REQUIRE_SCM_NATIVE") != "1" {
		t.Skip("set TT_REQUIRE_SCM_NATIVE=1 on an authorized disposable Windows host")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("elevated token required")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := "TTScmProbe-" + hex.EncodeToString(nonce[:])
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(name); err == nil {
		s.Close()
		t.Fatal("random service name already exists")
	} else if err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
		t.Fatal(err)
	}
	root := t.TempDir()
	gate := filepath.Join(root, "start")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestSCMFixtureCaller$")
	cmd.Env = append(os.Environ(), "TT_SCM_CALLER_NAME="+name, "TT_SCM_CALLER_GATE="+gate)
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(job)
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		t.Fatal(err)
	}
	// Defer cleanup before the gate can allow the child to create the service.
	defer func() {
		_ = windows.TerminateJobObject(job, 1)
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		s, err := m.OpenService(name)
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return
		}
		if err != nil {
			t.Errorf("open fixture service for cleanup: %v", err)
			return
		}
		cfg, err := s.Config()
		expected := syscall.EscapeArg(exe) + " " + syscall.EscapeArg("-test.run=^TestSCMFixtureService$") + " " + syscall.EscapeArg("--") + " " + syscall.EscapeArg(name)
		if err != nil || cfg.BinaryPathName != expected || cfg.StartType != mgr.StartManual || cfg.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS {
			_ = s.Close()
			t.Errorf("fixture service identity cannot be proven; retained without modification: %v", err)
			return
		}
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(15 * time.Second)
		stopped := false
		for time.Now().Before(deadline) {
			state, err := s.Query()
			if err != nil {
				t.Errorf("query fixture service during cleanup: %v", err)
				break
			}
			if state.State == svc.Stopped {
				stopped = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !stopped {
			t.Error("fixture service did not stop")
		}
		if err := s.Delete(); err != nil {
			t.Errorf("delete fixture service: %v", err)
		}
		_ = s.Close()
		deadline = time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			remaining, err := m.OpenService(name)
			if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
				return
			}
			if err == nil {
				remaining.Close()
			} else if err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
				t.Errorf("verify fixture service deletion: %v", err)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Error("fixture service remains after cleanup")
	}()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	caller, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(caller)
	if err := windows.AssignProcessToJobObject(job, caller); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gate, []byte("start"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	var service *mgr.Service
	for time.Now().Before(deadline) {
		service, err = m.OpenService(name)
		if err == nil {
			break
		}
		if err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if service == nil {
		t.Fatal("fixture service not created")
	}
	defer service.Close()
	var state svc.Status
	for time.Now().Before(deadline) {
		state, err = service.Query()
		if err != nil {
			t.Fatal(err)
		}
		if state.State == svc.Running && state.ProcessId != 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if state.State != svc.Running || state.ProcessId == 0 {
		t.Fatal("fixture service not running")
	}
	process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, state.ProcessId)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(process)
	var member uint32
	ok, _, callErr := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&member)))
	if ok == 0 || member != 0 {
		t.Fatalf("SCM service job membership: member=%d error=%v", member, callErr)
	}
	if err := windows.TerminateJobObject(job, 1); err != nil {
		t.Fatal(err)
	}
	status, err := windows.WaitForSingleObject(process, 0)
	if err != nil || status != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("expected SCM service to survive job termination: status=%d error=%v", status, err)
	}
	state, err = service.Query()
	if err != nil || state.State != svc.Running {
		t.Fatalf("expected service to remain running: state=%v error=%v", state.State, err)
	}
}

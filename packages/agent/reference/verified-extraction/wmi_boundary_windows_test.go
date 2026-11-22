//go:build windows

package verifiedextraction

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestNativeWMIProcessIsOutsideCallerJob is an opt-in native test, not an
// installer or SCM qualification. It creates only a short-lived, hidden test
// process and proves that CIM process creation is an external actor boundary.
func TestNativeWMIProcessIsOutsideCallerJob(t *testing.T) {
	if os.Getenv("TT_REQUIRE_WMI_NATIVE") != "1" {
		t.Skip("set TT_REQUIRE_WMI_NATIVE=1 on an authorized Windows host")
	}
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe")
	root := os.Getenv("TT_WMI_TEST_ROOT")
	if root == "" {
		root = t.TempDir()
	} else if !filepath.IsAbs(root) {
		t.Fatal("fixture root must be absolute")
	}
	gate := filepath.Join(root, "start")
	stop := filepath.Join(root, "stop")
	actorPIDFile := filepath.Join(root, "actor.pid")
	quotePS := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	encodePS := func(s string) string {
		units := utf16.Encode([]rune(s))
		encoded := make([]byte, 2*len(units))
		for i, code := range units {
			binary.LittleEndian.PutUint16(encoded[2*i:], code)
		}
		return base64.StdEncoding.EncodeToString(encoded)
	}
	actorScript := fmt.Sprintf(`$ErrorActionPreference='Stop'; $creation=[Diagnostics.Process]::GetCurrentProcess().StartTime.ToFileTimeUtc(); [IO.File]::WriteAllText('%s',([string]$PID+'|'+[string]$creation)); $deadline=[DateTime]::UtcNow.AddSeconds(15); while (!(Test-Path -LiteralPath '%s') -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 25 }`, quotePS(actorPIDFile), quotePS(stop))
	script := `$ErrorActionPreference='Stop'; $deadline=[DateTime]::UtcNow.AddSeconds(15); while (!(Test-Path -LiteralPath $env:TT_WMI_GATE)) { if ([DateTime]::UtcNow -gt $deadline) { throw 'job gate timed out' }; Start-Sleep -Milliseconds 25 }; $line='"' + $env:TT_WMI_ACTOR_PS + '" -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ' + $env:TT_WMI_ACTOR_CODE; $r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$line}; if ($r.ReturnValue -ne 0) { throw ('Win32_Process.Create failed: '+$r.ReturnValue) }; [Console]::WriteLine('TT_WMI_ACTOR_PID='+$r.ProcessId)`
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encodePS(script))
	cmd.Env = append(os.Environ(), "TT_WMI_ACTOR_PS="+ps, "TT_WMI_GATE="+gate, "TT_WMI_ACTOR_CODE="+encodePS(actorScript))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	var actor windows.Handle
	gateOpened := false
	// The stop marker is set on every return path. If the actor was created but
	// an assertion failed before OpenProcess, its own first action records its
	// PID and it exits on this marker; a 15-second deadline bounds its lifetime.
	defer func() {
		if !gateOpened {
			return
		}
		if err := os.WriteFile(stop, []byte("stop"), 0600); err != nil {
			t.Errorf("signal WMI fixture cleanup: %v", err)
		}
		if actor != 0 {
			state, waitErr := windows.WaitForSingleObject(actor, 5000)
			if waitErr != nil || state != windows.WAIT_OBJECT_0 {
				t.Errorf("WMI fixture did not exit on cleanup: status=%d error=%v", state, waitErr)
			}
			windows.CloseHandle(actor)
			return
		}
		// Let a just-created actor observe the marker before TempDir is removed.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if b, err := os.ReadFile(actorPIDFile); err == nil {
				fields := strings.Split(strings.TrimSpace(string(b)), "|")
				if n, err := strconv.Atoi(fields[0]); err == nil && n > 0 {
					if h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(n)); err == nil {
						_, _ = windows.WaitForSingleObject(h, 20000)
						windows.CloseHandle(h)
					}
				}
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()
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
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	parent, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(parent)
	if err := windows.AssignProcessToJobObject(job, parent); err != nil {
		t.Fatalf("assign caller to job: %v", err)
	}
	isInJob := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")
	var member uint32
	if ok, _, e := isInJob.Call(uintptr(parent), uintptr(job), uintptr(unsafe.Pointer(&member))); ok == 0 || member != 1 {
		t.Fatalf("caller job membership: %v", e)
	}
	if err := os.WriteFile(gate, []byte("start"), 0600); err != nil {
		t.Fatal(err)
	}
	gateOpened = true
	if err := cmd.Wait(); err != nil {
		t.Fatalf("CIM fixture: %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	var pid int
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TT_WMI_ACTOR_PID=") {
			pid, err = strconv.Atoi(strings.TrimPrefix(line, "TT_WMI_ACTOR_PID="))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if pid <= 0 {
		t.Fatalf("CIM fixture did not return a PID: %q %q", stdout.String(), stderr.String())
	}
	var marker []byte
	deadline := time.Now().Add(5 * time.Second)
	for len(marker) == 0 && time.Now().Before(deadline) {
		marker, _ = os.ReadFile(actorPIDFile)
		if len(marker) == 0 {
			time.Sleep(25 * time.Millisecond)
		}
	}
	fields := strings.Split(strings.TrimSpace(string(marker)), "|")
	if len(fields) != 2 || fields[0] != strconv.Itoa(pid) {
		t.Fatalf("actor identity marker missing or does not match WMI PID")
	}
	expectedCreated, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		t.Fatalf("invalid actor creation time: %v", err)
	}
	actor, err = windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatalf("open WMI fixture: %v", err)
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(actor, &created, &exited, &kernel, &user); err != nil {
		t.Fatalf("query actor identity: %v", err)
	}
	if (uint64(created.HighDateTime)<<32)|uint64(created.LowDateTime) != expectedCreated {
		t.Fatal("WMI PID was reused")
	}
	name := make([]uint16, 32768)
	nameLen := uint32(len(name))
	if err := windows.QueryFullProcessImageName(actor, 0, &name[0], &nameLen); err != nil {
		t.Fatalf("query actor executable: %v", err)
	}
	if !strings.EqualFold(windows.UTF16ToString(name[:nameLen]), ps) {
		t.Fatal("WMI actor executable mismatch")
	}
	if os.Getenv("TT_WMI_INJECT_FAILURE") == "1" {
		t.Fatal("injected failure after WMI actor identity check")
	}
	member = 0
	if ok, _, e := isInJob.Call(uintptr(actor), uintptr(job), uintptr(unsafe.Pointer(&member))); ok == 0 || member != 0 {
		t.Fatalf("WMI actor unexpectedly belongs to caller job: member=%d error=%v", member, e)
	}
	if err := windows.TerminateJobObject(job, 1); err != nil {
		t.Fatal(err)
	}
	state, err := windows.WaitForSingleObject(actor, 0)
	if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("expected WMI actor to outlive job: status=%d error=%v", state, err)
	}
}

// Prove cleanup still runs when an assertion fails after the real WMI actor
// starts. The PID is never terminated by number: creation time is checked and
// the fixture's stop marker is its normal exit path.
func TestNativeWMICleansActorAfterFailure(t *testing.T) {
	if os.Getenv("TT_REQUIRE_WMI_NATIVE") != "1" {
		t.Skip("set TT_REQUIRE_WMI_NATIVE=1 on an authorized Windows host")
	}
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeWMIProcessIsOutsideCallerJob$", "-test.count=1")
	cmd.Env = append(os.Environ(), "TT_WMI_TEST_ROOT="+root, "TT_WMI_INJECT_FAILURE=1")
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "injected failure after WMI actor identity check") {
		t.Fatalf("expected injected fixture failure; got %v: %s", err, output)
	}
	marker, err := os.ReadFile(filepath.Join(root, "actor.pid"))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(strings.TrimSpace(string(marker)), "|")
	if len(fields) != 2 {
		t.Fatal("invalid fixture identity")
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		t.Fatal("invalid fixture PID")
	}
	created, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		t.Fatal("invalid fixture creation time")
	}
	actor, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return
	} // Original process has exited.
	if err != nil {
		t.Fatalf("cannot establish fixture status: %v", err)
	}
	defer windows.CloseHandle(actor)
	var actual, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(actor, &actual, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	if (uint64(actual.HighDateTime)<<32)|uint64(actual.LowDateTime) != created {
		return
	} // PID belongs to a different process.
	status, err := windows.WaitForSingleObject(actor, 0)
	if err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("fixture still running after injected failure: status=%d error=%v", status, err)
	}
}

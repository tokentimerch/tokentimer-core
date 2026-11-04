//go:build windows

package verifiedextraction

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"os/exec"
	"testing"
	"tokentimer-verified-extraction/bootstraplock"
	"unsafe"
)

func TestRestartSCMConfigRequiresOwnProcessLocalSystemAndExactCommand(t *testing.T) {
	app := `C:\ProgramData\TokenTimerAgent\app`
	good := mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, ServiceStartName: "LocalSystem", BinaryPathName: expectedKeptServiceCommand(app, "amd64")}
	if err := validateSCMConfig(good, app, "amd64"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*mgr.Config)
	}{{"shared service", func(c *mgr.Config) { c.ServiceType = windows.SERVICE_WIN32_SHARE_PROCESS }}, {"other account", func(c *mgr.Config) { c.ServiceStartName = "NetworkService" }}, {"other runtime", func(c *mgr.Config) { c.BinaryPathName = `C:\untrusted\node.exe` }}, {"extra arguments", func(c *mgr.Config) { c.BinaryPathName += " --extra" }}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.mutate(&c)
			if err := validateSCMConfig(c, app, "amd64"); err == nil {
				t.Fatal("unsafe service config accepted")
			}
		})
	}
}
func TestRestartControllerRefusesMissingEnvironmentProof(t *testing.T) {
	c := &nativeRestartController{}
	if err := c.VerifyBefore(context.Background()); err == nil {
		t.Fatal("unqualified controller accepted")
	}
}
func TestRestartRejectsStoppedOrAmbiguousEntryWithoutOldHandles(t *testing.T) {
	for _, status := range []svc.Status{{State: svc.Stopped}, {State: svc.StopPending}, {State: svc.Running, ProcessId: 0}} {
		if err := validateStopEntryStatus(status); err == nil {
			t.Fatal("ambiguous prior process state accepted")
		}
	}
	if err := (&nativeRestartController{}).WaitStoppedAndOldProcessesExited(context.Background()); err == nil {
		t.Fatal("missing old process handles accepted")
	}
}
func TestCapturedChildRequiresStableAssociationAndCreation(t *testing.T) {
	timeout := uint32(windows.WAIT_TIMEOUT)
	if !validProcessAssociation(21, 21, 21, 100, 101, 101, 101, timeout, timeout) {
		t.Fatal("stable association rejected")
	}
	for _, tc := range []struct {
		first, opened, second uint32
		hostTime, nodeTime    uint64
		hostState, nodeState  uint32
	}{
		{21, 22, 21, 100, 101, timeout, timeout}, {21, 21, 22, 100, 101, timeout, timeout}, {21, 21, 21, 100, 99, timeout, timeout}, {21, 21, 21, 0, 101, timeout, timeout}, {21, 21, 21, 100, 101, 0, timeout}, {21, 21, 21, 100, 101, timeout, 0}, {0, 0, 0, 100, 101, timeout, timeout},
	} {
		if validProcessAssociation(tc.first, tc.opened, tc.second, tc.hostTime, tc.nodeTime, 101, 101, tc.hostState, tc.nodeState) {
			t.Fatalf("ambiguous process accepted: %+v", tc)
		}
	}
}
func TestProcessSnapshotBindsChildCreationToHandle(t *testing.T) {
	node, err := exec.LookPath("node.exe")
	if err != nil {
		t.Skip("Node unavailable")
	}
	cmd := exec.Command(node, "-e", "setInterval(()=>{},1000)")
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pid, created, err := snapshotSingleChild(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if pid != uint32(cmd.Process.Pid) {
		t.Fatal("snapshot returned another child")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	actual, err := processCreationTime(h)
	if err != nil || created != actual {
		t.Fatal("snapshot does not match process handle")
	}
	secondPID, secondCreated, err := snapshotSingleChild(uint32(os.Getpid()))
	if err != nil || secondPID != pid || secondCreated != created {
		t.Fatal("second snapshot disagrees")
	}
}
func TestProcessSnapshotParserRejectsInvalidABIAndAmbiguity(t *testing.T) {
	size := int(unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{}))
	makeEntry := func(next uint32, pid, parent uintptr, created int64) []byte {
		b := make([]byte, size)
		e := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&b[0]))
		e.NextEntryOffset = next
		e.UniqueProcessID = pid
		e.InheritedFromUniqueProcessID = parent
		e.CreateTime = created
		return b
	}
	valid := makeEntry(0, 22, 11, 123)
	pid, created, err := parseProcessSnapshot(valid, 11)
	if err != nil || pid != 22 || created != 123 {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	malformed := [][]byte{nil, valid[:size-1], makeEntry(1, 22, 11, 123), makeEntry(uint32(size+8), 22, 11, 123), makeEntry(0, 22, 11, 0), makeEntry(0, 0, 11, 123)}
	first := makeEntry(uint32(size), 22, 11, 123)
	duplicate := append(first, makeEntry(0, 23, 11, 124)...)
	malformed = append(malformed, duplicate)
	for i, b := range malformed {
		if _, _, err := parseProcessSnapshot(b, 11); err == nil {
			t.Fatalf("malformed snapshot %d accepted", i)
		}
	}
}
func TestStopOnlyRejectsMissingOrUncertainPendingRestartProof(t *testing.T) {
	if err := requireNoPendingRestart(nil); err == nil {
		t.Fatal("missing proof accepted")
	}
	if err := requireNoPendingRestart(func() error { return fmt.Errorf("unknown") }); err == nil {
		t.Fatal("uncertain proof accepted")
	}
	if err := requireNoPendingRestart(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
func TestNativeStopFactoryRejectsAbsentPendingProofBeforeSCM(t *testing.T) {
	if guard, err := stopServiceForReview(context.Background(), "unused", "unused", "unused", "unused", upgradeJournalBinding{}, bootstraplock.Policy{}, nil); err == nil || guard != nil {
		t.Fatal("unqualified stop factory accepted")
	}
}

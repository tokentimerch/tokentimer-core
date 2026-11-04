//go:build windows

package verifiedextraction

import (
	"context"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"testing"
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
	if !validProcessAssociation(21, 21, 21, 100, 101, timeout, timeout) {
		t.Fatal("stable association rejected")
	}
	for _, tc := range []struct {
		first, opened, second uint32
		hostTime, nodeTime    uint64
		hostState, nodeState  uint32
	}{
		{21, 22, 21, 100, 101, timeout, timeout}, {21, 21, 22, 100, 101, timeout, timeout}, {21, 21, 21, 100, 99, timeout, timeout}, {21, 21, 21, 0, 101, timeout, timeout}, {21, 21, 21, 100, 101, 0, timeout}, {21, 21, 21, 100, 101, timeout, 0}, {0, 0, 0, 100, 101, timeout, timeout},
	} {
		if validProcessAssociation(tc.first, tc.opened, tc.second, tc.hostTime, tc.nodeTime, tc.hostState, tc.nodeState) {
			t.Fatalf("ambiguous process accepted: %+v", tc)
		}
	}
}

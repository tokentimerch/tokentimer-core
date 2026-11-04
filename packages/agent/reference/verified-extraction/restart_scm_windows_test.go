//go:build windows

package verifiedextraction

import (
	"context"
	"golang.org/x/sys/windows"
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

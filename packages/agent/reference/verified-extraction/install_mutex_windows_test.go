//go:build windows

package verifiedextraction

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNativeInstallMutex(t *testing.T) {
	if os.Getenv("TT_REQUIRE_INSTALL_MUTEX_NATIVE") != "1" {
		t.Skip("requires disposable elevated Windows host")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("elevated token required")
	}
	if os.Getenv("TT_MUTEX_CHILD") == "1" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		defer cancel()
		h, err := lockInstall(ctx)
		if err == nil {
			unlockInstall(h)
			t.Fatal("concurrent acquisition succeeded")
		}
		if ctx.Err() == nil {
			t.Fatalf("mutex refused for wrong reason: %v", err)
		}
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	h, err := lockInstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlockInstall(h)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestNativeInstallMutex$")
	cmd.Env = append(os.Environ(), "TT_MUTEX_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child mutex test: %v: %s", err, out)
	}
}

func TestInstallMutexRejectsUntrustedDACL(t *testing.T) {
	if os.Getenv("TT_REQUIRE_INSTALL_MUTEX_NATIVE") != "1" {
		t.Skip("requires disposable Windows host")
	}
	name, _ := windows.UTF16PtrFromString(fmt.Sprintf(`Local\TokenTimer.Untrusted.%d`, os.Getpid()))
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateMutex(&attrs, false, name)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := validateInstallMutex(h); err == nil {
		t.Fatal("untrusted mutex accepted")
	}
}

// Separate-process handshake for native Go/PowerShell mutex interoperability.
func TestNativeInstallMutexHold(t *testing.T) {
	root := os.Getenv("TT_MUTEX_HOLD_ROOT")
	if os.Getenv("TT_REQUIRE_INSTALL_MUTEX_NATIVE") != "1" || root == "" {
		t.Skip("requires disposable host and hold root")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	h, err := lockInstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlockInstall(h)
	if err := os.WriteFile(filepath.Join(root, "ready"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(root, "release")); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("mutex hold timed out")
}

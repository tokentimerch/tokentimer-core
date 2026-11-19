//go:build windows

package bootstraplock

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Unverified helpers exist only in tests to demonstrate lock semantics.
// They must never be used as a package authentication or execution boundary.
func LockTree(root string) (*Locks, error) { return lockTree(root, nil) }

func Run(root, executable string, args ...string) error {
	if !filepath.IsAbs(root) || !filepath.IsAbs(executable) {
		return fmt.Errorf("absolute paths required")
	}
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(executable))
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("command must be a bundle entry")
	}
	locks, err := LockTree(root)
	if err != nil {
		return err
	}
	defer locks.Close()
	if !locks.files[strings.ToLower(filepath.Clean(executable))] {
		return fmt.Errorf("command was not a locked bundle file")
	}
	command := exec.Command(executable, args...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}

func TestLocksPreventFileAndDirectoryReplacement(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "bundle")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "node.exe")
	if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	locks, err := LockTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("replacement"), 0600); err == nil {
		t.Error("locked file was writable")
	}
	if err := os.Rename(root, filepath.Join(base, "renamed")); err == nil {
		t.Error("locked directory was renamed")
	}
	locks.Close()
	if err := os.Rename(root, filepath.Join(base, "renamed")); err != nil {
		t.Fatalf("rename after close: %v", err)
	}
}

func TestDirectoryLockDoesNotPreventNewEntries(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "bundle")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	locks, err := LockTree(root)
	if err != nil {
		t.Fatal(err)
	}
	defer locks.Close()
	if err := os.WriteFile(filepath.Join(root, "new-entry"), []byte("created"), 0600); err != nil {
		t.Fatalf("cannot demonstrate the required protected-directory prerequisite: %v", err)
	}
}

func TestRunRejectsCommandOutsideBundle(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "bundle")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := Run(root, filepath.Join(base, "outside.exe")); err == nil {
		t.Fatal("accepted command outside bundle")
	}
}

func TestRejectsReparsePoint(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "bundle")
	target := filepath.Join(base, "target")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "New-Item -ItemType Junction -Path $env:TT_LOCK_LINK -Target $env:TT_LOCK_TARGET -ErrorAction Stop | Out-Null")
	command.Env = append(os.Environ(), "TT_LOCK_LINK="+filepath.Join(root, "link"), "TT_LOCK_TARGET="+target)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("junction unavailable: %v: %s", err, output)
	}
	locks, err := LockTree(root)
	if err == nil {
		locks.Close()
		t.Fatal("accepted reparse point")
	}
}

func TestChild(t *testing.T) {
	if os.Getenv("TT_LOCK_CHILD") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("TT_LOCK_MARKER"), []byte("started"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(os.Getenv("TT_LOCK_RELEASE")); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("release signal did not arrive")
}

func TestRunHoldsLocksUntilChildExits(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "bundle")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(root, "child.exe")
	destination, err := os.Create(copyPath)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, err = io.Copy(destination, source)
	if closeErr := destination.Close(); err == nil {
		err = closeErr
	}
	source.Close()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(base, "started")
	release := filepath.Join(base, "release")
	t.Setenv("TT_LOCK_CHILD", "1")
	t.Setenv("TT_LOCK_MARKER", marker)
	t.Setenv("TT_LOCK_RELEASE", release)
	done := make(chan error, 1)
	go func() { done <- Run(root, copyPath, "-test.run=^TestChild$") }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("child exited early: %v", err)
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("child did not start")
	}
	if err := os.WriteFile(copyPath, []byte("replace"), 0600); err == nil {
		t.Error("child executable could be replaced")
	}
	if err := os.Rename(root, filepath.Join(base, "renamed")); err == nil {
		t.Error("bundle could be renamed while child ran")
	}
	if err := os.WriteFile(release, []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child did not exit")
	}
}

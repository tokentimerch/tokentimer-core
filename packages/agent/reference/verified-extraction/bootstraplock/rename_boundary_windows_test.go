//go:build windows

package bootstraplock

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLockedDirectoryRejectsRename(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "old")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	l := &Locks{}
	if err := l.open(root, true, nil); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Rename(root, filepath.Join(parent, "new")); err == nil {
		t.Fatal("directory renamed while locked without FILE_SHARE_DELETE")
	}
}

func TestLockedAncestorRejectsRenameWhileChildLocked(t *testing.T) {
	tmp := t.TempDir()
	parent := filepath.Join(tmp, "parent")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0700); err != nil {
		t.Fatal(err)
	}
	l := &Locks{}
	if err := l.open(parent, true, nil); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.open(child, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, filepath.Join(tmp, "moved")); err == nil {
		t.Fatal("locked ancestor renamed")
	}
}

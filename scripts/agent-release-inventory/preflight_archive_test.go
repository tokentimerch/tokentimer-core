package main

import (
	"io"
	"os"
	"testing"
)

// This preflight only checks archive structure before extraction on a CI
// runner. It does not authenticate, sign, qualify, or release the archive.
func TestPreflightArchive(t *testing.T) {
	name := os.Getenv("TT_PREFLIGHT_ARCHIVE")
	if name == "" {
		t.Skip("no signing-preflight archive requested")
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() <= 0 || stat.Size() > maxArchiveBytes {
		t.Fatal("invalid preflight archive")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxArchiveBytes+1))
	if err != nil || len(data) != int(stat.Size()) {
		t.Fatal("preflight archive read failed")
	}
	if _, err := listFiles(data); err != nil {
		t.Fatal(err)
	}
}

package verifiedextraction

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

type item struct {
	name string
	data string
	kind byte
}

func archive(t *testing.T, items []item) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	w := tar.NewWriter(z)
	for _, i := range items {
		typ := i.kind
		if typ == 0 {
			typ = tar.TypeReg
		}
		size := int64(len(i.data))
		if typ != tar.TypeReg {
			size = 0
		}
		if err := w.WriteHeader(&tar.Header{Name: i.name, Mode: 0600, Size: size, Typeflag: typ}); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := w.Write([]byte(i.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func entry(name, data string) Entry {
	h := sha256.Sum256([]byte(data))
	return Entry{Path: name, SHA256: hex.EncodeToString(h[:]), Size: int64(len(data))}
}
func archiveHash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func TestExtractExactInventory(t *testing.T) {
	root := t.TempDir()
	data := archive(t, []item{{"package/", "", tar.TypeDir}, {"package/scripts/", "", tar.TypeDir}, {"package/scripts/install.ps1", "signed", 0}})
	if err := Extract(bytes.NewReader(data), root, []Entry{entry("package/scripts/install.ps1", "signed")}, archiveHash(data)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "scripts", "install.ps1"))
	if err != nil || string(got) != "signed" {
		t.Fatalf("wrong output: %q, %v", got, err)
	}
}

func TestRejectsArchiveWithWrongSignedDigestBeforeWriting(t *testing.T) {
	root := t.TempDir()
	data := archive(t, []item{{"package/a.js", "ok", 0}})
	if err := Extract(bytes.NewReader(data), root, []Entry{entry("package/a.js", "ok")}, archiveHash([]byte("different"))); err == nil {
		t.Fatal("unexpected acceptance")
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 0 {
		t.Fatalf("destination changed before archive authentication: %v", err)
	}
}

func TestRejectsCorruptGzipEvenWithMatchingArchiveDigest(t *testing.T) {
	data := archive(t, []item{{"package/a.js", "ok", 0}})
	data[len(data)-8] ^= 0xff
	if err := Extract(bytes.NewReader(data), t.TempDir(), []Entry{entry("package/a.js", "ok")}, archiveHash(data)); err == nil {
		t.Fatal("corrupt gzip checksum accepted")
	}
}

func TestRejectsConcatenatedGzipMembers(t *testing.T) {
	data := archive(t, []item{{"package/a.js", "ok", 0}})
	data = append(data, archive(t, []item{{"package/hidden.js", "x", 0}})...)
	if err := Extract(bytes.NewReader(data), t.TempDir(), []Entry{entry("package/a.js", "ok")}, archiveHash(data)); err == nil {
		t.Fatal("concatenated gzip members accepted")
	}
}
func TestRejectsUntrustedArchive(t *testing.T) {
	good := entry("package/a.js", "ok")
	cases := []struct {
		name     string
		files    []item
		expected []Entry
	}{
		{"traversal", []item{{"package/../bad", "ok", 0}}, []Entry{good}},
		{"alternate stream", []item{{"package/a:evil", "ok", 0}}, []Entry{good}},
		{"symlink", []item{{"package/a.js", "", tar.TypeSymlink}}, []Entry{good}},
		{"duplicate", []item{{"package/a.js", "ok", 0}, {"package/a.js", "ok", 0}}, []Entry{good}},
		{"wrong content", []item{{"package/a.js", "no", 0}}, []Entry{good}},
		{"unlisted", []item{{"package/a.js", "ok", 0}, {"package/b", "x", 0}}, []Entry{good}},
		{"missing", []item{}, []Entry{good}},
		{"case collision", []item{}, []Entry{good, entry("package/A.js", "ok")}},
		{"reserved", []item{}, []Entry{entry("package/CON.txt", "x")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := archive(t, tc.files)
			if err := Extract(bytes.NewReader(data), t.TempDir(), tc.expected, archiveHash(data)); err == nil {
				t.Fatal("unexpected acceptance")
			}
		})
	}
}

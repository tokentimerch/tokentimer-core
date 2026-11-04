//go:build windows

package verifiedextraction

import (
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLockedSignedFileRejectsModificationAndReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.exe")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := lockSignedFile(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if w, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		w.Close()
		t.Fatal("locked file opened for writing")
	}
	if err := os.Rename(path, path+".other"); err == nil {
		t.Fatal("locked file renamed")
	}
}

func TestSpcRejectsWeakFileDigestWithSHA256Signer(t *testing.T) {
	wrap := func(class, tag int, b []byte) []byte {
		x, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: b})
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	oid := func(v asn1.ObjectIdentifier) []byte {
		x, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	concat := func(parts ...[]byte) []byte {
		var x []byte
		for _, p := range parts {
			x = append(x, p...)
		}
		return x
	}
	sha256 := oid(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	sha1 := oid(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26})
	version := []byte{2, 1, 1}
	null := []byte{5, 0}
	signerAlgorithm := wrap(0, 16, concat(sha256, null))
	makeCMS := func(fileAlgorithm []byte, digestSize int) []byte {
		fileDigest, err := asn1.Marshal(make([]byte, digestSize))
		if err != nil {
			t.Fatal(err)
		}
		digestInfo := wrap(0, 16, concat(wrap(0, 16, concat(fileAlgorithm, null)), fileDigest))
		indirect := wrap(0, 16, concat(wrap(0, 16, nil), digestInfo))
		content := wrap(0, 16, concat(oid(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}), wrap(2, 0, indirect)))
		// The CMS signer algorithm remains SHA-256 in both fixtures.
		signer := wrap(0, 16, concat(version, wrap(0, 16, nil), signerAlgorithm))
		signed := wrap(0, 16, concat(version, wrap(0, 17, signerAlgorithm), content, wrap(0, 17, signer)))
		return wrap(0, 16, concat(oid(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}), wrap(2, 0, signed)))
	}
	if err := spcCMSHasSHA256(makeCMS(sha256, 32)); err != nil {
		t.Fatalf("SHA-256 file digest rejected: %v", err)
	}
	if err := spcCMSHasSHA256(makeCMS(sha1, 20)); err == nil || !strings.Contains(err.Error(), "file digest") {
		t.Fatalf("SHA-1 file digest accepted: %v", err)
	}
}

func TestExperimentalSpcNodeFixture(t *testing.T) {
	path, err := exec.LookPath("node.exe")
	if err != nil {
		t.Skip("signed fixture unavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := experimentalSpcSHA256(f); err != nil {
		t.Fatalf("SHA-256 signed node fixture: %v", err)
	}
}

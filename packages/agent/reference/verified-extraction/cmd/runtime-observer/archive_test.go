package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

type member struct {
	name string
	typ  byte
	body []byte
}

func archiveFixture(t *testing.T, members []member) []byte {
	t.Helper()
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	w := tar.NewWriter(z)
	for _, m := range members {
		h := &tar.Header{Name: m.name, Typeflag: m.typ, Mode: 0600}
		if m.typ == tar.TypeReg {
			h.Size = int64(len(m.body))
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size != 0 {
			if _, err := w.Write(m.body); err != nil {
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
	return out.Bytes()
}

func TestRuntimeBytesAreBoundToCandidateAndPin(t *testing.T) {
	node := []byte("synthetic-runtime")
	path := "package/runtime/amd64/node.exe"
	valid := []member{{name: path, typ: tar.TypeReg, body: node}}
	archive := archiveFixture(t, valid)
	got, err := runtimeFromArchive(archive, digest(archive), "amd64", digest(node))
	if err != nil || !bytes.Equal(got, node) {
		t.Fatalf("valid fixture: %v", err)
	}
	if _, err := runtimeFromArchive(archive, digest([]byte("other")), "amd64", digest(node)); err == nil {
		t.Fatal("wrong archive digest accepted")
	}
	if _, err := runtimeFromArchive(archive, digest(archive), "amd64", digest([]byte("other"))); err == nil {
		t.Fatal("wrong runtime pin accepted")
	}
	for _, extra := range []member{
		{name: path, typ: tar.TypeReg, body: node},
		{name: "package/../escape", typ: tar.TypeReg, body: node},
		{name: "package/CON.txt", typ: tar.TypeReg, body: node},
		{name: "package/link", typ: tar.TypeSymlink},
	} {
		bad := archiveFixture(t, append(append([]member{}, valid...), extra))
		if _, err := runtimeFromArchive(bad, digest(bad), "amd64", digest(node)); err == nil {
			t.Fatalf("unsafe archive accepted: %+v", extra)
		}
	}
	var extra bytes.Buffer
	z := gzip.NewWriter(&extra)
	_, _ = z.Write([]byte("hidden"))
	_ = z.Close()
	bad := append(append([]byte{}, archive...), extra.Bytes()...)
	if _, err := runtimeFromArchive(bad, digest(bad), "amd64", digest(node)); err == nil {
		t.Fatal("concatenated gzip accepted")
	}
}

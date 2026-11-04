package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
)

type fixture struct {
	name string
	data string
	kind byte
}

func archive(t *testing.T, entries ...fixture) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	w := tar.NewWriter(z)
	for _, e := range entries {
		kind := e.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0600, Typeflag: kind}
		if kind == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if kind == tar.TypeSymlink {
			h.Linkname = "evil"
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if kind == tar.TypeReg {
			if _, err := w.Write([]byte(e.data)); err != nil {
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

func TestInventoryBindsActualArchiveAndSBOM(t *testing.T) {
	a := archive(t, fixture{name: "package/", kind: tar.TypeDir}, fixture{name: "package/b.js", data: "second"}, fixture{name: "package/a.js", data: "first"})
	b := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"node"}]}`)
	commit := strings.Repeat("a", 40)
	v, err := build("tokentimer-agent-1.2.3-windows-amd64.tgz", a, b, "agent.cdx.json", "1.2.3", "amd64", commit)
	if err != nil {
		t.Fatal(err)
	}
	if v.Archive.SHA256 != checksum(a) || v.SBOM.SHA256 != checksum(b) || v.SourceCommit != commit || len(v.Files) != 2 {
		t.Fatal("artifact binding missing")
	}
	if v.Files[0].Path != "package/a.js" || v.Files[0].SHA256 != checksum([]byte("first")) || v.Files[0].Size != 5 {
		t.Fatal("file inventory incorrect")
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"schemaVersion":1`)) || !bytes.Contains(encoded, []byte(`"architecture":"amd64"`)) {
		t.Fatal("launcher schema mismatch")
	}
	v2, err := build("tokentimer-agent-1.2.3-windows-amd64.tgz", a, b, "agent.cdx.json", "1.2.3", "amd64", commit)
	if err != nil {
		t.Fatal(err)
	}
	encoded2, _ := json.Marshal(v2)
	if !bytes.Equal(encoded, encoded2) {
		t.Fatal("nondeterministic inventory")
	}
}

func TestRejectUnsafeArchiveEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries []fixture
	}{
		{"traversal", []fixture{{name: "package/../escape", data: "x"}}},
		{"outside", []fixture{{name: "elsewhere/a", data: "x"}}},
		{"backslash", []fixture{{name: `package/a\b`, data: "x"}}},
		{"ads", []fixture{{name: "package/a:evil", data: "x"}}},
		{"reserved", []fixture{{name: "package/con.txt", data: "x"}}},
		{"trailing-dot", []fixture{{name: "package/file.", data: "x"}}},
		{"case-duplicate", []fixture{{name: "package/A", data: "x"}, {name: "package/a", data: "y"}}},
		{"link", []fixture{{name: "package/link", kind: tar.TypeSymlink}}},
		{"file-parent", []fixture{{name: "package/a", data: "x"}, {name: "package/a/b", data: "y"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := listFiles(archive(t, tt.entries...)); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestRejectWrongCandidateAndCorruption(t *testing.T) {
	a := archive(t, fixture{name: "package/a", data: "ok"})
	b := []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","documentNamespace":"https://example.test/doc","packages":[{"name":"node","SPDXID":"SPDXRef-node"}]}`)
	for _, test := range []struct {
		name, filename, version, arch, commit string
		archive, sbom                         []byte
	}{
		{"wrong-arch-name", "tokentimer-agent-1.2.3-windows-arm64.tgz", "1.2.3", "amd64", strings.Repeat("a", 40), a, b},
		{"wrong-commit", "tokentimer-agent-1.2.3-windows-amd64.tgz", "1.2.3", "amd64", "main", a, b},
		{"invalid-sbom", "tokentimer-agent-1.2.3-windows-amd64.tgz", "1.2.3", "amd64", strings.Repeat("a", 40), a, []byte("{}")},
		{"empty-components", "tokentimer-agent-1.2.3-windows-amd64.tgz", "1.2.3", "amd64", strings.Repeat("a", 40), a, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`)},
		{"corrupted", "tokentimer-agent-1.2.3-windows-amd64.tgz", "1.2.3", "amd64", strings.Repeat("a", 40), a[:len(a)-3], b},
		{"concatenated-gzip", "tokentimer-agent-1.2.3-windows-amd64.tgz", "1.2.3", "amd64", strings.Repeat("a", 40), append(append([]byte{}, a...), a...), b},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := build(test.filename, test.archive, test.sbom, "agent.spdx.json", test.version, test.arch, test.commit); err == nil {
				t.Fatal("invalid candidate accepted")
			}
		})
	}
}

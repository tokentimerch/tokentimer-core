package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"sort"
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

func completePackage(arch string) []fixture {
	names := []string{
		"package/package.json", "package/LICENSE", "package/README.md",
		"package/bin/tokentimer-agent.js", "package/src/index.js",
		"package/scripts/install-agent.ps1", "package/src/acme/windows-command.ps1",
		"package/src/windows-material/connector.ps1", "package/runtime/LICENSE",
		"package/runtime/manifest.json", "package/runtime/" + arch + "/node.exe",
		"package/bin/tokentimer-agent-host-amd64.exe", "package/bin/tokentimer-agent-host-arm64.exe",
		"package/bin/tokentimer-adcs-chain-amd64.exe", "package/bin/tokentimer-adcs-chain-arm64.exe",
		"package/bin/tokentimer-adcs-cmc-amd64.exe", "package/bin/tokentimer-adcs-cmc-arm64.exe",
	}
	entries := make([]fixture, 0, len(names))
	for _, name := range names {
		data := name
		if strings.HasSuffix(name, "/node.exe") {
			data = "node"
		}
		entries = append(entries, fixture{name: name, data: data})
	}
	return entries
}

func componentsForPackage(entries []fixture) string {
	var components []string
	for _, f := range entries {
		if strings.HasPrefix(f.name, "package/bin/tokentimer-") && strings.HasSuffix(f.name, ".exe") {
			components = append(components, fmt.Sprintf(`{"name":%q,"hashes":[{"alg":"SHA-256","content":"%s"}]}`, f.name, checksum([]byte(f.data))))
		}
	}
	return strings.Join(components, ",")
}

func TestRequiredBundledFiles(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			entries := completePackage(arch)
			bom := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"node","licenses":[{"license":{"id":"MIT"}}],"hashes":[{"alg":"SHA-256","content":"%s"}]},%s]}`, checksum([]byte("node")), componentsForPackage(entries)))
			buildArchive := func(entries []fixture) error {
				_, err := build("tokentimer-agent-1.2.3-windows-"+arch+".tgz", archive(t, entries...), bom, "agent.cdx.json", "1.2.3", arch, strings.Repeat("a", 40))
				return err
			}
			if err := buildArchive(entries); err != nil {
				t.Fatal(err)
			}
			for i, entry := range entries {
				t.Run(entry.name, func(t *testing.T) {
					missing := append(append([]fixture{}, entries[:i]...), entries[i+1:]...)
					if err := buildArchive(missing); err == nil || !strings.Contains(err.Error(), entry.name) {
						t.Fatalf("missing file accepted: %v", err)
					}
					empty := append([]fixture{}, entries...)
					empty[i].data = ""
					if err := buildArchive(empty); err == nil || !strings.Contains(err.Error(), entry.name) {
						t.Fatalf("empty file accepted: %v", err)
					}
				})
			}
		})
	}
}

func TestInventoryBindsActualArchiveAndSBOM(t *testing.T) {
	entries := append(completePackage("amd64"), fixture{name: "package/b.js", data: "second"}, fixture{name: "package/a.js", data: "first"}, fixture{name: "package/bin/host.exe", data: "host"})
	a := archive(t, entries...)
	b := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"node","licenses":[{"license":{"id":"MIT"}}],"hashes":[{"alg":"SHA-256","content":"%s"}]},{"name":"host","hashes":[{"alg":"SHA-256","content":"%s"}]},%s]}`, checksum([]byte("node")), checksum([]byte("host")), componentsForPackage(entries)))
	commit := strings.Repeat("a", 40)
	v, err := build("tokentimer-agent-1.2.3-windows-amd64.tgz", a, b, "agent.cdx.json", "1.2.3", "amd64", commit)
	if err != nil {
		t.Fatal(err)
	}
	if v.Archive.SHA256 != checksum(a) || v.SBOM.SHA256 != checksum(b) || v.SourceCommit != commit || len(v.Files) != len(entries) {
		t.Fatal("artifact binding missing")
	}
	found := false
	for _, file := range v.Files {
		if file.Path == "package/a.js" && file.SHA256 == checksum([]byte("first")) && file.Size == 5 {
			found = true
		}
	}
	if !found {
		t.Fatal("file inventory incorrect")
	}
	if !sort.SliceIsSorted(v.Files, func(i, j int) bool { return v.Files[i].Path < v.Files[j].Path }) {
		t.Fatal("file inventory not sorted")
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
	missingHost := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"node","licenses":[{"license":{"id":"MIT"}}],"hashes":[{"alg":"SHA-256","content":"%s"}]}]}`, checksum([]byte("node"))))
	if _, err := build("tokentimer-agent-1.2.3-windows-amd64.tgz", a, missingHost, "agent.cdx.json", "1.2.3", "amd64", commit); err == nil || !strings.Contains(err.Error(), "packaged executable") {
		t.Fatal("missing helper digest accepted")
	}
	missingLicense := bytes.Replace(b, []byte(`"licenses":[{"license":{"id":"MIT"}}],`), nil, 1)
	if _, err := build("tokentimer-agent-1.2.3-windows-amd64.tgz", a, missingLicense, "agent.cdx.json", "1.2.3", "amd64", commit); err == nil || !strings.Contains(err.Error(), "license") {
		t.Fatal("missing Node license accepted")
	}
	misnamedHost := bytes.Replace(b, []byte(`"name":"host"`), []byte(`"name":"unrelated"`), 1)
	if _, err := build("tokentimer-agent-1.2.3-windows-amd64.tgz", a, misnamedHost, "agent.cdx.json", "1.2.3", "amd64", commit); err == nil || !strings.Contains(err.Error(), "identity and digest") {
		t.Fatal("unrelated component identity accepted")
	}
	wrongNodeDigest := bytes.Replace(b, []byte(checksum([]byte("node"))), []byte(strings.Repeat("a", 64)), 1)
	if _, err := build("tokentimer-agent-1.2.3-windows-amd64.tgz", a, wrongNodeDigest, "agent.cdx.json", "1.2.3", "amd64", commit); err == nil || !strings.Contains(err.Error(), "Node runtime digest") {
		t.Fatal("incorrect Node digest accepted")
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

func TestTotalEntryLimitCountsDirectories(t *testing.T) {
	entries := make([]fixture, 0, maxFiles+1)
	for i := 0; i <= maxFiles; i++ {
		entries = append(entries, fixture{name: fmt.Sprintf("package/d%05d/", i), kind: tar.TypeDir})
	}
	if _, err := listFiles(archive(t, entries...)); err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatal("excess directories accepted")
	}
}

func TestSPDXIncludesPackagedRuntime(t *testing.T) {
	entries := completePackage("amd64")
	a := archive(t, entries...)
	b := []byte(fmt.Sprintf(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","documentNamespace":"https://example.test/doc","packages":[{"name":"nodejs","SPDXID":"SPDXRef-node","licenseDeclared":"MIT","checksums":[{"algorithm":"SHA256","checksumValue":"%s"}]}],"files":[%s]}`, checksum([]byte("node")), componentsForPackage(entries)))
	if _, err := build("tokentimer-agent-1.2.3-windows-amd64.tgz", a, b, "sbom.spdx.json", "1.2.3", "amd64", strings.Repeat("a", 40)); err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(`"licenseDeclared":"MIT"`), []byte(`"licenseDeclared":"NOASSERTION"`), 1)
	if _, err := build("tokentimer-agent-1.2.3-windows-amd64.tgz", a, b, "sbom.spdx.json", "1.2.3", "amd64", strings.Repeat("a", 40)); err == nil {
		t.Fatal("unknown license accepted")
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

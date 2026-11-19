package verifiedextraction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseManifestEnforcesReleaseAndSBOM(t *testing.T) {
	sbom := []byte("document")
	sum := sha256.Sum256(sbom)
	sbomHash := hex.EncodeToString(sum[:])
	commit := strings.Repeat("a", 40)
	m := Manifest{SchemaVersion: 1, SourceCommit: commit, Version: "0.18.2", Architecture: "amd64", Archive: Artifact{Name: "agent.tgz", SHA256: strings.Repeat("b", 64)}, SBOM: Artifact{Name: "sbom.json", SHA256: sbomHash}, Files: []Entry{entry("package/a.js", "ok")}}
	content, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(content, commit, m.Version, m.Architecture, "agent.tgz", "sbom.json", sbom); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name                                     string
		content                                  []byte
		commit, version, arch, archive, sbomName string
		data                                     []byte
	}{
		{"wrong commit", content, strings.Repeat("c", 40), m.Version, m.Architecture, "agent.tgz", "sbom.json", sbom},
		{"wrong arch", content, commit, m.Version, "arm64", "agent.tgz", "sbom.json", sbom},
		{"wrong archive", content, commit, m.Version, m.Architecture, "else.tgz", "sbom.json", sbom},
		{"wrong SBOM", content, commit, m.Version, m.Architecture, "agent.tgz", "sbom.json", []byte("different")},
		{"unknown field", append(content[:len(content)-1], []byte(",\"extra\":true}")...), commit, m.Version, m.Architecture, "agent.tgz", "sbom.json", sbom},
		{"duplicate key", append(content[:len(content)-1], []byte(",\"SchemaVersion\":1}")...), commit, m.Version, m.Architecture, "agent.tgz", "sbom.json", sbom},
		{"trailing data", append(content, []byte("{}")...), commit, m.Version, m.Architecture, "agent.tgz", "sbom.json", sbom},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseManifest(tc.content, tc.commit, tc.version, tc.arch, tc.archive, tc.sbomName, tc.data); err == nil {
				t.Fatal("unexpected acceptance")
			}
		})
	}
}

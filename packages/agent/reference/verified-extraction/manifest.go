package verifiedextraction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	SchemaVersion int      `json:"schemaVersion"`
	SourceCommit  string   `json:"sourceCommit"`
	Version       string   `json:"version"`
	Architecture  string   `json:"architecture"`
	Archive       Artifact `json:"archive"`
	SBOM          Artifact `json:"sbom"`
	Files         []Entry  `json:"files"`
}

var sourceCommitPattern = regexp.MustCompile("^[a-f0-9]{40}$")
var versionPattern = regexp.MustCompile("^[0-9]+[.][0-9]+[.][0-9]+(?:-[A-Za-z0-9.-]+)?$")

func checkJSONValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("JSON nesting limit")
	}
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			raw, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := raw.(string)
			if !ok {
				return fmt.Errorf("invalid JSON key")
			}
			lower := strings.ToLower(key)
			if seen[lower] {
				return fmt.Errorf("duplicate JSON key")
			}
			seen[lower] = true
			if err := checkJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case '[':
		for d.More() {
			if err := checkJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}

// ParseManifest consumes only content already authenticated with VerifyCMS.
// Caller-provided expected values must come from a separately trusted release
// selection, not from the signed manifest itself.
func ParseManifest(content []byte, expectedCommit, expectedVersion, expectedArch, archiveName, sbomName string, sbom []byte) (Manifest, error) {
	var m Manifest
	if len(content) == 0 || len(content) > 8<<20 || len(sbom) == 0 || len(sbom) > 16<<20 {
		return m, fmt.Errorf("invalid manifest or SBOM size")
	}
	if !sourceCommitPattern.MatchString(expectedCommit) || !versionPattern.MatchString(expectedVersion) || (expectedArch != "amd64" && expectedArch != "arm64") {
		return m, fmt.Errorf("invalid expected release selection")
	}
	jsonCheck := json.NewDecoder(bytes.NewReader(content))
	if err := checkJSONValue(jsonCheck, 0); err != nil {
		return m, err
	}
	if _, err := jsonCheck.Token(); err != io.EOF {
		return m, fmt.Errorf("trailing JSON data")
	}
	d := json.NewDecoder(bytes.NewReader(content))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, err
	}
	if m.SchemaVersion != 1 || m.SourceCommit != expectedCommit || m.Version != expectedVersion || m.Architecture != expectedArch {
		return m, fmt.Errorf("wrong release selection")
	}
	validName := func(name string) bool {
		return name != "" && filepath.Base(name) == name && !strings.ContainsAny(name, "/\\:") && name != "." && name != ".."
	}
	if !validName(archiveName) || !validName(sbomName) || archiveName != m.Archive.Name || sbomName != m.SBOM.Name || !digest.MatchString(m.Archive.SHA256) || !digest.MatchString(m.SBOM.SHA256) {
		return m, fmt.Errorf("invalid artifact metadata")
	}
	sum := sha256.Sum256(sbom)
	if hex.EncodeToString(sum[:]) != m.SBOM.SHA256 {
		return m, fmt.Errorf("SBOM digest mismatch")
	}
	if len(m.Files) == 0 || len(m.Files) > maxFiles {
		return m, fmt.Errorf("invalid file count")
	}
	return m, nil
}

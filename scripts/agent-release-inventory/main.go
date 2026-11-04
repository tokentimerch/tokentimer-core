// Command agent-release-inventory creates an unsigned, deterministic inventory
// of the actual Windows agent release archive and its supplied SBOM. A separate
// trusted signing step must authenticate the resulting bytes before use.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

const maxArchiveBytes = 128 << 20
const maxExpandedBytes = 256 << 20
const maxFiles = 20000

var sourcePattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type inventory struct {
	SchemaVersion int      `json:"schemaVersion"`
	SourceCommit  string   `json:"sourceCommit"`
	Version       string   `json:"version"`
	Architecture  string   `json:"architecture"`
	Archive       artifact `json:"archive"`
	SBOM          artifact `json:"sbom"`
	Files         []entry  `json:"files"`
}

func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Windows treats case, reserved DOS names, ADS syntax and trailing periods
// specially. Reject ambiguous names before the manifest reaches an extractor.
func cleanName(name string, directory bool) (string, error) {
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if len(name) == 0 || len(name) > 1024 || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return "", errors.New("invalid archive path")
	}
	parts := strings.Split(name, "/")
	if parts[0] != "package" {
		return "", errors.New("archive entry outside package")
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 255 || !segmentPattern.MatchString(part) || strings.HasSuffix(part, ".") || part == "." || part == ".." {
			return "", errors.New("ambiguous archive component")
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			regexp.MustCompile(`^(COM|LPT)[1-9]$`).MatchString(base) {
			return "", errors.New("reserved Windows archive component")
		}
	}
	if len(parts) == 1 && !directory {
		return "", errors.New("package root is not a file")
	}
	return name, nil
}

func listFiles(compressed []byte) ([]entry, error) {
	input := bytes.NewReader(compressed)
	zr, err := gzip.NewReader(input)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	zr.Multistream(false)
	tr := tar.NewReader(zr)
	seen := map[string]byte{}
	files := []entry{}
	var expanded int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		isDir := h.Typeflag == tar.TypeDir
		if !isDir && h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("unsupported archive entry type %d", h.Typeflag)
		}
		name, err := cleanName(h.Name, isDir)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", h.Name, err)
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate archive path: %s", name)
		}
		seen[key] = h.Typeflag
		if isDir {
			if h.Size != 0 {
				return nil, errors.New("nonempty directory entry")
			}
			continue
		}
		if h.Size < 0 || h.Size > maxExpandedBytes-expanded || len(files) >= maxFiles {
			return nil, errors.New("archive content limit exceeded")
		}
		expanded += h.Size
		digest := sha256.New()
		n, err := io.Copy(digest, tr)
		if err != nil || n != h.Size {
			return nil, errors.New("truncated archive entry")
		}
		files = append(files, entry{Path: name, SHA256: hex.EncodeToString(digest.Sum(nil)), Size: n})
	}
	trailing, err := io.ReadAll(io.LimitReader(zr, 1<<20))
	if err != nil {
		return nil, err
	}
	for _, b := range trailing {
		if b != 0 {
			return nil, errors.New("unexpected trailing archive data")
		}
	}
	if len(trailing) == 1<<20 || input.Len() != 0 {
		return nil, errors.New("trailing compressed data")
	}
	if len(files) == 0 {
		return nil, errors.New("archive has no files")
	}
	for _, f := range files {
		for parent := path.Dir(f.Path); parent != "."; parent = path.Dir(parent) {
			if kind, ok := seen[strings.ToLower(parent)]; ok && kind != tar.TypeDir {
				return nil, fmt.Errorf("file is also parent directory: %s", parent)
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func build(archiveName string, compressed, sbom []byte, sbomName, version, arch, source string) (inventory, error) {
	if !sourcePattern.MatchString(source) || !versionPattern.MatchString(version) || (arch != "amd64" && arch != "arm64") {
		return inventory{}, errors.New("invalid candidate metadata")
	}
	expected := fmt.Sprintf("tokentimer-agent-%s-windows-%s.tgz", version, arch)
	if archiveName != expected || path.Base(sbomName) != sbomName || !segmentPattern.MatchString(sbomName) || len(sbomName) > 255 {
		return inventory{}, errors.New("invalid artifact name")
	}
	if len(compressed) == 0 || len(compressed) > maxArchiveBytes || len(sbom) == 0 || len(sbom) > 16<<20 {
		return inventory{}, errors.New("artifact size invalid")
	}
	var sbomMetadata struct {
		SPDXVersion       string `json:"spdxVersion"`
		SPDXID            string `json:"SPDXID"`
		DocumentNamespace string `json:"documentNamespace"`
		Packages          []struct {
			Name   string `json:"name"`
			SPDXID string `json:"SPDXID"`
		} `json:"packages"`
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Version     int    `json:"version"`
		Components  []struct {
			Name string `json:"name"`
		} `json:"components"`
	}
	if err := json.Unmarshal(sbom, &sbomMetadata); err != nil {
		return inventory{}, errors.New("invalid SPDX or CycloneDX SBOM")
	}
	switch {
	case sbomMetadata.BOMFormat == "CycloneDX":
		if (sbomMetadata.SpecVersion != "1.4" && sbomMetadata.SpecVersion != "1.5" && sbomMetadata.SpecVersion != "1.6") || sbomMetadata.Version < 1 || len(sbomMetadata.Components) == 0 {
			return inventory{}, errors.New("incomplete CycloneDX SBOM")
		}
		for _, component := range sbomMetadata.Components {
			if strings.TrimSpace(component.Name) == "" {
				return inventory{}, errors.New("unnamed CycloneDX component")
			}
		}
	case sbomMetadata.SPDXVersion == "SPDX-2.3":
		if sbomMetadata.SPDXID != "SPDXRef-DOCUMENT" || sbomMetadata.DocumentNamespace == "" || len(sbomMetadata.Packages) == 0 {
			return inventory{}, errors.New("incomplete SPDX SBOM")
		}
		for _, pkg := range sbomMetadata.Packages {
			if strings.TrimSpace(pkg.Name) == "" || !strings.HasPrefix(pkg.SPDXID, "SPDXRef-") {
				return inventory{}, errors.New("invalid SPDX package")
			}
		}
	default:
		return inventory{}, errors.New("invalid SPDX or CycloneDX SBOM")
	}
	files, err := listFiles(compressed)
	if err != nil {
		return inventory{}, err
	}
	return inventory{
		SchemaVersion: 1, SourceCommit: source, Version: version, Architecture: arch,
		Archive: artifact{Name: archiveName, SHA256: checksum(compressed)},
		SBOM:    artifact{Name: sbomName, SHA256: checksum(sbom)}, Files: files,
	}, nil
}

func main() {
	archive := flag.String("archive", "", "Windows agent .tgz")
	sbom := flag.String("sbom", "", "SPDX or CycloneDX JSON SBOM")
	version := flag.String("version", "", "agent release version")
	arch := flag.String("architecture", "", "amd64 or arm64")
	source := flag.String("source-commit", "", "full source commit SHA")
	output := flag.String("out", "", "new inventory output file")
	flag.Parse()
	if err := run(*archive, *sbom, *version, *arch, *source, *output); err != nil {
		fmt.Fprintln(os.Stderr, "agent-release-inventory:", err)
		os.Exit(1)
	}
}

func run(archive, sbom, version, arch, source, output string) error {
	if archive == "" || sbom == "" || output == "" {
		return errors.New("archive, sbom and out are required")
	}
	for _, input := range []struct {
		name  string
		limit int64
	}{{archive, maxArchiveBytes}, {sbom, 16 << 20}} {
		st, err := os.Stat(input.name)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > input.limit {
			return errors.New("input size or type invalid")
		}
	}
	a, err := os.ReadFile(archive)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(sbom)
	if err != nil {
		return err
	}
	v, err := build(path.Base(strings.ReplaceAll(archive, "\\", "/")), a, b, path.Base(strings.ReplaceAll(sbom, "\\", "/")), version, arch, source)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(encoded); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

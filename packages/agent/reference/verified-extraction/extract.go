// Package verifiedextraction extracts a previously authenticated agent archive.
// Its caller must create an empty private destination atomically before invoking
// Extract, and must keep it protected from untrusted writes until use.
package verifiedextraction

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

type Entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

const maxFiles = 20000
const maxArchiveEntries = 20000
const maxPathBytes = 1024
const maxArchiveBytes = 128 << 20
const maxFileBytes = 256 << 20
const maxTotalBytes = 256 << 20

var segment = regexp.MustCompile("^[A-Za-z0-9_.-]+$")
var digest = regexp.MustCompile("^[a-f0-9]{64}$")
var reserved = regexp.MustCompile("^(COM|LPT)[1-9]$")

func canonical(name string, directory bool) (string, error) {
	if len(name) > maxPathBytes {
		return "", fmt.Errorf("path too long")
	}
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "package" && directory {
		return "", nil
	}
	if !strings.HasPrefix(name, "package/") {
		return "", fmt.Errorf("path outside package")
	}
	name = strings.TrimPrefix(name, "package/")
	if name == "" || strings.Contains(name, "\\") {
		return "", fmt.Errorf("invalid path")
	}
	for _, p := range strings.Split(name, "/") {
		if len(p) > 255 {
			return "", fmt.Errorf("path component too long")
		}
		if !segment.MatchString(p) || p == "." || p == ".." || strings.HasSuffix(p, ".") {
			return "", fmt.Errorf("invalid path component")
		}
		stem := strings.ToUpper(strings.SplitN(p, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || reserved.MatchString(stem) {
			return "", fmt.Errorf("reserved Windows name")
		}
	}
	return name, nil
}

// Extract uses an authenticated exact inventory. Before invoking this function,
// the caller must authenticate the manifest containing the expected archive hash
// and must supply a freshly-created directory protected against untrusted writes.
// Extract rejects links, duplicates, unexpected/missing entries and hash mismatch.
// A failed extraction must never be executed.
func Extract(source io.Reader, destination string, entries []Entry, archiveSHA256 string) error {
	if !digest.MatchString(archiveSHA256) {
		return fmt.Errorf("invalid archive digest")
	}
	archive, err := io.ReadAll(io.LimitReader(source, maxArchiveBytes+1))
	if err != nil {
		return err
	}
	if len(archive) > maxArchiveBytes {
		return fmt.Errorf("archive too large")
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != archiveSHA256 {
		return fmt.Errorf("archive integrity mismatch")
	}
	if !filepath.IsAbs(destination) {
		return fmt.Errorf("destination must be absolute")
	}
	info, err := os.Lstat(destination)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("destination must be an existing private directory")
	}
	contents, err := os.ReadDir(destination)
	if err != nil || len(contents) != 0 {
		return fmt.Errorf("destination must be empty")
	}
	if len(entries) == 0 || len(entries) > maxFiles {
		return fmt.Errorf("invalid inventory size")
	}
	expected := map[string]Entry{}
	dirs := map[string]bool{"": true}
	total := int64(0)
	for _, e := range entries {
		name, err := canonical(e.Path, false)
		if err != nil {
			return err
		}
		key := strings.ToLower(name)
		if _, exists := expected[key]; exists || !digest.MatchString(e.SHA256) || e.Size < 0 || e.Size > maxFileBytes {
			return fmt.Errorf("invalid inventory entry")
		}
		total += e.Size
		if total > maxTotalBytes {
			return fmt.Errorf("inventory too large")
		}
		expected[key] = e
		for d := path.Dir(name); d != "."; d = path.Dir(d) {
			dirs[strings.ToLower(d)] = true
		}
	}
	compressed := bytes.NewReader(archive)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return err
	}
	gz.Multistream(false)
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	seenDirs := map[string]bool{}
	entryCount := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		entryCount++
		if entryCount > maxArchiveEntries {
			return fmt.Errorf("too many archive entries")
		}
		isDir := h.Typeflag == tar.TypeDir
		if !isDir && h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return fmt.Errorf("unsupported tar entry")
		}
		name, err := canonical(h.Name, isDir)
		if err != nil {
			return err
		}
		key := strings.ToLower(name)
		if isDir {
			if !dirs[key] || seenDirs[key] {
				return fmt.Errorf("unexpected or duplicate directory")
			}
			seenDirs[key] = true
			continue
		}
		e, ok := expected[key]
		if !ok || seen[key] || e.Path != h.Name || h.Size != e.Size {
			return fmt.Errorf("unexpected or duplicate file")
		}
		seen[key] = true
		target := filepath.Join(destination, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, copyErr := io.CopyN(io.MultiWriter(f, hash), tr, h.Size)
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil || n != h.Size || hex.EncodeToString(hash.Sum(nil)) != e.SHA256 {
			return fmt.Errorf("file integrity mismatch")
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("missing inventory files")
	}
	// tar may legally have zero padding, but no hidden trailing payload.
	padding, err := io.ReadAll(io.LimitReader(gz, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(padding) > 1<<20 {
		return fmt.Errorf("excessive tar padding")
	}
	for _, b := range padding {
		if b != 0 {
			return fmt.Errorf("nonzero data after tar end")
		}
	}
	if compressed.Len() != 0 {
		return fmt.Errorf("trailing compressed data")
	}
	return nil
}

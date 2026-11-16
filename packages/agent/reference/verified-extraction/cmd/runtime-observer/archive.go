package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const maxArchive = 128 << 20
const maxExpanded = 256 << 20
const maxEntries = 20000

var segment = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
var dos = regexp.MustCompile(`^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$`)
var runtimePins = map[string]string{
	"amd64": "9a4eb5f1c29c6a2e93852ead46b999e284a6a5ca8bab4d4e241d587d025a52de",
	"arm64": "c7225670c3f477778e18c43a55867f7a0d76468221245e5981ab80eb953c8102",
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// runtimeFromArchive validates the whole archive before returning bytes. It
// never extracts archive paths to disk and does not authenticate a release.
func runtimeFromArchive(compressed []byte, expectedArchive, arch, runtimePin string) ([]byte, error) {
	if len(compressed) == 0 || len(compressed) > maxArchive || digest(compressed) != expectedArchive || (arch != "amd64" && arch != "arm64") {
		return nil, errors.New("invalid candidate archive")
	}
	input := bytes.NewReader(compressed)
	z, err := gzip.NewReader(input)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	z.Multistream(false)
	t := tar.NewReader(z)
	seen := make(map[string]byte)
	var runtime []byte
	var expanded int64
	for count := 0; ; count++ {
		h, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil || count >= maxEntries {
			return nil, errors.New("invalid archive entry")
		}
		directory := h.Typeflag == tar.TypeDir
		if !directory && h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return nil, errors.New("unsupported archive entry")
		}
		name := h.Name
		if directory {
			name = strings.TrimSuffix(name, "/")
		}
		parts := strings.Split(name, "/")
		if len(name) == 0 || len(name) > 1024 || parts[0] != "package" || (len(parts) == 1 && !directory) {
			return nil, errors.New("invalid archive path")
		}
		for _, part := range parts {
			base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
			if len(part) == 0 || len(part) > 255 || !segment.MatchString(part) || part == "." || part == ".." || strings.HasSuffix(part, ".") || dos.MatchString(base) {
				return nil, errors.New("invalid archive path")
			}
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, errors.New("duplicate archive path")
		}
		seen[key] = h.Typeflag
		if h.Size < 0 || h.Size > maxExpanded-expanded || (directory && h.Size != 0) {
			return nil, errors.New("archive size exceeded")
		}
		expanded += h.Size
		if name == fmt.Sprintf("package/runtime/%s/node.exe", arch) {
			if directory || h.Size <= 0 || h.Size > maxArchive {
				return nil, errors.New("invalid runtime")
			}
			runtime, err = io.ReadAll(io.LimitReader(t, maxArchive+1))
			if err != nil || int64(len(runtime)) != h.Size {
				return nil, errors.New("truncated runtime")
			}
		}
	}
	for name := range seen {
		parts := strings.Split(name, "/")
		for i := 1; i < len(parts); i++ {
			if kind, ok := seen[strings.Join(parts[:i], "/")]; ok && kind != tar.TypeDir {
				return nil, errors.New("file is parent directory")
			}
		}
	}
	trailing, err := io.ReadAll(io.LimitReader(z, 1<<20))
	if err != nil || len(trailing) == 1<<20 || input.Len() != 0 {
		return nil, errors.New("invalid trailing data")
	}
	for _, b := range trailing {
		if b != 0 {
			return nil, errors.New("unexpected trailing data")
		}
	}
	if len(runtime) == 0 || digest(runtime) != runtimePin {
		return nil, errors.New("runtime does not match independent upstream pin")
	}
	return runtime, nil
}

//go:build windows

package verifiedextraction

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"tokentimer-verified-extraction/bootstraplock"
)

// lockVerifiedInstalledApp accepts only a manifest already authenticated with
// independent release policy. Its returned locks must remain held until every
// subsequent recovery operation is complete. Directory handles do not prevent
// a privileged actor from creating new children: callers must independently
// stop and review those actors and enforce the supplied ACL policy.
func lockVerifiedInstalledApp(app string, manifest Manifest, policy bootstraplock.Policy) (_ *bootstraplock.Locks, err error) {
	if len(manifest.Files) == 0 || len(manifest.Files) > maxFiles {
		return nil, fmt.Errorf("invalid signed inventory")
	}
	expected := map[string]Entry{}
	directories := map[string]bool{".": true}
	for _, entry := range manifest.Files {
		name, e := canonical(entry.Path, false)
		if e != nil || !digest.MatchString(entry.SHA256) || entry.Size < 0 || entry.Size > maxFileBytes {
			return nil, fmt.Errorf("invalid signed inventory")
		}
		name = filepath.FromSlash(name)
		key := strings.ToLower(name)
		if _, exists := expected[key]; exists {
			return nil, fmt.Errorf("duplicate signed inventory path")
		}
		expected[key] = entry
		for d := filepath.Dir(name); d != "."; d = filepath.Dir(d) {
			directories[strings.ToLower(d)] = true
		}
	}
	locks, err := bootstraplock.LockProtectedTree(app, policy)
	if err != nil {
		return nil, fmt.Errorf("active application tree is not protected")
	}
	defer func() {
		if err != nil {
			locks.Close()
		}
	}()
	seen := map[string]bool{}
	err = filepath.WalkDir(app, func(path string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("application entry unavailable")
		}
		rel, e := filepath.Rel(app, path)
		if e != nil {
			return fmt.Errorf("application path unavailable")
		}
		key := strings.ToLower(rel)
		if item.IsDir() {
			if !directories[key] {
				return fmt.Errorf("unexpected application directory")
			}
			return nil
		}
		if item.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("linked application entry")
		}
		entry, ok := expected[key]
		if !ok || seen[key] {
			return fmt.Errorf("unexpected application file")
		}
		seen[key] = true
		f, e := os.Open(path)
		if e != nil {
			return fmt.Errorf("application file unavailable")
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() != entry.Size {
			return fmt.Errorf("application size mismatch")
		}
		h := sha256.New()
		if _, e = io.Copy(h, f); e != nil || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
			return fmt.Errorf("application digest mismatch")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(seen) != len(expected) {
		return nil, fmt.Errorf("signed application file missing")
	}
	return locks, nil
}

type installedAppLock struct{ locks *bootstraplock.Locks }

func (l *installedAppLock) Close() error { l.locks.Close(); return nil }

// authenticatedActiveVerifier never accepts a manifest or release selection
// from the journal. Candidate policy is supplied by the authenticated caller.
func authenticatedActiveVerifier(c Candidate, policy bootstraplock.Policy) (func(string, string) (io.Closer, error), error) {
	content, err := VerifyCMS(c.CMS, c.PublisherPin)
	if err != nil {
		return nil, fmt.Errorf("signed application manifest rejected")
	}
	manifest, err := ParseManifest(content, c.SourceCommit, c.Version, c.Architecture, c.ArchiveName, c.SBOMName, c.SBOM)
	if err != nil {
		return nil, fmt.Errorf("signed application manifest rejected")
	}
	if err = requireQualifiedInstaller(manifest, c.InstallerSHA256); err != nil {
		return nil, fmt.Errorf("qualified installer mismatch")
	}
	if !digest.MatchString(c.RuntimePublisherPin) {
		return nil, fmt.Errorf("independent runtime publisher pin required")
	}
	return func(app, archiveSHA256 string) (io.Closer, error) {
		if manifest.Archive.SHA256 != archiveSHA256 {
			return nil, fmt.Errorf("signed archive does not match retained intent")
		}
		locks, err := lockVerifiedInstalledApp(app, manifest, policy)
		if err != nil {
			return nil, err
		}
		if err = verifyAuthenticode(app, manifest.Files, manifest.Architecture, c.PublisherPin, c.RuntimePublisherPin); err != nil {
			locks.Close()
			return nil, fmt.Errorf("active application signatures rejected")
		}
		return &installedAppLock{locks}, nil
	}, nil
}

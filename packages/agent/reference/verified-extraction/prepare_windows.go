//go:build windows

package verifiedextraction

import (
	"fmt"
	"io"
	"path/filepath"
)

// Candidate's publisher pins and expected release selection are independent
// trusted inputs, never values taken from the downloaded package.
type Candidate struct {
	CMS                 []byte
	PublisherPin        string
	RuntimePublisherPin string
	SourceCommit        string
	Version             string
	Architecture        string
	ArchiveName         string
	Archive             io.Reader
	SBOMName            string
	SBOM                []byte
}

// Prepared keeps the secure paths locked through verification and use.
type Prepared struct {
	staging  *PrivateStaging
	manifest Manifest
}

func (p *Prepared) InstallerPath() (string, error) {
	if p == nil || p.staging == nil || p.staging.ancestors == nil || p.staging.staging == nil || p.staging.payload == nil {
		return "", fmt.Errorf("prepared payload is not locked")
	}
	return filepath.Join(p.staging.Root(), "scripts", "install-agent.ps1"), nil
}
func (p *Prepared) Manifest() Manifest { return p.manifest }
func (p *Prepared) Cleanup() error     { return p.staging.Cleanup() }

// Close releases locks if cleanup cannot complete; retained files need manual recovery.
func (p *Prepared) Close() {
	if p != nil && p.staging != nil {
		p.staging.Close()
	}
}

func cleanupFailedStage(stage *PrivateStaging, cause error) error {
	if cleanupErr := stage.Cleanup(); cleanupErr != nil {
		stage.Close()
		return fmt.Errorf("%v; staging cleanup failed; manual recovery required: %w", cause, cleanupErr)
	}
	return cause
}

// PrepareCandidate assumes the launcher itself was independently authenticated
// before execution. It fails closed on unsigned/untrusted data and never
// invokes extracted package code. Calling code must keep Prepared alive through
// any installer execution and perform ownership-safe cleanup afterwards.
func PrepareCandidate(c Candidate) (_ *Prepared, err error) {
	content, err := VerifyCMS(c.CMS, c.PublisherPin)
	if err != nil {
		return nil, err
	}
	manifest, err := ParseManifest(content, c.SourceCommit, c.Version, c.Architecture, c.ArchiveName, c.SBOMName, c.SBOM)
	if err != nil {
		return nil, err
	}
	if !digest.MatchString(c.RuntimePublisherPin) {
		return nil, fmt.Errorf("independent runtime publisher pin is required")
	}
	if c.Archive == nil {
		return nil, fmt.Errorf("archive is required")
	}
	stage, err := NewPrivateStaging()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = cleanupFailedStage(stage, err)
		}
	}()
	if err = Extract(c.Archive, stage.Root(), manifest.Files, manifest.Archive.SHA256); err != nil {
		return nil, err
	}
	if err = stage.LockPayload(); err != nil {
		return nil, err
	}
	if err = verifyAuthenticode(stage.Root(), manifest.Files, manifest.Architecture, c.PublisherPin, c.RuntimePublisherPin); err != nil {
		return nil, err
	}
	return &Prepared{staging: stage, manifest: manifest}, nil
}

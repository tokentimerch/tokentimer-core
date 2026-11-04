//go:build windows

// This command is not wired into releases. Before execution an independent
// trusted bootstrap or enforced App Control policy must authenticate the
// executable and its publisher; self-verification is not a trust boundary.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	verified "tokentimer-verified-extraction"
)

// The release signing build must set all policy fields before signing this
// executable. They are intentionally not command-line inputs and are never
// read from the downloaded manifest, archive or adjacent files.
var (
	trustedPublisherSHA256   string
	trustedRuntimeSHA256     string
	qualifiedInstallerSHA256 string
	qualifiedSourceCommit    string
	qualifiedVersion         string
	qualifiedArchitecture    string
)

type trustPolicy struct{ publisher, runtimePublisher, installer, commit, version, architecture string }

func currentTrustPolicy() trustPolicy {
	return trustPolicy{trustedPublisherSHA256, trustedRuntimeSHA256, qualifiedInstallerSHA256, qualifiedSourceCommit, qualifiedVersion, qualifiedArchitecture}
}
func (p trustPolicy) validate() error {
	hash := regexp.MustCompile(`^[a-f0-9]{64}$`)
	commit := regexp.MustCompile(`^[a-f0-9]{40}$`)
	version := regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$`)
	if !hash.MatchString(p.publisher) || !hash.MatchString(p.runtimePublisher) || !hash.MatchString(p.installer) || !commit.MatchString(p.commit) || !version.MatchString(p.version) || (p.architecture != "amd64" && p.architecture != "arm64") || p.architecture != runtime.GOARCH {
		return fmt.Errorf("launcher lacks a valid release-bound trust policy")
	}
	return nil
}

func bounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || int64(len(b)) > limit {
		return nil, fmt.Errorf("invalid input size")
	}
	return b, nil
}
func main() {
	inspect := flag.Bool("inspect-quarantine", false, "inspect retained staging without changing it")
	manifestPath := flag.String("manifest", "", "encapsulated signed CMS manifest")
	archivePath := flag.String("archive", "", "agent archive")
	sbomPath := flag.String("sbom", "", "SBOM")
	flag.Parse()
	policy := currentTrustPolicy()
	if err := policy.validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *inspect {
		if *manifestPath != "" || *archivePath != "" || *sbomPath != "" || len(flag.Args()) != 0 {
			fmt.Fprintln(os.Stderr, "inspection does not accept package or installer arguments")
			os.Exit(2)
		}
		records, err := verified.InspectQuarantine(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "quarantine inspection failed:", err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(records); err != nil {
			fmt.Fprintln(os.Stderr, "quarantine report could not be written")
			os.Exit(1)
		}
		return
	}
	if *manifestPath == "" || *archivePath == "" || *sbomPath == "" {
		fmt.Fprintln(os.Stderr, "signed manifest, archive and SBOM are required")
		os.Exit(2)
	}
	cms, err := bounded(*manifestPath, 8<<20)
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest read failed")
		os.Exit(1)
	}
	sbom, err := bounded(*sbomPath, 16<<20)
	if err != nil {
		fmt.Fprintln(os.Stderr, "SBOM read failed")
		os.Exit(1)
	}
	archive, err := os.Open(*archivePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "archive open failed")
		os.Exit(1)
	}
	defer archive.Close()
	candidate := verified.Candidate{CMS: cms, PublisherPin: policy.publisher, RuntimePublisherPin: policy.runtimePublisher, InstallerSHA256: policy.installer, SourceCommit: policy.commit, Version: policy.version, Architecture: policy.architecture, ArchiveName: filepath.Base(*archivePath), Archive: archive, SBOMName: filepath.Base(*sbomPath), SBOM: sbom}
	// Installer flags follow --; the bootstrap token is read from a protected
	// environment variable or prompted by the existing installer, never logged.
	result, err := verified.RunCandidate(context.Background(), candidate, flag.Args(), os.Getenv("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN"))
	if result.CleanupPending {
		fmt.Fprintln(os.Stderr, "Protected staging retained; operator reconciliation is required.")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent installation failed:", err)
		os.Exit(1)
	}
	if result.InstallerErr != nil {
		fmt.Fprintln(os.Stderr, "agent installation failed:", result.InstallerErr)
		os.Exit(1)
	}
}

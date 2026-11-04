//go:build windows

// This command is not wired into releases. Before execution an independent
// trusted bootstrap or enforced App Control policy must authenticate the
// executable and its publisher; self-verification is not a trust boundary.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	verified "tokentimer-verified-extraction"
)

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
	manifestPath := flag.String("manifest", "", "encapsulated signed CMS manifest")
	archivePath := flag.String("archive", "", "agent archive")
	sbomPath := flag.String("sbom", "", "SBOM")
	publisherPin := flag.String("publisher-sha256", "", "independently trusted publisher certificate SHA-256")
	runtimePin := flag.String("runtime-publisher-sha256", "", "independently trusted Node publisher certificate SHA-256")
	installerPin := flag.String("installer-sha256", "", "independently trusted qualified installer SHA-256")
	commit := flag.String("source-commit", "", "expected release source commit")
	version := flag.String("version", "", "expected release version")
	architecture := flag.String("architecture", "", "expected native architecture")
	flag.Parse()
	if *manifestPath == "" || *archivePath == "" || *sbomPath == "" || *publisherPin == "" || *runtimePin == "" || *installerPin == "" || *commit == "" || *version == "" || *architecture == "" {
		fmt.Fprintln(os.Stderr, "all signed package and independently trusted identity flags are required")
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
	candidate := verified.Candidate{CMS: cms, PublisherPin: *publisherPin, RuntimePublisherPin: *runtimePin, InstallerSHA256: *installerPin, SourceCommit: *commit, Version: *version, Architecture: *architecture, ArchiveName: filepath.Base(*archivePath), Archive: archive, SBOMName: filepath.Base(*sbomPath), SBOM: sbom}
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

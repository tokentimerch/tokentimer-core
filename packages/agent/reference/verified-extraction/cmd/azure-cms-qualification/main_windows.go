//go:build windows && azurecmsqualify

// This intentionally opt-in tool checks signed manifest bytes only. It does
// not authenticate itself, install anything, or qualify a release archive.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	verified "tokentimer-verified-extraction"
)

// A trusted build supplies every value independently before signing this tool.
// Neither command-line options nor downloaded candidate files can set them.
var (
	qualifiedPublisherIssuer string
	qualifiedTimestampIssuer string
	qualifiedProfileEKU      string
	qualifiedManifestSHA256  string
)

func readBounded(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("absolute input path required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("regular input file required")
	}
	data, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > 8<<20 {
		return nil, fmt.Errorf("invalid input size")
	}
	return data, nil
}

func run(args []string) error {
	flags := flag.NewFlagSet("azure-cms-qualification", flag.ContinueOnError)
	ack := flags.Bool("experimental", false, "acknowledge experimental manifest-only verification")
	cmsPath := flags.String("cms", "", "absolute path to signed CMS")
	manifestPath := flags.String("manifest", "", "absolute path to independently pinned manifest")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*ack || flags.NArg() != 0 {
		return fmt.Errorf("explicit experimental acknowledgement is required")
	}
	policy := verified.AzureCMSQualificationPolicy{PublisherIssuerSHA256: qualifiedPublisherIssuer, TimestampIssuerSHA256: qualifiedTimestampIssuer, ProfileEKU: qualifiedProfileEKU, ExpectedManifestSHA256: qualifiedManifestSHA256}
	if err := verified.ValidateAzureCMSQualificationPolicy(policy); err != nil {
		return err
	}
	cms, err := readBounded(*cmsPath)
	if err != nil {
		return err
	}
	manifest, err := readBounded(*manifestPath)
	if err != nil {
		return err
	}
	return verified.QualifyAzureCMSExperimental(cms, manifest, policy)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Experimental manifest check failed:", err)
		os.Exit(1)
	}
	fmt.Println("Experimental signed manifest bytes verified; archive and release are not qualified.")
}

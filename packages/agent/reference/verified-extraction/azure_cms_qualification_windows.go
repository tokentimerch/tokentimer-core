//go:build windows && azurecmsqualify

package verifiedextraction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// AzureCMSQualificationPolicy is an independently supplied experimental
// qualification policy. It must not be derived from the candidate package.
type AzureCMSQualificationPolicy struct {
	PublisherIssuerSHA256  string
	TimestampIssuerSHA256  string
	ProfileEKU             string
	ExpectedManifestSHA256 string
}

// ValidateAzureCMSQualificationPolicy rejects absent or malformed independent
// pins before any potentially untrusted candidate is read.
func ValidateAzureCMSQualificationPolicy(p AzureCMSQualificationPolicy) error {
	if !digest.MatchString(p.PublisherIssuerSHA256) || !digest.MatchString(p.TimestampIssuerSHA256) ||
		!digest.MatchString(p.ExpectedManifestSHA256) || !artifactProfile.MatchString(p.ProfileEKU) || reservedProfile.MatchString(p.ProfileEKU) {
		return fmt.Errorf("independent qualification policy is missing or invalid")
	}
	return nil
}

// QualifyAzureCMSExperimental compares authenticated CMS content with exact
// independently pinned manifest bytes. It does not qualify an agent archive,
// release, bootstrap, or installation, and is not called by the launcher.
func QualifyAzureCMSExperimental(cms, expected []byte, p AzureCMSQualificationPolicy) error {
	return qualifyAzureCMSWithContexts(cms, expected, p, experimentalChainContext{}, experimentalChainContext{})
}

func qualifyAzureCMSWithContexts(cms, expected []byte, p AzureCMSQualificationPolicy, publisherChain, timestampChain experimentalChainContext) error {
	if err := ValidateAzureCMSQualificationPolicy(p); err != nil {
		return err
	}
	if len(expected) == 0 || len(expected) > 8<<20 {
		return fmt.Errorf("invalid expected manifest")
	}
	// Keep a single local snapshot for both the independent digest and the
	// exact comparison, without trusting a file after it has been read.
	expected = append([]byte(nil), expected...)
	sum := sha256.Sum256(expected)
	if hex.EncodeToString(sum[:]) != p.ExpectedManifestSHA256 {
		return fmt.Errorf("expected manifest does not match independent digest")
	}
	content, err := verifyAzureCMSExperimentalWithContexts(cms, azureCMSExperimentalPolicy{
		PublisherIssuerSHA256: p.PublisherIssuerSHA256, TimestampIssuerSHA256: p.TimestampIssuerSHA256, ProfileEKU: p.ProfileEKU,
	}, publisherChain, timestampChain)
	if err != nil {
		return err
	}
	if !bytes.Equal(content, expected) {
		return fmt.Errorf("verified manifest bytes differ from the independently qualified manifest")
	}
	return nil
}

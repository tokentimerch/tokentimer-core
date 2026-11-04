//go:build windows

package verifiedextraction

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// This isolated experiment is deliberately not called by the launcher. A real
// Azure publisher, timestamps, chain/revocation policy and native architectures
// must be qualified independently before any production integration.
//
//go:embed verify-azure-cms-experimental.ps1
var azureCMSExperimentalScript string

//go:embed extract-azure-cms-experimental.ps1
var azureCMSExperimentalExtractScript string

var artifactProfile = regexp.MustCompile(`^1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.){2,}[0-9]+$`)
var reservedProfile = regexp.MustCompile(`^1\.3\.6\.1\.4\.1\.311\.97\.1\.(?:0|3\.1|4\.1)(?:\.|$)`)

type azureCMSExperimentalPolicy struct {
	PublisherIssuerSHA256 string
	TimestampIssuerSHA256 string
	ProfileEKU            string
}

// verifyAzureCMSExperimental authenticates an encapsulated CMS only with
// independently supplied identity pins. It is not a supported release path.
func verifyAzureCMSExperimental(cms []byte, p azureCMSExperimentalPolicy) ([]byte, error) {
	if len(cms) == 0 || len(cms) > 8<<20 || !digest.MatchString(p.PublisherIssuerSHA256) ||
		!digest.MatchString(p.TimestampIssuerSHA256) || !artifactProfile.MatchString(p.ProfileEKU) || reservedProfile.MatchString(p.ProfileEKU) {
		return nil, fmt.Errorf("invalid experimental Azure CMS trust inputs")
	}
	// Snapshot the bytes once so both isolated verification stages see exactly
	// the same content even if the caller reuses its input buffer.
	cms = append([]byte(nil), cms...)
	extractRequest, err := json.Marshal(struct {
		CMS string `json:"cms"`
	}{base64.StdEncoding.EncodeToString(cms)})
	if err != nil {
		return nil, err
	}
	extracted, err := runSystemPowerShell(azureCMSExperimentalExtractScript, extractRequest)
	if err != nil {
		return nil, fmt.Errorf("experimental CMS signature extraction failed: %w", err)
	}
	var fields struct {
		Token     string `json:"token"`
		Signature string `json:"signature"`
	}
	if len(extracted) > 16<<20 || json.Unmarshal(extracted, &fields) != nil {
		return nil, fmt.Errorf("invalid CMS extraction result")
	}
	token, err := base64.StdEncoding.Strict().DecodeString(fields.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp token")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(fields.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid CMS signature")
	}
	stamp, timestampCert, err := verifyExperimentalTimestamp(token, signature)
	if err != nil {
		return nil, err
	}
	request, err := json.Marshal(struct {
		CMS             string `json:"cms"`
		PublisherIssuer string `json:"publisherIssuer"`
		TimestampIssuer string `json:"timestampIssuer"`
		Profile         string `json:"profile"`
		Timestamp       string `json:"timestamp"`
		TimestampCert   string `json:"timestampCertificate"`
	}{base64.StdEncoding.EncodeToString(cms), p.PublisherIssuerSHA256, p.TimestampIssuerSHA256, p.ProfileEKU,
		stamp.Format(time.RFC3339Nano), base64.StdEncoding.EncodeToString(timestampCert)})
	if err != nil {
		return nil, err
	}
	output, err := runSystemPowerShell(azureCMSExperimentalScript, request)
	if err != nil {
		return nil, fmt.Errorf("experimental Azure CMS trust verification failed: %w", err)
	}
	content, err := base64.StdEncoding.Strict().DecodeString(string(output))
	if err != nil || len(content) == 0 || len(content) > 8<<20 {
		return nil, fmt.Errorf("invalid verified content")
	}
	return content, nil
}

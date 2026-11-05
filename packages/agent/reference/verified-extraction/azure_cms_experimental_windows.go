//go:build windows

package verifiedextraction

import (
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
)

// This isolated experiment is deliberately not called by the launcher. A real
// Azure publisher, timestamps, chain/revocation policy and native architectures
// must be qualified independently before any production integration.
//
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
	return verifyAzureCMSExperimentalWithContexts(cms, p, experimentalChainContext{}, experimentalChainContext{})
}

func verifyAzureCMSExperimentalWithContexts(cms []byte, p azureCMSExperimentalPolicy, publisherChain, timestampChain experimentalChainContext) ([]byte, error) {
	if len(cms) == 0 || len(cms) > 8<<20 || !digest.MatchString(p.PublisherIssuerSHA256) ||
		!digest.MatchString(p.TimestampIssuerSHA256) || !artifactProfile.MatchString(p.ProfileEKU) || reservedProfile.MatchString(p.ProfileEKU) {
		return nil, fmt.Errorf("invalid experimental Azure CMS trust inputs")
	}
	// Snapshot the bytes once so both isolated verification stages see exactly
	// the same content even if the caller reuses its input buffer.
	cms = append([]byte(nil), cms...)
	// SignedCms.Decode can ignore bytes after the outer CMS object. Reject
	// trailing content before handing the snapshot to the native verifier.
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(cms, &outer)
	if err != nil || len(rest) != 0 || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return nil, fmt.Errorf("invalid experimental CMS envelope")
	}
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
		Token                 string   `json:"token"`
		Signature             string   `json:"signature"`
		Publisher             string   `json:"publisher"`
		Content               string   `json:"content"`
		PublisherCertificates []string `json:"publisherCertificates"`
		TimestampCertificates []string `json:"timestampCertificates"`
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
	publisher, err := base64.StdEncoding.Strict().DecodeString(fields.Publisher)
	if err != nil {
		return nil, fmt.Errorf("invalid publisher certificate")
	}
	pubCert, err := x509.ParseCertificate(publisher)
	if err != nil {
		return nil, err
	}
	tsaCert, err := x509.ParseCertificate(timestampCert)
	if err != nil {
		return nil, err
	}
	if err = experimentalPublisherEKU(pubCert, p.ProfileEKU); err != nil {
		return nil, err
	}
	if err = experimentalTimestampEKU(tsaCert); err != nil {
		return nil, err
	}
	pubExtra, err := experimentalDecodeCerts(fields.PublisherCertificates)
	if err != nil {
		return nil, err
	}
	tsaExtra, err := experimentalDecodeCerts(fields.TimestampCertificates)
	if err != nil {
		return nil, err
	}
	if err = experimentalVerifyChain(timestampCert, tsaExtra, "1.3.6.1.5.5.7.3.8", p.TimestampIssuerSHA256, stamp, timestampChain); err != nil {
		return nil, fmt.Errorf("timestamp chain: %w", err)
	}
	if err = experimentalVerifyChain(publisher, pubExtra, "1.3.6.1.5.5.7.3.3", p.PublisherIssuerSHA256, stamp, publisherChain); err != nil {
		return nil, fmt.Errorf("publisher chain: %w", err)
	}
	content, err := base64.StdEncoding.Strict().DecodeString(fields.Content)
	if err != nil || len(content) == 0 || len(content) > 8<<20 {
		return nil, fmt.Errorf("invalid verified content")
	}
	return content, nil
}

func experimentalDecodeCerts(values []string) ([][]byte, error) {
	if len(values) > 100 {
		return nil, fmt.Errorf("too many certificates")
	}
	var out [][]byte
	for _, v := range values {
		b, err := base64.StdEncoding.Strict().DecodeString(v)
		if err != nil || len(b) == 0 || len(b) > 1<<20 {
			return nil, fmt.Errorf("invalid certificate")
		}
		out = append(out, b)
	}
	return out, nil
}

func experimentalPublisherEKU(cert *x509.Certificate, profile string) error {
	code := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			code = true
		}
	}
	match := false
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.String() == profile {
			match = true
		}
	}
	if !code || !match {
		return fmt.Errorf("invalid publisher EKU")
	}
	return nil
}

func experimentalTimestampEKU(cert *x509.Certificate) error {
	critical := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) && ext.Critical {
			critical = true
		}
	}
	if !critical || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(cert.UnknownExtKeyUsage) != 0 {
		return fmt.Errorf("invalid timestamp EKU")
	}
	return nil
}

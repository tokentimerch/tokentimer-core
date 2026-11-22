//go:build windows

package verifiedextraction

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func experimentalFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "fixtures", "windows-rfc3161", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAzureCMSExperimentalTimestampBinding(t *testing.T) {
	fixture := experimentalFixture(t, "timestamped.p7")
	request, err := json.Marshal(map[string]string{"cms": base64.StdEncoding.EncodeToString(fixture)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runSystemPowerShell(azureCMSExperimentalExtractScript, request)
	if err != nil {
		t.Fatalf("CMS extraction under launcher environment: %v", err)
	}
	var value struct {
		Token     string `json:"token"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(result, &value); err != nil {
		t.Fatal(err)
	}
	token, err := base64.StdEncoding.Strict().DecodeString(value.Token)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(value.Signature)
	if err != nil {
		t.Fatal(err)
	}
	stamp, certificate, err := verifyExperimentalTimestamp(token, signature)
	if err != nil {
		t.Fatalf("native timestamp verification: %v", err)
	}
	if stamp.Format("2006-01-02T15:04:05.000Z") != "2026-11-04T22:51:19.437Z" || len(certificate) == 0 {
		t.Fatal("unexpected timestamp or missing TSA certificate")
	}
	signature[0] ^= 1
	if _, _, err := verifyExperimentalTimestamp(token, signature); err == nil {
		t.Fatal("accepted different signature")
	}
	signature[0] ^= 1
	token[len(token)-1] ^= 1
	if _, _, err := verifyExperimentalTimestamp(token, signature); err == nil {
		t.Fatal("accepted altered timestamp")
	}
}

func TestAzureCMSExperimentalRejectsUntrustedFixtures(t *testing.T) {
	policy := azureCMSExperimentalPolicy{
		PublisherIssuerSHA256: strings.Repeat("a", 64), TimestampIssuerSHA256: strings.Repeat("b", 64),
		ProfileEKU: "1.3.6.1.4.1.311.97.990309390.766961637.194916062.941502583",
	}
	timestamped := experimentalFixture(t, "timestamped.p7")
	tampered := bytes.Clone(timestamped)
	offset := bytes.Index(tampered, []byte(`{"fixture":true}`))
	if offset < 0 {
		t.Fatal("fixture payload not found")
	}
	tampered[offset+2] ^= 1
	for name, value := range map[string][]byte{
		"untrusted publisher": timestamped,
		"missing timestamp":   experimentalFixture(t, "untimestamped.p7"),
		"altered content":     tampered,
		"malformed CMS":       []byte("not CMS"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyAzureCMSExperimental(value, policy); err == nil {
				t.Fatal("untrusted content accepted")
			}
		})
	}
	for name, change := range map[string]func(*azureCMSExperimentalPolicy){
		"missing issuer":    func(p *azureCMSExperimentalPolicy) { p.PublisherIssuerSHA256 = "" },
		"timestamp issuer":  func(p *azureCMSExperimentalPolicy) { p.TimestampIssuerSHA256 = strings.Repeat("A", 64) },
		"generic profile":   func(p *azureCMSExperimentalPolicy) { p.ProfileEKU = "1.3.6.1.4.1.311.97.1.0" },
		"malformed profile": func(p *azureCMSExperimentalPolicy) { p.ProfileEKU = "1.3.6.1.5.5.7.3.3" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := policy
			change(&bad)
			if _, err := verifyAzureCMSExperimental(timestamped, bad); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

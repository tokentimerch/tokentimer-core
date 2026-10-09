// Package cmccore parses CA-signed CMC responses for the AD CS issuer path.
//
// This is a trust boundary: strict DER, 64 KiB bound, no trailing data, and
// the CMS signature must verify against a CA certificate whose public-key
// SHA-256 equals the enrollment snapshot's caKeySha256. See ADR-0014.
package cmccore

import "fmt"

// MaxResponseBytes is the hard upper bound on a CMC response body.
const MaxResponseBytes = 64 * 1024

// Result is the structured verdict the agent consumes as JSON.
type Result struct {
	Disposition string `json:"disposition"` // issued | pending | denied | unknown
	RequestID   *uint32 `json:"requestId,omitempty"`
	CertificateDerB64 string `json:"certificateDerB64,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Decode parses and verifies a CMC response. The caKeySHA256 hex string is
// the pin from the enrollment snapshot; responses signed by any other key
// must fail closed.
func Decode(response []byte, caKeySHA256 string) (Result, error) {
	if len(response) == 0 {
		return Result{}, fmt.Errorf("empty CMC response")
	}
	if len(response) > MaxResponseBytes {
		return Result{}, fmt.Errorf("CMC response exceeds %d bytes", MaxResponseBytes)
	}
	if caKeySHA256 == "" {
		return Result{}, fmt.Errorf("caKeySha256 is required")
	}
	// Implementation lands with the W4 spike: DER CMS SignedData, CMCStatusInfo,
	// pend token, issued-cert hash attribute, and signature check against the pin.
	return Result{}, fmt.Errorf("CMC decode not implemented yet")
}

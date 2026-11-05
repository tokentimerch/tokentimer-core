package revocation

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

type responseEnvelope struct {
	Status   asn1.Enumerated
	Response struct {
		Type asn1.ObjectIdentifier
		Body []byte
	} `asn1:"explicit,tag:0,optional"`
}
type responseCertID struct {
	Algorithm pkix.AlgorithmIdentifier
	NameHash  []byte
	KeyHash   []byte
	Serial    *big.Int
}
type revokedEntry struct {
	At     time.Time       `asn1:"generalized"`
	Reason asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}
type singleStatus struct {
	ID         responseCertID
	Good       asn1.Flag        `asn1:"tag:0,optional"`
	Revoked    revokedEntry     `asn1:"tag:1,optional"`
	Unknown    asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}
type signedResponse struct {
	Data struct {
		Raw        asn1.RawContent
		Version    int `asn1:"optional,default:0,explicit,tag:0"`
		Responder  asn1.RawValue
		ProducedAt time.Time `asn1:"generalized"`
		Responses  []singleStatus
	}
	Algorithm    pkix.AlgorithmIdentifier
	Signature    asn1.BitString
	Certificates []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// verifyIssuerBinding independently compares both issuer hashes from the
// signed response with an OCSP request derived from the actual issuer.
func verifyIssuerBinding(der []byte, leaf, issuer *x509.Certificate, parsed *ocsp.Response) error {
	var envelope responseEnvelope
	if rest, err := asn1.Unmarshal(der, &envelope); err != nil || len(rest) != 0 {
		return fmt.Errorf("invalid OCSP envelope")
	}
	var basic signedResponse
	if rest, err := asn1.Unmarshal(envelope.Response.Body, &basic); err != nil || len(rest) != 0 {
		return fmt.Errorf("invalid OCSP response data")
	}
	reqDER, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: parsed.IssuerHash})
	if err != nil {
		return err
	}
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return err
	}
	var match *responseCertID
	for i := range basic.Data.Responses {
		id := &basic.Data.Responses[i].ID
		if id.Serial != nil && id.Serial.Cmp(leaf.SerialNumber) == 0 {
			if match != nil {
				return fmt.Errorf("duplicate OCSP serial")
			}
			match = id
		}
	}
	if match == nil || !bytes.Equal(match.NameHash, req.IssuerNameHash) || !bytes.Equal(match.KeyHash, req.IssuerKeyHash) {
		return fmt.Errorf("OCSP issuer binding mismatch")
	}
	return nil
}

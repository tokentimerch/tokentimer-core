package revocation

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"
)

// CheckOCSP validates a signed response. The caller must establish CertID
// issuer's chain. The issuer name and key hashes are checked independently.
func CheckOCSP(der []byte, leaf, issuer *x509.Certificate, now time.Time, checkResponder func(*x509.Certificate) (string, time.Time)) (string, time.Time, error) {
	if leaf == nil || issuer == nil || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return "unknown", time.Time{}, fmt.Errorf("certificate or issuer binding unavailable")
	}
	resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err != nil {
		return "unknown", time.Time{}, err
	}
	if err := verifyIssuerBinding(der, leaf, issuer, resp); err != nil {
		return "unknown", time.Time{}, err
	}
	signer := issuer
	var responderUntil time.Time
	if resp.Certificate != nil {
		signer = resp.Certificate
	}
	if len(resp.RawResponderName) > 0 {
		if !bytes.Equal(resp.RawResponderName, signer.RawSubject) {
			return "unknown", time.Time{}, fmt.Errorf("OCSP responder identity mismatch")
		}
	} else {
		var info struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if rest, err := asn1.Unmarshal(signer.RawSubjectPublicKeyInfo, &info); err != nil || len(rest) != 0 {
			return "unknown", time.Time{}, fmt.Errorf("invalid OCSP responder key")
		}
		hash := sha1.Sum(info.PublicKey.RightAlign())
		if !bytes.Equal(resp.ResponderKeyHash, hash[:]) {
			return "unknown", time.Time{}, fmt.Errorf("OCSP responder identity mismatch")
		}
	}
	if resp.Certificate != nil {
		if now.Before(resp.Certificate.NotBefore) || !now.Before(resp.Certificate.NotAfter) {
			return "unknown", time.Time{}, fmt.Errorf("responder certificate not valid")
		}
		authorized := false
		for _, usage := range resp.Certificate.ExtKeyUsage {
			if usage == x509.ExtKeyUsageOCSPSigning {
				authorized = true
			}
		}
		if !authorized {
			return "unknown", time.Time{}, fmt.Errorf("responder lacks OCSP signing usage")
		}
		if resp.Certificate.KeyUsage != 0 && resp.Certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return "unknown", time.Time{}, fmt.Errorf("responder key usage forbids signatures")
		}
		// A delegated responder without id-pkix-ocsp-nocheck needs its own
		// revocation checked separately; do not recurse through OCSP.
		noCheck := false
		for _, ext := range resp.Certificate.Extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}) && !ext.Critical && bytes.Equal(ext.Value, []byte{0x05, 0x00}) {
				noCheck = true
			}
		}
		if !noCheck {
			if checkResponder == nil {
				return "unknown", time.Time{}, fmt.Errorf("delegated responder revocation not verified")
			}
			status, until := checkResponder(resp.Certificate)
			if status != "good" || until.IsZero() || !now.Before(until) {
				return "unknown", time.Time{}, fmt.Errorf("delegated responder revocation not verified")
			}
			responderUntil = until
		}
	}
	if resp.ThisUpdate.IsZero() || now.Before(resp.ThisUpdate) || resp.NextUpdate.IsZero() || !now.Before(resp.NextUpdate) || (!resp.ProducedAt.IsZero() && now.Before(resp.ProducedAt)) {
		return "unknown", resp.NextUpdate, fmt.Errorf("OCSP response is not fresh")
	}
	if !responderUntil.IsZero() && responderUntil.Before(resp.NextUpdate) {
		resp.NextUpdate = responderUntil
	}
	switch resp.Status {
	case ocsp.Good:
		return "good", resp.NextUpdate, nil
	case ocsp.Revoked:
		if resp.RevokedAt.IsZero() || resp.RevokedAt.After(now) {
			return "unknown", resp.NextUpdate, fmt.Errorf("invalid revocation time")
		}
		return "revoked", resp.NextUpdate, nil
	default:
		return "unknown", resp.NextUpdate, fmt.Errorf("responder returned unknown")
	}
}

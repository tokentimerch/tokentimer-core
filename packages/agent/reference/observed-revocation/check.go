package revocation

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"time"

	"golang.org/x/crypto/ocsp"
)

type ChainResult struct {
	Verdict    string
	CheckedAt  time.Time
	ValidUntil time.Time
	Detail     string
}

// CheckChain checks each non-root certificate on an already validated chain.
// Missing, invalid, unsupported or unauthorized revocation data stays unknown.
func CheckChain(ctx context.Context, chain []*x509.Certificate, allowedOrigins []string, tlsRoots []*x509.Certificate, now time.Time) ChainResult {
	return checkChain(ctx, chain, allowedOrigins, tlsRoots, now, FetchPublicStatus)
}

type statusFetcher func(context.Context, string, []string, []byte, []*x509.Certificate) ([]byte, error)

func checkChain(ctx context.Context, chain []*x509.Certificate, allowedOrigins []string, tlsRoots []*x509.Certificate, now time.Time, fetch statusFetcher) ChainResult {
	result := ChainResult{Verdict: "unknown", CheckedAt: now}
	if len(chain) < 2 || len(chain) > 10 || now.IsZero() {
		result.Detail = "validated chain unavailable"
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var expiry time.Time
	unknown := false
	for i := 0; i < len(chain)-1; i++ {
		cert, issuer := chain[i], chain[i+1]
		if cert == nil || issuer == nil {
			result.Detail = "chain certificate missing"
			return result
		}
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			result.Detail = "chain signature invalid"
			return result
		}
		verdict, until := checkCertificate(ctx, cert, issuer, allowedOrigins, tlsRoots, now, fetch)
		if verdict == "revoked" {
			if i == 0 {
				result.Verdict = "revoked"
			} else {
				result.Verdict = "issuer_revoked"
			}
			result.ValidUntil = until
			return result
		}
		if verdict != "good" {
			unknown = true
			continue
		}
		if expiry.IsZero() || until.Before(expiry) {
			expiry = until
		}
	}
	if unknown {
		result.Detail = "revocation data unavailable or unsupported"
		return result
	}
	result.Verdict = "good"
	result.ValidUntil = expiry
	return result
}

func checkCertificate(ctx context.Context, cert, issuer *x509.Certificate, allowed []string, tlsRoots []*x509.Certificate, now time.Time, fetch statusFetcher) (string, time.Time) {
	request, err := ocsp.CreateRequest(cert, issuer, nil)
	if err == nil {
		for i, endpoint := range cert.OCSPServer {
			if i >= 8 || ctx.Err() != nil {
				break
			}
			der, err := fetch(ctx, endpoint, allowed, request, tlsRoots)
			if err != nil {
				continue
			}
			verdict, until, err := CheckOCSP(der, cert, issuer, now, func(responder *x509.Certificate) (string, time.Time) {
				return checkCRL(ctx, responder, issuer, allowed, tlsRoots, now, fetch)
			})
			if err == nil && verdict != "unknown" {
				return verdict, until
			}
		}
	}
	return checkCRL(ctx, cert, issuer, allowed, tlsRoots, now, fetch)
}

func checkCRL(ctx context.Context, cert, issuer *x509.Certificate, allowed []string, tlsRoots []*x509.Certificate, now time.Time, fetch statusFetcher) (string, time.Time) {
	complete := fullCRLDistributionPoints(cert)
	for i, endpoint := range cert.CRLDistributionPoints {
		if i >= 8 || ctx.Err() != nil {
			break
		}
		der, err := fetch(ctx, endpoint, allowed, nil, tlsRoots)
		if err != nil {
			continue
		}
		verdict, until, err := checkBaseAndDelta(ctx, der, cert, issuer, allowed, tlsRoots, now, complete, fetch)
		if err == nil && verdict != "unknown" {
			return verdict, until
		}
	}
	return "unknown", time.Time{}
}

// Go exposes CRL URLs but not distribution-point reason masks or CRL issuers.
// A CRL can establish good only when every point uses the simple full-name
// form with no restricted reasons or alternate issuer. Unknown tags fail safe.
func fullCRLDistributionPoints(cert *x509.Certificate) bool {
	if cert == nil || len(cert.CRLDistributionPoints) == 0 {
		return false
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
			continue
		}
		var sequence asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &sequence); err != nil || len(rest) != 0 || sequence.Tag != asn1.TagSequence {
			return false
		}
		data := sequence.Bytes
		points := 0
		for len(data) > 0 {
			var point asn1.RawValue
			var err error
			data, err = asn1.Unmarshal(data, &point)
			if err != nil || point.Tag != asn1.TagSequence || !point.IsCompound {
				return false
			}
			fields := point.Bytes
			count := 0
			for len(fields) > 0 {
				var field asn1.RawValue
				fields, err = asn1.Unmarshal(fields, &field)
				if err != nil || field.Class != asn1.ClassContextSpecific || field.Tag != 0 || !field.IsCompound {
					return false
				}
				var name asn1.RawValue
				if rest, e := asn1.Unmarshal(field.Bytes, &name); e != nil || len(rest) != 0 || name.Class != asn1.ClassContextSpecific || name.Tag != 0 || !name.IsCompound {
					return false
				}
				count++
			}
			if count != 1 {
				return false
			}
			points++
		}
		return points > 0
	}
	return false
}

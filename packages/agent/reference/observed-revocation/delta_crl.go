package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

var freshestCRLOID = asn1.ObjectIdentifier{2, 5, 29, 46}
var deltaIndicatorOID = asn1.ObjectIdentifier{2, 5, 29, 27}

// deltaURLs accepts only unrestricted full-name distribution points. Relative
// names, reason masks and alternate CRL issuers require scope handling that
// this verifier deliberately does not implement.
func deltaURLs(extensions []pkix.Extension) ([]string, bool, error) {
	var urls []string
	found := false
	for _, ext := range extensions {
		if !ext.Id.Equal(freshestCRLOID) {
			continue
		}
		if found || ext.Critical {
			return nil, true, fmt.Errorf("invalid freshest CRL extension")
		}
		found = true
		var seq asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &seq); err != nil || len(rest) != 0 || seq.Tag != asn1.TagSequence || !seq.IsCompound {
			return nil, true, fmt.Errorf("invalid freshest CRL")
		}
		for data := seq.Bytes; len(data) > 0; {
			var point, field, name asn1.RawValue
			var err error
			data, err = asn1.Unmarshal(data, &point)
			if err != nil || point.Class != 0 || point.Tag != asn1.TagSequence || !point.IsCompound {
				return nil, true, fmt.Errorf("invalid freshest point")
			}
			rest, err := asn1.Unmarshal(point.Bytes, &field)
			if err != nil || len(rest) != 0 || field.Class != 2 || field.Tag != 0 || !field.IsCompound {
				return nil, true, fmt.Errorf("unsupported freshest scope")
			}
			rest, err = asn1.Unmarshal(field.Bytes, &name)
			if err != nil || len(rest) != 0 || name.Class != 2 || name.Tag != 0 || !name.IsCompound {
				return nil, true, fmt.Errorf("unsupported freshest name")
			}
			for names := name.Bytes; len(names) > 0; {
				var item asn1.RawValue
				names, err = asn1.Unmarshal(names, &item)
				if err != nil || item.Class != 2 || item.Tag != 6 || item.IsCompound {
					return nil, true, fmt.Errorf("unsupported freshest location")
				}
				u, err := url.Parse(string(item.Bytes))
				if err != nil || u.Scheme == "" || ((u.Scheme == "http" || u.Scheme == "https") && u.Hostname() == "") {
					return nil, true, fmt.Errorf("invalid freshest URL")
				}
				if u.Scheme == "http" || u.Scheme == "https" {
					urls = append(urls, u.String())
				}
			}
		}
	}
	if len(urls) > 8 {
		return nil, true, fmt.Errorf("too many delta locations")
	}
	return urls, found, nil
}

func validatedList(der []byte, issuer *x509.Certificate, now time.Time, delta bool) (*x509.RevocationList, *big.Int, error) {
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, nil, err
	}
	if issuer == nil || !bytes.Equal(list.RawIssuer, issuer.RawSubject) || list.CheckSignatureFrom(issuer) != nil {
		return nil, nil, fmt.Errorf("invalid CRL issuer or signature")
	}
	if list.NextUpdate.IsZero() || now.Before(list.ThisUpdate) || !now.Before(list.NextUpdate) || list.Number == nil || list.Number.Sign() < 0 {
		return nil, nil, fmt.Errorf("invalid CRL validity or number")
	}
	var baseNumber *big.Int
	for _, ext := range list.Extensions {
		switch {
		case ext.Id.Equal(deltaIndicatorOID):
			if !delta || !ext.Critical || baseNumber != nil {
				return nil, nil, fmt.Errorf("invalid delta indicator")
			}
			rest, e := asn1.Unmarshal(ext.Value, &baseNumber)
			if e != nil || len(rest) != 0 || baseNumber == nil || baseNumber.Sign() < 0 {
				return nil, nil, fmt.Errorf("invalid base CRL number")
			}
		case ext.Id.Equal(freshestCRLOID):
			if delta || ext.Critical {
				return nil, nil, fmt.Errorf("invalid freshest extension")
			}
		case ext.Id.String() == "2.5.29.28" || ext.Critical:
			return nil, nil, fmt.Errorf("unsupported CRL scope or critical extension")
		}
	}
	if delta && baseNumber == nil {
		return nil, nil, fmt.Errorf("missing delta indicator")
	}
	seen := make(map[string]bool)
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 || seen[entry.SerialNumber.String()] || (!delta && entry.ReasonCode == 8) {
			return nil, nil, fmt.Errorf("invalid CRL entry")
		}
		seen[entry.SerialNumber.String()] = true
		for _, ext := range entry.Extensions {
			if ext.Critical {
				return nil, nil, fmt.Errorf("unsupported critical entry extension")
			}
		}
	}
	return list, baseNumber, nil
}

func checkBaseAndDelta(ctx context.Context, der []byte, cert, issuer *x509.Certificate, allowed []string, tlsRoots []*x509.Certificate, now time.Time, complete bool, fetch statusFetcher) (string, time.Time, error) {
	if cert == nil || cert.SerialNumber == nil || !complete {
		return "unknown", time.Time{}, fmt.Errorf("CRL coverage unavailable")
	}
	base, _, err := validatedList(der, issuer, now, false)
	if err != nil {
		return "unknown", time.Time{}, err
	}
	certURLs, certHas, err := deltaURLs(cert.Extensions)
	if err != nil {
		return "unknown", time.Time{}, err
	}
	baseURLs, baseHas, err := deltaURLs(base.Extensions)
	if err != nil {
		return "unknown", time.Time{}, err
	}
	if !certHas && !baseHas {
		return CheckCRL(der, issuer, cert.SerialNumber, now, true)
	}
	urls := append(certURLs, baseURLs...)
	// All advertised HTTP(S) locations must agree. Never select a good result
	// while another advertised source is unavailable or gives another verdict.
	var selected string
	var expiry time.Time
	visited := make(map[string]bool)
	for _, endpoint := range urls {
		if visited[endpoint] {
			continue
		}
		visited[endpoint] = true
		data, err := fetch(ctx, endpoint, allowed, nil, tlsRoots)
		if err != nil {
			return "unknown", time.Time{}, err
		}
		delta, baseNumber, err := validatedList(data, issuer, now, true)
		if err != nil {
			return "unknown", time.Time{}, err
		}
		order := base.Number.Cmp(delta.Number)
		if base.Number.Cmp(baseNumber) < 0 || order > 0 || delta.ThisUpdate.Before(base.ThisUpdate) || (order == 0 && !delta.ThisUpdate.Equal(base.ThisUpdate)) || len(base.AuthorityKeyId) == 0 || !bytes.Equal(base.AuthorityKeyId, delta.AuthorityKeyId) {
			return "unknown", time.Time{}, fmt.Errorf("incompatible base and delta CRLs")
		}
		verdict := "good"
		baseReason := -1
		for _, entry := range base.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				if entry.RevocationTime.After(now) {
					return "unknown", time.Time{}, fmt.Errorf("future revocation entry")
				}
				verdict = "revoked"
				baseReason = entry.ReasonCode
			}
		}
		for _, entry := range delta.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				if entry.RevocationTime.After(now) {
					return "unknown", time.Time{}, fmt.Errorf("future delta entry")
				}
				// A simultaneously issued complete CRL already includes the
				// delta's changes; it is not a base to which they can be applied.
				if order == 0 {
					if (entry.ReasonCode == 8 && baseReason != -1) || (entry.ReasonCode != 8 && (baseReason == -1 || baseReason != entry.ReasonCode)) {
						return "unknown", time.Time{}, fmt.Errorf("simultaneous CRLs disagree")
					}
					continue
				}
				if entry.ReasonCode == 8 {
					if baseReason != -1 && baseReason != 6 {
						return "unknown", time.Time{}, fmt.Errorf("invalid removal of permanent revocation")
					}
					verdict = "good"
				} else {
					verdict = "revoked"
				}
			}
		}
		if selected != "" && selected != verdict {
			return "unknown", time.Time{}, fmt.Errorf("delta CRLs disagree")
		}
		selected = verdict
		until := delta.NextUpdate
		if base.NextUpdate.Before(until) {
			until = base.NextUpdate
		}
		if expiry.IsZero() || until.Before(expiry) {
			expiry = until
		}
	}
	if selected == "" {
		return "unknown", time.Time{}, fmt.Errorf("delta CRL unavailable")
	}
	return selected, expiry, nil
}

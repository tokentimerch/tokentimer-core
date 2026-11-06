package revocation

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

// CheckCRL accepts public material only. A missing/invalid/stale list cannot
// establish a good status. Callers must validate the issuer chain and establish
// that the CRL covers the certificate and all revocation reasons.
func CheckCRL(der []byte, issuer *x509.Certificate, serial *big.Int, now time.Time, coverageComplete bool) (string, time.Time, error) {
	if issuer == nil || serial == nil || serial.Sign() <= 0 || len(der) == 0 {
		return "unknown", time.Time{}, fmt.Errorf("missing public certificate or CRL")
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return "unknown", time.Time{}, err
	}
	if !bytes.Equal(list.RawIssuer, issuer.RawSubject) {
		return "unknown", time.Time{}, fmt.Errorf("CRL issuer mismatch")
	}
	if err = list.CheckSignatureFrom(issuer); err != nil {
		return "unknown", time.Time{}, err
	}
	if list.NextUpdate.IsZero() || now.Before(list.ThisUpdate) || !now.Before(list.NextUpdate) {
		return "unknown", list.NextUpdate, fmt.Errorf("CRL is not fresh")
	}
	// Delta and indirect CRLs need explicit processing; never treat them as complete.
	for _, ext := range list.Extensions {
		if ext.Critical || ext.Id.String() == "2.5.29.27" || ext.Id.String() == "2.5.29.28" || ext.Id.String() == "2.5.29.46" {
			return "unknown", list.NextUpdate, fmt.Errorf("unsupported CRL scope or critical extension")
		}
	}
	if !coverageComplete {
		return "unknown", list.NextUpdate, fmt.Errorf("CRL coverage not established")
	}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 || entry.ReasonCode == 8 {
			return "unknown", list.NextUpdate, fmt.Errorf("unsupported or invalid CRL entry")
		}
		for _, ext := range entry.Extensions {
			if ext.Critical {
				return "unknown", list.NextUpdate, fmt.Errorf("unsupported critical CRL entry extension")
			}
		}
		if entry.SerialNumber.Cmp(serial) == 0 && !entry.RevocationTime.After(now) {
			return "revoked", list.NextUpdate, nil
		}
	}
	return "good", list.NextUpdate, nil
}

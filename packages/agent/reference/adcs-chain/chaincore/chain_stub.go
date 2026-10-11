//go:build !windows

package chaincore

import "errors"

// Verify builds a certificate chain with revocation checking. The CryptoAPI
// path is Windows-only (ADR-0014 decision 6).
func Verify(leafDER []byte, caKeySha256 string, extraCerts [][]byte, revocationMode string) (Result, error) {
	_ = leafDER
	_ = caKeySha256
	_ = extraCerts
	_ = revocationMode
	return Result{Verdict: VerdictInvalid, Error: "tokentimer-adcs-chain: CryptoAPI chain validation is Windows-only"}, errors.New("windows only")
}

package chaincore

import "fmt"

// CryptoAPI trust-status bits used by decision 6 (numeric, non-localized).
const (
	CertTrustIsRevoked               = 0x00000004
	CertTrustRevocationStatusUnknown = 0x00000040
	CertTrustIsOfflineRevocation     = 0x01000000
)

// CertChainRevocationCheckChainExcludeRoot is the sole revocation flag
// CertGetCertificateChain may receive for this helper. Microsoft documents
// the CERT_CHAIN_REVOCATION_CHECK_* group as mutually exclusive; this flag
// checks the end certificate and intermediates while excluding the root.
const CertChainRevocationCheckChainExcludeRoot = 0x40000000

// RevocationUnavailableMask is the pair of trust bits that together mean
// CRL/OCSP status could not be obtained (ADR-0014 decision 6).
const RevocationUnavailableMask = CertTrustRevocationStatusUnknown | CertTrustIsOfflineRevocation

// Recognized CertVerifyCertificateChainPolicy errors that mean revocation
// status could not be obtained (not that the chain is otherwise untrusted).
const (
	CryptENoRevocationCheck  = 0x80092012
	CryptERevocationOffline  = 0x80092013
	CertERevocationFailure   = 0x800B010E
	CertEUntrustedRoot       = 0x800B0109 // unrelated; must never map to revocation_unknown
)

// IsRevocationUnavailablePolicyError reports whether dwError from
// CertVerifyCertificateChainPolicy is a revocation-unavailability condition.
func IsRevocationUnavailablePolicyError(policyError uint32) bool {
	switch policyError {
	case CryptENoRevocationCheck, CryptERevocationOffline, CertERevocationFailure:
		return true
	default:
		return false
	}
}

// MapChainTrust maps CryptoAPI trust-status and chain-policy error codes to a
// stable verdict. revocation_unknown requires that every non-zero trust bit is
// in RevocationUnavailableMask (both bits set) and that any nonzero policy
// error is an explicitly recognized revocation-unavailability code. Best-effort
// acceptance is applied by the JS caller; this function never treats an
// otherwise-broken chain (for example CERT_E_UNTRUSTEDROOT) as revocation-only.
func MapChainTrust(trustStatus, policyError uint32) Result {
	if trustStatus&CertTrustIsRevoked != 0 {
		return Result{
			Verdict:     VerdictInvalid,
			TrustStatus: trustStatus,
			Error:       "certificate is revoked",
		}
	}

	other := trustStatus &^ RevocationUnavailableMask
	if other != 0 {
		return Result{
			Verdict:     VerdictInvalid,
			TrustStatus: trustStatus,
			Error: fmt.Sprintf(
				"chain trust failed (trustStatus=0x%08x policyError=0x%08x)",
				trustStatus,
				policyError,
			),
		}
	}

	// Unrelated policy failures stay invalid even when revocation bits are set.
	if policyError != 0 && !IsRevocationUnavailablePolicyError(policyError) {
		return Result{
			Verdict:     VerdictInvalid,
			TrustStatus: trustStatus,
			Error: fmt.Sprintf(
				"chain policy failed (trustStatus=0x%08x policyError=0x%08x)",
				trustStatus,
				policyError,
			),
		}
	}

	revocationUnavailableBits := trustStatus&CertTrustRevocationStatusUnknown != 0 &&
		trustStatus&CertTrustIsOfflineRevocation != 0
	if revocationUnavailableBits || IsRevocationUnavailablePolicyError(policyError) {
		return Result{
			Verdict:     VerdictRevocationUnknown,
			TrustStatus: trustStatus,
			Error:       "revocation status unknown or offline",
		}
	}

	if policyError != 0 || trustStatus != 0 {
		return Result{
			Verdict:     VerdictInvalid,
			TrustStatus: trustStatus,
			Error: fmt.Sprintf(
				"chain policy failed (trustStatus=0x%08x policyError=0x%08x)",
				trustStatus,
				policyError,
			),
		}
	}

	return Result{Verdict: VerdictValid, TrustStatus: trustStatus}
}

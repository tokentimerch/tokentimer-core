package chaincore

import "testing"

func TestRevocationFlagIsSingleExcludeRoot(t *testing.T) {
	// Documented mutual exclusion: never OR with CERT_CHAIN_REVOCATION_CHECK_END_CERT (0x10000000).
	const endCert = uint32(0x10000000)
	if CertChainRevocationCheckChainExcludeRoot&endCert != 0 {
		t.Fatalf("exclude-root flag unexpectedly overlaps end-cert flag")
	}
	if CertChainRevocationCheckChainExcludeRoot != 0x40000000 {
		t.Fatalf("unexpected exclude-root flag: 0x%08x", CertChainRevocationCheckChainExcludeRoot)
	}
}

func TestMapChainTrustRevocationUnknownOnlyWhenExclusive(t *testing.T) {
	r := MapChainTrust(RevocationUnavailableMask, 0)
	if r.Verdict != VerdictRevocationUnknown {
		t.Fatalf("got %s, want revocation_unknown", r.Verdict)
	}

	// Mixed: revocation outage + partial chain / other trust failure.
	mixed := RevocationUnavailableMask | uint32(0x00000020) // CERT_TRUST_IS_PARTIAL_CHAIN
	r = MapChainTrust(mixed, 0)
	if r.Verdict != VerdictInvalid {
		t.Fatalf("mixed trust must be invalid, got %s", r.Verdict)
	}

	r = MapChainTrust(CertTrustIsRevoked|RevocationUnavailableMask, 0)
	if r.Verdict != VerdictInvalid {
		t.Fatalf("revoked must be invalid, got %s", r.Verdict)
	}

	r = MapChainTrust(0, 0)
	if r.Verdict != VerdictValid {
		t.Fatalf("clean chain must be valid, got %s", r.Verdict)
	}

	r = MapChainTrust(0, 0x800B0100)
	if r.Verdict != VerdictInvalid {
		t.Fatalf("policy error must be invalid, got %s", r.Verdict)
	}

	// Unknown without offline is not the ADR unavailable pair.
	r = MapChainTrust(CertTrustRevocationStatusUnknown, 0)
	if r.Verdict != VerdictInvalid {
		t.Fatalf("unknown without offline must be invalid, got %s", r.Verdict)
	}

	// Revocation-unavailable trust bits must not mask an untrusted-root policy error.
	r = MapChainTrust(RevocationUnavailableMask, CertEUntrustedRoot)
	if r.Verdict != VerdictInvalid {
		t.Fatalf("untrusted root with offline revocation must be invalid, got %s", r.Verdict)
	}

	r = MapChainTrust(0, CryptERevocationOffline)
	if r.Verdict != VerdictRevocationUnknown {
		t.Fatalf("revocation-offline policy alone must be revocation_unknown, got %s", r.Verdict)
	}
}

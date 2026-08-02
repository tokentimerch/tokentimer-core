package verifycore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// FuzzVerify exercises the entire parsing/verify surface of this package
// with adversarial inputs: an arbitrary PEM blob (which may or may not
// parse, may or may not be Ed25519), an arbitrary payload, and an
// arbitrary signature. This is the surface the ADR-0012 planning notes
// call out as the most fuzzable part of this milestone, because it is the
// one place a non-JavaScript client parses attacker-influenced bytes
// (a PEM-encoded key selection hint is trusted-local-config in production,
// but the parser itself must never panic on malformed input either way).
//
// The property under test is purely "never panic, never hang": ParseEd25519
// PublicKey and VerifyDetached must always return an error/false rather
// than crashing, for any byte sequence. Go's fuzzer will report any input
// that violates this via a panic, so there is no explicit assertion beyond
// calling both functions.
//
// Run with: go test -fuzz=FuzzVerify -fuzztime=60s ./verifycore
func FuzzVerify(f *testing.F) {
	validPub, validPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(validPub)
	if err != nil {
		f.Fatalf("x509.MarshalPKIXPublicKey: %v", err)
	}
	validPemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	validPayload := []byte(`{"jobId":"job-1","action":"protocol_smoke","nonce":"abcdefghijklmnop"}`)
	validSignature := ed25519.Sign(validPriv, validPayload)

	// Seed corpus: the fully-valid case, plus small structural mutations
	// that historically cause parser bugs (empty input, truncated PEM,
	// truncated signature, oversized signature, non-PEM garbage, a
	// deliberately-corrupted signature so the corpus also exercises the
	// "fails cleanly" path rather than only the "parses cleanly" path).
	f.Add(validPemBytes, validPayload, validSignature)
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(validPemBytes[:len(validPemBytes)/2], validPayload, validSignature)
	f.Add(validPemBytes, validPayload, validSignature[:32])
	f.Add(validPemBytes, validPayload, append(append([]byte{}, validSignature...), 0x00))
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\nnot base64!!\n-----END PUBLIC KEY-----\n"), validPayload, validSignature)
	f.Add([]byte("random garbage, not PEM at all"), []byte("random payload"), []byte("random signature"))
	corrupted := append([]byte{}, validSignature...)
	corrupted[0] ^= 0xFF
	f.Add(validPemBytes, validPayload, corrupted)

	f.Fuzz(func(t *testing.T, pemBytes, payload, signature []byte) {
		pub, parseErr := ParseEd25519PublicKey(pemBytes)
		if parseErr != nil {
			// A parse failure must leave pub unusable; there is nothing
			// further to check for this input, and reaching here without
			// panicking already satisfies the property under test.
			return
		}
		// A successful parse must always be a real Ed25519 key of the
		// correct length; VerifyDetached must not panic regardless of
		// payload/signature content or length.
		if len(pub) != ed25519.PublicKeySize {
			t.Fatalf("ParseEd25519PublicKey returned a key of length %d, want %d", len(pub), ed25519.PublicKeySize)
		}
		_ = VerifyDetached(pub, payload, signature)
	})
}

package verifycore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func generateEd25519PEM(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return pub, priv, string(pem.EncodeToMemory(block))
}

func generateRSAPEM(t *testing.T) string {
	t.Helper()
	// A fixed, small RSA public key is enough: this test only needs a
	// well-formed non-Ed25519 SubjectPublicKeyInfo, never a real trust
	// anchor. Generating one at test time keeps this file self-contained.
	priv := generateTestRSAKey(t)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey (RSA): %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func TestParseEd25519PublicKey_Valid(t *testing.T) {
	pub, _, pemStr := generateEd25519PEM(t)
	parsed, err := ParseEd25519PublicKey([]byte(pemStr))
	if err != nil {
		t.Fatalf("ParseEd25519PublicKey: unexpected error: %v", err)
	}
	if !parsed.Equal(pub) {
		t.Fatalf("parsed public key does not match the generated one")
	}
}

func TestParseEd25519PublicKey_RejectsRSA(t *testing.T) {
	pemStr := generateRSAPEM(t)
	_, err := ParseEd25519PublicKey([]byte(pemStr))
	if err == nil {
		t.Fatal("expected an error for a non-Ed25519 (RSA) public key, got nil")
	}
	if !strings.Contains(err.Error(), "not Ed25519") {
		t.Fatalf("expected a clear non-Ed25519 error, got: %v", err)
	}
}

func TestParseEd25519PublicKey_RejectsPrivateKeyBlock(t *testing.T) {
	_, priv, _ := generateEd25519PEM(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	_, err = ParseEd25519PublicKey(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected an error when given a PRIVATE KEY block, got nil")
	}
}

func TestParseEd25519PublicKey_RejectsGarbage(t *testing.T) {
	_, err := ParseEd25519PublicKey([]byte("this is not PEM at all"))
	if err == nil {
		t.Fatal("expected an error for non-PEM input, got nil")
	}
}

func TestParseEd25519PublicKey_RejectsTrailingData(t *testing.T) {
	_, _, pemStr := generateEd25519PEM(t)
	withTrailer := pemStr + "not part of any PEM block\n"
	_, err := ParseEd25519PublicKey([]byte(withTrailer))
	if err == nil {
		t.Fatal("expected an error for trailing data after the PEM block, got nil")
	}
}

func TestVerifyDetached_ValidSignaturePasses(t *testing.T) {
	pub, priv, _ := generateEd25519PEM(t)
	payload := []byte(`{"jobId":"job-1","action":"protocol_smoke"}`)
	sig := ed25519.Sign(priv, payload)
	if !VerifyDetached(pub, payload, sig) {
		t.Fatal("expected a valid signature to verify, got false")
	}
}

func TestVerifyDetached_TamperedPayloadFails(t *testing.T) {
	pub, priv, _ := generateEd25519PEM(t)
	payload := []byte(`{"jobId":"job-1","action":"protocol_smoke"}`)
	sig := ed25519.Sign(priv, payload)
	tampered := append([]byte{}, payload...)
	tampered[0] ^= 0xFF
	if VerifyDetached(pub, tampered, sig) {
		t.Fatal("expected a tampered payload to fail verification, got true")
	}
}

func TestVerifyDetached_TamperedSignatureFails(t *testing.T) {
	pub, priv, _ := generateEd25519PEM(t)
	payload := []byte(`{"jobId":"job-1","action":"protocol_smoke"}`)
	sig := ed25519.Sign(priv, payload)
	tampered := append([]byte{}, sig...)
	tampered[0] ^= 0xFF
	if VerifyDetached(pub, payload, tampered) {
		t.Fatal("expected a tampered signature to fail verification, got true")
	}
}

func TestVerifyDetached_WrongKeyFails(t *testing.T) {
	_, priv, _ := generateEd25519PEM(t)
	otherPub, _, _ := generateEd25519PEM(t)
	payload := []byte(`{"jobId":"job-1","action":"protocol_smoke"}`)
	sig := ed25519.Sign(priv, payload)
	if VerifyDetached(otherPub, payload, sig) {
		t.Fatal("expected verification under the wrong key to fail, got true")
	}
}

func TestVerifyDetached_WrongLengthSignatureFailsCleanly(t *testing.T) {
	pub, _, _ := generateEd25519PEM(t)
	payload := []byte("hello")
	if VerifyDetached(pub, payload, []byte("too short")) {
		t.Fatal("expected a malformed-length signature to fail, got true")
	}
}

func TestVerifyDetached_EmptyPayloadStillVerifiable(t *testing.T) {
	pub, priv, _ := generateEd25519PEM(t)
	sig := ed25519.Sign(priv, []byte{})
	if !VerifyDetached(pub, []byte{}, sig) {
		t.Fatal("expected a signature over an empty payload to verify, got false")
	}
}

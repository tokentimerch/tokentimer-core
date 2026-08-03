package verifycore

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// generateTestRSAKey isolates the RSA keygen call (test-only fixture
// generation for the "reject a well-formed non-Ed25519 key" case) so the
// main test file only imports crypto/rsa through this one helper.
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	// 2048 bits is the minimum RSA size Go's crypto/rsa accepts quickly and
	// without warnings; the key is never used for anything except proving
	// ParseEd25519PublicKey rejects it.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return priv
}

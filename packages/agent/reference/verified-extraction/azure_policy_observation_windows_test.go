//go:build windows

package verifiedextraction

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func observationCRL(t *testing.T, id testIdentity, revokedAt time.Time) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	list := &x509.RevocationList{Number: big.NewInt(8), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: revokedAt}}}
	der, err := x509.CreateRevocationList(rand.Reader, list, id.ca, id.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// This observation describes CryptoAPI's current treatment of the CRL date;
// it does not approve it as TokenTimer's eventual incident-response policy.
func TestAzureObserveRevocationRelativeToSigning(t *testing.T) {
	publisher := testIdentityCreate(t, false)
	tsa := testIdentityCreate(t, true)
	payload := []byte(`{"fixture":true}`)
	_, signature := testCMS(t, payload, testDataOID, publisher, nil, false)
	imprint := sha256.Sum256(signature)
	alg := testSeq(t, testOID(t, 2, 16, 840, 1, 101, 3, 4, 2, 1), []byte{5, 0})
	signingTime := time.Now().UTC().Truncate(time.Second).Add(-10 * time.Second)
	clock, err := asn1.MarshalWithParams(signingTime, "generalized")
	if err != nil {
		t.Fatal(err)
	}
	info := testSeq(t, testDER(t, 1), testOID(t, 1, 2, 3, 4), testSeq(t, alg, testDER(t, imprint[:])), testDER(t, 99), clock)
	token, _ := testCMS(t, info, testTSTOID, tsa, nil, true)
	cms, _ := testCMS(t, payload, testDataOID, publisher, token, false)
	pubHash := sha256.Sum256(publisher.root)
	tsaHash := sha256.Sum256(tsa.root)
	policy := azureCMSExperimentalPolicy{hex.EncodeToString(pubHash[:]), hex.EncodeToString(tsaHash[:]), "1.3.6.1.4.1.311.97.123.456.789"}
	tsaContext := testPrivateEngine(t, tsa.root, testCRL(t, tsa, false))
	pubContext := testPrivateEngine(t, publisher.root, testCRL(t, publisher, false))
	for _, tc := range []struct {
		name      string
		revokedAt time.Time
		reject    bool
	}{
		{"before signing", signingTime.Add(-time.Second), true},
		{"after signing", signingTime.Add(time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testPrivateEngine(t, publisher.root, observationCRL(t, publisher, tc.revokedAt))
			_, err := verifyAzureCMSExperimentalWithContexts(cms, policy, ctx, tsaContext)
			if (err != nil) != tc.reject {
				t.Fatalf("unexpected CryptoAPI revocation treatment: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name      string
		revokedAt time.Time
		reject    bool
	}{
		{"timestamp signer before signing", signingTime.Add(-time.Second), true},
		{"timestamp signer after signing", signingTime.Add(time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testPrivateEngine(t, tsa.root, observationCRL(t, tsa, tc.revokedAt))
			_, err := verifyAzureCMSExperimentalWithContexts(cms, policy, pubContext, ctx)
			if (err != nil) != tc.reject {
				t.Fatalf("unexpected timestamp signer revocation treatment: %v", err)
			}
		})
	}
}

func TestAzureVerifierInputLimits(t *testing.T) {
	for _, tc := range []struct {
		name             string
		token, signature []byte
	}{
		{"missing token", nil, []byte{1}}, {"missing signature", []byte{1}, nil},
		{"oversized token", make([]byte, (8<<20)+1), []byte{1}}, {"oversized signature", []byte{1}, make([]byte, (64<<10)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := verifyExperimentalTimestamp(tc.token, tc.signature); err == nil {
				t.Fatal("invalid native input accepted")
			}
		})
	}
	if _, err := experimentalDecodeCerts(make([]string, 101)); err == nil {
		t.Fatal("excess certificates accepted")
	}
	if _, err := experimentalDecodeCerts([]string{"not-base64!"}); err == nil {
		t.Fatal("malformed certificate encoding accepted")
	}
	if _, err := experimentalDecodeCerts([]string{strings.Repeat("A", (2 << 20))}); err == nil {
		t.Fatal("oversized certificate accepted")
	}
}

func TestAzureRejectsReusedOrWrongTimestamp(t *testing.T) {
	publisher := testIdentityCreate(t, false)
	tsa := testIdentityCreate(t, true)
	payload := []byte(`{"fixture":true}`)
	_, signature := testCMS(t, payload, testDataOID, publisher, nil, false)
	pubHash := sha256.Sum256(publisher.root)
	tsaHash := sha256.Sum256(tsa.root)
	policy := azureCMSExperimentalPolicy{hex.EncodeToString(pubHash[:]), hex.EncodeToString(tsaHash[:]), "1.3.6.1.4.1.311.97.123.456.789"}
	pubContext := testPrivateEngine(t, publisher.root, testCRL(t, publisher, false))
	tsaContext := testPrivateEngine(t, tsa.root, testCRL(t, tsa, false))
	clock, err := asn1.MarshalWithParams(time.Now().UTC().Truncate(time.Second), "generalized")
	if err != nil {
		t.Fatal(err)
	}
	makeToken := func(hash []byte, algorithm []byte, id testIdentity) []byte {
		info := testSeq(t, testDER(t, 1), testOID(t, 1, 2, 3, 4), testSeq(t, algorithm, testDER(t, hash)), testDER(t, 99), clock)
		token, _ := testCMS(t, info, testTSTOID, id, nil, true)
		return token
	}
	sha256Alg := testSeq(t, testOID(t, 2, 16, 840, 1, 101, 3, 4, 2, 1), []byte{5, 0})
	sha1Alg := testSeq(t, testOID(t, 1, 3, 14, 3, 2, 26), []byte{5, 0})
	wrong := sha256.Sum256([]byte("different signature"))
	weak := sha1.Sum(signature) // Negative fixture: SHA-1 is explicitly rejected.
	correct := sha256.Sum256(signature)
	for _, tc := range []struct {
		name  string
		token []byte
	}{
		{"timestamp for different signature", makeToken(wrong[:], sha256Alg, tsa)},
		{"weak timestamp digest", makeToken(weak[:], sha1Alg, tsa)},
		{"timestamp signed by wrong usage", makeToken(correct[:], sha256Alg, publisher)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cms, _ := testCMS(t, payload, testDataOID, publisher, tc.token, false)
			if _, err := verifyAzureCMSExperimentalWithContexts(cms, policy, pubContext, tsaContext); err == nil {
				t.Fatal("invalid timestamp accepted")
			}
		})
	}
}

//go:build windows && azurecmsqualify

package verifiedextraction

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"testing"
	"time"
)

func TestAzureManifestQualificationPrivatePKI(t *testing.T) {
	publisher := testIdentityCreate(t, false)
	tsa := testIdentityCreate(t, true)
	payload := []byte(`{"fixture":true}`)
	_, signature := testCMS(t, payload, testDataOID, publisher, nil, false)
	imprint := sha256.Sum256(signature)
	algorithm := testSeq(t, testOID(t, 2, 16, 840, 1, 101, 3, 4, 2, 1), []byte{5, 0})
	clock, err := asn1.MarshalWithParams(time.Now().UTC().Truncate(time.Second), "generalized")
	if err != nil {
		t.Fatal(err)
	}
	info := testSeq(t, testDER(t, 1), testOID(t, 1, 2, 3, 4), testSeq(t, algorithm, testDER(t, imprint[:])), testDER(t, 99), clock)
	token, _ := testCMS(t, info, testTSTOID, tsa, nil, true)
	cms, _ := testCMS(t, payload, testDataOID, publisher, token, false)
	pubHash := sha256.Sum256(publisher.root)
	tsaHash := sha256.Sum256(tsa.root)
	contentHash := sha256.Sum256(payload)
	policy := AzureCMSQualificationPolicy{hex.EncodeToString(pubHash[:]), hex.EncodeToString(tsaHash[:]), "1.3.6.1.4.1.311.97.123.456.789", hex.EncodeToString(contentHash[:])}
	pubContext := testPrivateEngine(t, publisher.root, testCRL(t, publisher, false))
	tsaContext := testPrivateEngine(t, tsa.root, testCRL(t, tsa, false))
	if err = qualifyAzureCMSWithContexts(cms, payload, policy, pubContext, tsaContext); err != nil {
		t.Fatalf("valid signed manifest: %v", err)
	}
	bad := policy
	bad.ProfileEKU = ""
	if err = qualifyAzureCMSWithContexts(cms, payload, bad, pubContext, tsaContext); err == nil {
		t.Fatal("missing independent policy accepted")
	}
	bad = policy
	bad.ExpectedManifestSHA256 = hex.EncodeToString(tsaHash[:])
	if err = qualifyAzureCMSWithContexts(cms, payload, bad, pubContext, tsaContext); err == nil {
		t.Fatal("wrong expected digest accepted")
	}
	different := []byte(`{"fixture":false}`)
	differentHash := sha256.Sum256(different)
	bad = policy
	bad.ExpectedManifestSHA256 = hex.EncodeToString(differentHash[:])
	if err = qualifyAzureCMSWithContexts(cms, different, bad, pubContext, tsaContext); err == nil {
		t.Fatal("different verified content accepted")
	}
	revoked := testPrivateEngine(t, publisher.root, testCRL(t, publisher, true))
	if err = qualifyAzureCMSWithContexts(cms, payload, policy, revoked, tsaContext); err == nil {
		t.Fatal("revoked publisher accepted")
	}
}

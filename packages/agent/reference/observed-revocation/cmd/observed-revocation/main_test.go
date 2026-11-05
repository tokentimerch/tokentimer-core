package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestMissingTrustIsUnknownNotInvalid(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(request{Leaf: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(bytes.NewReader(input), &out, now); err != nil {
		t.Fatal(err)
	}
	var result response
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "unknown" || result.ChainStatus != "unknown" || result.Detail != "trust anchors unavailable" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRejectsPrivateMaterialAndUnknownFields(t *testing.T) {
	if _, err := parseCertificate("-----BEGIN PRIVATE " + "KEY-----\nMAA=\n-----END PRIVATE " + "KEY-----\n"); err == nil {
		t.Fatal("accepted private material")
	}
	if err := run(bytes.NewBufferString(`{"unexpected":true}`), &bytes.Buffer{}, time.Now()); err == nil {
		t.Fatal("accepted unknown field")
	}
}

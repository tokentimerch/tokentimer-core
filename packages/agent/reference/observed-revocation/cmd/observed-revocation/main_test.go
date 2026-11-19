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

func TestUnsupportedSystemTrustDoesNotPoisonValidExplicitTrust(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	unsupportedDER := append([]byte(nil), rootDER...)
	serialOffset := bytes.Index(unsupportedDER, []byte{0x02, 0x01, 0x0a})
	if serialOffset < 0 {
		t.Fatal("fixture serial not found")
	}
	unsupportedDER[serialOffset+2] = 0x8a // Node/OpenSSL accepts this encoding; Go rejects a negative serial.
	if _, err := x509.ParseCertificate(unsupportedDER); err == nil {
		t.Fatal("unsupported system certificate unexpectedly parsed")
	}
	unsupportedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unsupportedDER}))
	tests := []struct {
		name          string
		req           request
		chain, detail string
	}{
		{"bad system root and intermediate", request{Leaf: leafPEM, Roots: []string{rootPEM}, SystemRoots: []string{unsupportedPEM}, SystemIntermediates: []string{unsupportedPEM}}, "valid", "revocation data unavailable or unsupported"},
		{"mixed system roots", request{Leaf: leafPEM, SystemRoots: []string{unsupportedPEM, rootPEM}}, "valid", "revocation data unavailable or unsupported"},
		{"bad explicit root", request{Leaf: leafPEM, Roots: []string{rootPEM, "unsupported"}}, "unknown", "invalid trust anchor"},
		{"bad explicit intermediate", request{Leaf: leafPEM, Roots: []string{rootPEM}, Intermediates: []string{"unsupported"}}, "unknown", "invalid intermediate"},
		{"only unsupported system root", request{Leaf: leafPEM, SystemRoots: []string{"unsupported"}}, "unknown", "trust anchors unavailable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input, err := json.Marshal(tc.req)
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
			if result.Verdict != "unknown" || result.ChainStatus != tc.chain || result.Detail != tc.detail {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

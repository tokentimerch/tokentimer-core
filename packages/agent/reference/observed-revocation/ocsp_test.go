package revocation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestOCSPRequiresSignedFreshBoundResponse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, SubjectKeyId: []byte{1, 2, 3}}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42)}
	otherTemplate := *tpl
	otherTemplate.Subject = pkix.Name{CommonName: "Other issuer using same key"}
	otherDER, err := x509.CreateCertificate(rand.Reader, &otherTemplate, &otherTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	otherIssuer, err := x509.ParseCertificate(otherDER)
	if err != nil {
		t.Fatal(err)
	}
	wrongIssuerResponse, err := ocsp.CreateResponse(otherIssuer, otherIssuer, ocsp.Response{Status: ocsp.Good, SerialNumber: leaf.SerialNumber, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := CheckOCSP(wrongIssuerResponse, leaf, issuer, now, nil); got != "unknown" {
		t.Fatalf("same-key wrong-name issuer accepted: %s", got)
	}
	for _, tc := range []struct {
		name   string
		status int
		want   string
	}{{"good", ocsp.Good, "good"}, {"revoked", ocsp.Revoked, "revoked"}, {"unknown", ocsp.Unknown, "unknown"}} {
		t.Run(tc.name, func(t *testing.T) {
			response := ocsp.Response{Status: tc.status, SerialNumber: leaf.SerialNumber, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), RevokedAt: now.Add(-time.Minute)}
			der, err := ocsp.CreateResponse(issuer, issuer, response, key)
			if err != nil {
				t.Fatal(err)
			}
			got, _, _ := CheckOCSP(der, leaf, issuer, now, nil)
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
			if got, _, _ := CheckOCSP(der, leaf, issuer, now.Add(2*time.Hour), nil); got != "unknown" {
				t.Fatalf("stale: %s", got)
			}
			der[len(der)-1] ^= 1
			if got, _, _ := CheckOCSP(der, leaf, issuer, now, nil); got != "unknown" {
				t.Fatalf("tampered: %s", got)
			}
		})
	}
}

func TestDelegatedOCSPResponderRequiresRevocationEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, SubjectKeyId: []byte{1}}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "OCSP signer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}
	makeResponse := func(noCheck bool) []byte {
		tpl := *signerTemplate
		if noCheck {
			tpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}}
		}
		certDER, e := x509.CreateCertificate(rand.Reader, &tpl, issuer, &signerKey.PublicKey, issuerKey)
		if e != nil {
			t.Fatal(e)
		}
		signer, e := x509.ParseCertificate(certDER)
		if e != nil {
			t.Fatal(e)
		}
		der, e := ocsp.CreateResponse(issuer, signer, ocsp.Response{Status: ocsp.Good, SerialNumber: big.NewInt(42), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), Certificate: signer}, signerKey)
		if e != nil {
			t.Fatal(e)
		}
		return der
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42)}
	der := makeResponse(false)
	if got, _, _ := CheckOCSP(der, leaf, issuer, now, nil); got != "unknown" {
		t.Fatal("unchecked delegated responder accepted")
	}
	if got, until, _ := CheckOCSP(der, leaf, issuer, now, func(*x509.Certificate) (string, time.Time) { return "good", now.Add(10 * time.Minute) }); got != "good" || !until.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("responder validity not bounded: %s %s", got, until)
	}
	if got, _, _ := CheckOCSP(der, leaf, issuer, now, func(*x509.Certificate) (string, time.Time) { return "revoked", now.Add(time.Minute) }); got != "unknown" {
		t.Fatal("revoked responder accepted")
	}
	if got, _, err := CheckOCSP(makeResponse(true), leaf, issuer, now, nil); got != "good" {
		t.Fatalf("no-check responder rejected: %s %v", got, err)
	}
}

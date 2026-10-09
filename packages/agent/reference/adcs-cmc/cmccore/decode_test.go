package cmccore

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.mozilla.org/pkcs7"
)

func TestDecodeRejectsEmptyAndOversized(t *testing.T) {
	if _, err := Decode(nil, "ab"); err == nil {
		t.Fatal("expected empty rejection")
	}
	big := make([]byte, MaxResponseBytes+1)
	if _, err := Decode(big, "ab"); err == nil {
		t.Fatal("expected oversized rejection")
	}
	if _, err := Decode([]byte{0x30, 0x00}, ""); err == nil {
		t.Fatal("expected missing pin rejection")
	}
}

func TestDecodePoCFixtures(t *testing.T) {
	pin := readFile(t, filepath.Join("..", "testdata", "ca-key-sha256.txt"))
	ca := mustParseCert(t, filepath.Join("..", "testdata", "ca.cer"))
	leaf := mustParseCert(t, filepath.Join("..", "testdata", "issued.cer"))

	issued := readFileBytes(t, filepath.Join("..", "testdata", "issued.rsp"))
	r, err := Decode(issued, string(pin), ca)
	if err != nil {
		t.Fatalf("issued: %v", err)
	}
	if r.Disposition != "issued" || r.CertificateDerB64 == "" {
		t.Fatalf("issued result: %+v", r)
	}

	// Nested 1.3.6.1.4.1.311.21.17 under 21.10.1 must be read and enforced.
	status, _, hash, err := parsePKIResponse(mustCMSContent(t, issued))
	if err != nil || status != cmcStatusSuccess || len(hash) != 20 {
		t.Fatalf("issued hash extract: status=%d hashLen=%d err=%v", status, len(hash), err)
	}
	sum := sha1.Sum(leaf.Raw)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), hex.EncodeToString(hash)) {
		t.Fatalf("extracted hash %x != leaf SHA-1 %x", hash, sum[:])
	}

	pending := readFileBytes(t, filepath.Join("..", "testdata", "pending.rsp"))
	r, err = Decode(pending, string(pin), ca)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if r.Disposition != "pending" || r.RequestID == nil || *r.RequestID != 5 {
		t.Fatalf("pending result: %+v", r)
	}

	denied := readFileBytes(t, filepath.Join("..", "testdata", "denied.rsp"))
	r, err = Decode(denied, string(pin), ca)
	if err != nil {
		t.Fatalf("denied: %v", err)
	}
	if r.Disposition != "denied" {
		t.Fatalf("denied result: %+v", r)
	}
}

func TestDecodeRejectsWrongPin(t *testing.T) {
	ca := mustParseCert(t, filepath.Join("..", "testdata", "ca.cer"))
	issued := readFileBytes(t, filepath.Join("..", "testdata", "issued.rsp"))
	wrong := "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := Decode(issued, wrong, ca); err == nil {
		t.Fatal("expected wrong-pin rejection")
	}
}

func TestDecodePendingRequiresCACert(t *testing.T) {
	pin := readFile(t, filepath.Join("..", "testdata", "ca-key-sha256.txt"))
	pending := readFileBytes(t, filepath.Join("..", "testdata", "pending.rsp"))
	if _, err := Decode(pending, string(pin)); err == nil {
		t.Fatal("expected pending without ca cert to fail")
	}
}

func TestSuccessResultPolicyUnknown(t *testing.T) {
	leaf := mustParseCert(t, filepath.Join("..", "testdata", "issued.cer"))
	sum := sha1.Sum(leaf.Raw)

	if r := successResult(nil, sum[:]); r.Disposition != "unknown" || r.Error == "" {
		t.Fatalf("missing leaf: %+v", r)
	}
	if r := successResult(leaf, nil); r.Disposition != "unknown" {
		t.Fatalf("missing hash: %+v", r)
	}
	wrong := append([]byte(nil), sum[:]...)
	wrong[0] ^= 0xff
	if r := successResult(leaf, wrong); r.Disposition != "unknown" {
		t.Fatalf("hash mismatch: %+v", r)
	}
	if r := successResult(leaf, sum[:]); r.Disposition != "issued" || r.CertificateDerB64 == "" {
		t.Fatalf("match: %+v", r)
	}
}

func mustCMSContent(t *testing.T, rsp []byte) []byte {
	t.Helper()
	der, err := normalizeDER(rsp)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	return sd.Content
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustParseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw := readFileBytes(t, path)
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	c, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

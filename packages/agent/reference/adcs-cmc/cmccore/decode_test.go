package cmccore

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
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

	issued := readFileBytes(t, filepath.Join("..", "testdata", "issued.rsp"))
	r, err := Decode(issued, string(pin), ca)
	if err != nil {
		t.Fatalf("issued: %v", err)
	}
	if r.Disposition != "issued" || r.CertificateDerB64 == "" {
		t.Fatalf("issued result: %+v", r)
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

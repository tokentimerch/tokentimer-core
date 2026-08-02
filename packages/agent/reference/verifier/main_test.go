package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeTempPEM(t *testing.T, dir string) (pemPath string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pemPath = filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pemPath, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile pem: %v", err)
	}
	return pemPath, priv
}

func TestRun_ValidSignatureExitsZero(t *testing.T) {
	dir := t.TempDir()
	pemPath, priv := writeTempPEM(t, dir)
	payload := []byte(`{"jobId":"job-1"}`)
	sig := ed25519.Sign(priv, payload)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	var stderr bytes.Buffer
	code := run(
		[]string{"--pubkey", pemPath, "--signature-b64", sigB64},
		bytes.NewReader(payload),
		&stderr,
	)
	if code != exitOK {
		t.Fatalf("expected exit code %d, got %d (stderr: %s)", exitOK, code, stderr.String())
	}
}

func TestRun_TamperedPayloadExitsVerifyFailed(t *testing.T) {
	dir := t.TempDir()
	pemPath, priv := writeTempPEM(t, dir)
	payload := []byte(`{"jobId":"job-1"}`)
	sig := ed25519.Sign(priv, payload)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	var stderr bytes.Buffer
	code := run(
		[]string{"--pubkey", pemPath, "--signature-b64", sigB64},
		bytes.NewReader([]byte(`{"jobId":"job-2"}`)),
		&stderr,
	)
	if code != exitVerifyFailed {
		t.Fatalf("expected exit code %d, got %d", exitVerifyFailed, code)
	}
}

func TestRun_NonEd25519KeyExitsUsageError(t *testing.T) {
	dir := t.TempDir()
	// A well-formed but non-PUBLIC-KEY PEM block (garbage type) is enough
	// to exercise the usage-error path without depending on RSA/x509
	// helpers from the verifycore test package.
	pemPath := filepath.Join(dir, "bad.pem")
	badPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a real cert")})
	if err := os.WriteFile(pemPath, badPem, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	sig := make([]byte, 64)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	var stderr bytes.Buffer
	code := run(
		[]string{"--pubkey", pemPath, "--signature-b64", sigB64},
		bytes.NewReader([]byte("payload")),
		&stderr,
	)
	if code != exitUsageError {
		t.Fatalf("expected exit code %d, got %d", exitUsageError, code)
	}
}

func TestRun_MissingPubkeyExitsUsageError(t *testing.T) {
	var stderr bytes.Buffer
	code := run(
		[]string{"--signature-b64", "AAAA"},
		bytes.NewReader([]byte("payload")),
		&stderr,
	)
	if code != exitUsageError {
		t.Fatalf("expected exit code %d, got %d", exitUsageError, code)
	}
}

func TestRun_BothSignatureFormsIsUsageError(t *testing.T) {
	dir := t.TempDir()
	pemPath, _ := writeTempPEM(t, dir)
	sigPath := filepath.Join(dir, "sig.bin")
	if err := os.WriteFile(sigPath, make([]byte, 64), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stderr bytes.Buffer
	code := run(
		[]string{"--pubkey", pemPath, "--signature", sigPath, "--signature-b64", "AAAA"},
		bytes.NewReader([]byte("payload")),
		&stderr,
	)
	if code != exitUsageError {
		t.Fatalf("expected exit code %d, got %d", exitUsageError, code)
	}
}

func TestRun_SignatureViaFileWorks(t *testing.T) {
	dir := t.TempDir()
	pemPath, priv := writeTempPEM(t, dir)
	payload := []byte("file-based signature path")
	sig := ed25519.Sign(priv, payload)
	sigPath := filepath.Join(dir, "sig.bin")
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stderr bytes.Buffer
	code := run(
		[]string{"--pubkey", pemPath, "--signature", sigPath},
		bytes.NewReader(payload),
		&stderr,
	)
	if code != exitOK {
		t.Fatalf("expected exit code %d, got %d (stderr: %s)", exitOK, code, stderr.String())
	}
}

func TestRun_PayloadViaFileWorks(t *testing.T) {
	dir := t.TempDir()
	pemPath, priv := writeTempPEM(t, dir)
	payload := []byte("payload from a file, not stdin")
	sig := ed25519.Sign(priv, payload)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	payloadPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stderr bytes.Buffer
	code := run(
		[]string{"--pubkey", pemPath, "--signature-b64", sigB64, "--payload", payloadPath},
		bytes.NewReader([]byte("ignored, since --payload was given")),
		&stderr,
	)
	if code != exitOK {
		t.Fatalf("expected exit code %d, got %d (stderr: %s)", exitOK, code, stderr.String())
	}
}

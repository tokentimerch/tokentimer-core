// Package verifycore implements exactly one step of the CertOps v2 envelope
// verification order documented in ADR-0012 (decision 2, step 5): given a
// pinned Ed25519 public key, a payload, and a detached signature, report
// whether the signature is valid for that payload under that key.
//
// This package intentionally does nothing else. It does not parse JSON, it
// does not check timestamps, it does not select an algorithm dynamically,
// and it does not canonicalize anything. The envelope's base64 decoding,
// canonical-base64 enforcement, JSON parsing, and every other step in the
// ADR's normative order happen in the calling script (tokentimer-protocol.ps1
// on the PowerShell side), never here. Keeping this surface minimal is what
// makes it fuzzable: the entire input space is "arbitrary PEM bytes,
// arbitrary signature bytes, arbitrary payload bytes", with no protocol
// semantics to model.
package verifycore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ErrNotEd25519 is returned when a parsed SubjectPublicKeyInfo key is a
// well-formed public key of some other algorithm (RSA, ECDSA, etc). This
// verifier rejects it with a clear error rather than silently accepting it
// or crashing: ADR-0012 decision 1 fixes the algorithm at Ed25519 (there is
// no unsigned "algorithm" field on the wire), so nothing on the wire may
// ever select a different verifier.
var ErrNotEd25519 = errors.New("tokentimer-verify: public key algorithm is not Ed25519")

// ParseEd25519PublicKey parses a single PEM block containing a
// SubjectPublicKeyInfo ("BEGIN PUBLIC KEY") and requires the encoded
// algorithm to be Ed25519. Any other PEM block type (for example a
// certificate, or a PRIVATE KEY block, which must never be accepted here in
// any case) or any other public-key algorithm is rejected.
//
// Trailing bytes after the single PEM block are rejected rather than
// silently ignored, so a file that concatenates a second block cannot
// smuggle anything past this parser.
func ParseEd25519PublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("tokentimer-verify: input does not contain a PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf(
			"tokentimer-verify: PEM block type is %q, want \"PUBLIC KEY\" (SubjectPublicKeyInfo)",
			block.Type,
		)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("tokentimer-verify: trailing data after the PEM block is not allowed")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tokentimer-verify: could not parse SubjectPublicKeyInfo: %w", err)
	}

	edKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w (got %T)", ErrNotEd25519, parsed)
	}
	if len(edKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"tokentimer-verify: Ed25519 public key has length %d, want %d",
			len(edKey), ed25519.PublicKeySize,
		)
	}
	return edKey, nil
}

// VerifyDetached reports whether signature is a valid Ed25519 signature by
// pub over the exact bytes of payload. It performs no interpretation of
// payload: the caller has already decided these are "the exact decoded
// bytes" per ADR-0012 decision 2, step 5.
//
// A malformed (wrong-length) signature is a verification failure, not a
// panic: crypto/ed25519.Verify already returns false for a signature that
// is not exactly ed25519.SignatureSize bytes, so this function never panics
// regardless of caller input.
func VerifyDetached(pub ed25519.PublicKey, payload, signature []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, payload, signature)
}

// Command tokentimer-verify is a minimal, verification-only Ed25519
// checker. It implements exactly step 5 of the ADR-0012 decision-2
// verification order: given a pinned SubjectPublicKeyInfo Ed25519 public
// key, a payload, and a detached signature, report a pass/fail verdict via
// exit code. Nothing else.
//
// It does not parse JSON, does not check timestamps, does not select an
// algorithm dynamically, and does not canonicalize anything. Every other
// step in the ADR's normative order (base64 decode, canonical-base64
// enforcement, UTF-8 decode, JSON parse, field checks, time window) is the
// calling script's responsibility (tokentimer-protocol.ps1), never this
// binary's.
//
// Usage:
//
//	tokentimer-verify --pubkey <pem-file> --signature-b64 <base64-string> [--payload <file>]
//	tokentimer-verify --pubkey <pem-file> --signature <raw-bytes-file> [--payload <file>]
//
// When --payload is omitted, the payload is read from stdin as a raw byte
// stream. This is the primary calling convention from tokentimer-protocol.ps1,
// which hands the decoded v2 envelope payload to this process through a
// byte-preserving binary stdin stream rather than the PowerShell text
// pipeline (ADR-0012 decision 8).
//
// The signature is exactly 64 raw bytes once decoded. Passing it as a
// base64 string on argv (--signature-b64) is safe because base64 text
// cannot contain a NUL byte or otherwise be mistaken for a second
// argument; passing it as a path to a raw-bytes file (--signature) is
// supported for scripts or tests that already have the decoded bytes on
// disk. Exactly one of the two must be given.
//
// Exit codes:
//
//	0  signature is valid for the given payload under the given key
//	1  signature verification failed (well-formed input, bad signature)
//	2  usage error: bad arguments, unreadable file, unparseable PEM,
//	   non-Ed25519 key, or malformed signature encoding/length
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

	"tokentimer-verify/verifycore"
)

const exitOK = 0
const exitVerifyFailed = 1
const exitUsageError = 2

func run(args []string, stdin io.Reader, stderr io.Writer) int {
	fs := flag.NewFlagSet("tokentimer-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	pubkeyPath := fs.String("pubkey", "", "path to a PEM SubjectPublicKeyInfo file (Ed25519 required)")
	payloadPath := fs.String("payload", "", "path to the payload bytes (default: read from stdin)")
	signaturePath := fs.String("signature", "", "path to the raw 64-byte decoded signature")
	signatureB64 := fs.String("signature-b64", "", "base64 encoding of the 64-byte decoded signature")

	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError already printed usage to stderr.
		return exitUsageError
	}

	if *pubkeyPath == "" {
		fmt.Fprintln(stderr, "tokentimer-verify: --pubkey is required")
		return exitUsageError
	}
	if (*signaturePath == "") == (*signatureB64 == "") {
		fmt.Fprintln(stderr, "tokentimer-verify: exactly one of --signature or --signature-b64 is required")
		return exitUsageError
	}

	pubkeyPem, err := os.ReadFile(*pubkeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "tokentimer-verify: could not read --pubkey: %v\n", err)
		return exitUsageError
	}

	pub, err := verifycore.ParseEd25519PublicKey(pubkeyPem)
	if err != nil {
		fmt.Fprintf(stderr, "tokentimer-verify: %v\n", err)
		return exitUsageError
	}

	var signature []byte
	if *signaturePath != "" {
		signature, err = os.ReadFile(*signaturePath)
		if err != nil {
			fmt.Fprintf(stderr, "tokentimer-verify: could not read --signature: %v\n", err)
			return exitUsageError
		}
	} else {
		signature, err = base64.StdEncoding.DecodeString(*signatureB64)
		if err != nil {
			fmt.Fprintf(stderr, "tokentimer-verify: --signature-b64 is not valid base64: %v\n", err)
			return exitUsageError
		}
	}
	if len(signature) != 64 {
		fmt.Fprintf(stderr, "tokentimer-verify: signature is %d bytes, want exactly 64\n", len(signature))
		return exitUsageError
	}

	var payload []byte
	if *payloadPath != "" {
		payload, err = os.ReadFile(*payloadPath)
	} else {
		payload, err = io.ReadAll(stdin)
	}
	if err != nil {
		fmt.Fprintf(stderr, "tokentimer-verify: could not read payload: %v\n", err)
		return exitUsageError
	}

	if verifycore.VerifyDetached(pub, payload, signature) {
		return exitOK
	}
	return exitVerifyFailed
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stderr))
}

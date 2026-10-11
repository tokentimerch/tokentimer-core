// Command tokentimer-adcs-chain validates an issued certificate chain with
// Windows CryptoAPI (ADR-0014 decision 6). The agent calls it with argv only
// (no shell), one process per check, and reads a single JSON object from stdout.
//
// Usage:
//
//	tokentimer-adcs-chain --cert <file> --ca-key-sha256 <hex> [--ca-cert <file>]
//	                      [--extra-store <file>] [--revocation require|best-effort]
//
// Exit codes:
//
//	0  verdict=valid
//	1  verdict=revocation_unknown (caller may defer)
//	2  verdict=invalid, ca_key_changed, or hard failure
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"tokentimer-adcs-chain/chaincore"
)

const exitOK = 0
const exitDeferred = 1
const exitFail = 2

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tokentimer-adcs-chain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	certPath := fs.String("cert", "", "path to the leaf certificate (PEM or DER)")
	caKey := fs.String("ca-key-sha256", "", "hex SHA-256 of the pinned CA public key")
	caCertPath := fs.String("ca-cert", "", "optional PEM/DER CA certificate added to the extra store")
	extraStore := fs.String("extra-store", "", "optional PEM/DER certificates for the extra store")
	revocation := fs.String("revocation", "require", "require or best-effort (best-effort is applied by the agent)")
	if err := fs.Parse(args); err != nil {
		return exitFail
	}
	if *certPath == "" || *caKey == "" {
		fmt.Fprintln(stderr, "usage: tokentimer-adcs-chain --cert <file> --ca-key-sha256 <hex> [--ca-cert <file>] [--extra-store <file>] [--revocation require|best-effort]")
		return exitFail
	}
	if *revocation != "require" && *revocation != "best-effort" {
		fmt.Fprintln(stderr, "--revocation must be require or best-effort")
		return exitFail
	}

	leaf, err := loadCertBytes(*certPath)
	if err != nil {
		_ = json.NewEncoder(stdout).Encode(chaincore.Result{Verdict: chaincore.VerdictInvalid, Error: err.Error()})
		return exitFail
	}
	var extras [][]byte
	for _, p := range []string{*caCertPath, *extraStore} {
		if p == "" {
			continue
		}
		certs, err := loadAllCerts(p)
		if err != nil {
			_ = json.NewEncoder(stdout).Encode(chaincore.Result{Verdict: chaincore.VerdictInvalid, Error: err.Error()})
			return exitFail
		}
		extras = append(extras, certs...)
	}

	result, err := chaincore.Verify(leaf, *caKey, extras, *revocation)
	if err != nil && result.Error == "" {
		result = chaincore.Result{Verdict: chaincore.VerdictInvalid, Error: err.Error()}
	}
	if encErr := json.NewEncoder(stdout).Encode(result); encErr != nil {
		fmt.Fprintf(stderr, "encode: %v\n", encErr)
		return exitFail
	}
	switch result.Verdict {
	case chaincore.VerdictValid:
		return exitOK
	case chaincore.VerdictRevocationUnknown:
		return exitDeferred
	default:
		return exitFail
	}
}

func loadCertBytes(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block type %q is not CERTIFICATE", block.Type)
		}
		return block.Bytes, nil
	}
	if _, err := x509.ParseCertificate(raw); err != nil {
		return nil, fmt.Errorf("certificate is neither PEM nor DER: %w", err)
	}
	return raw, nil
}

func loadAllCerts(path string) ([][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	rest := raw
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		out = append(out, block.Bytes)
	}
	if len(out) > 0 {
		return out, nil
	}
	if _, err := x509.ParseCertificate(raw); err != nil {
		return nil, fmt.Errorf("extra store is neither PEM certificates nor DER: %w", err)
	}
	return [][]byte{raw}, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// Command tokentimer-adcs-cmc decodes a CA-signed CMC response for the
// Windows AD CS enrollment path. The agent calls it with argv only (no
// shell) and reads a single JSON object from stdout.
//
// Usage:
//
//	tokentimer-adcs-cmc --response <file> --ca-key-sha256 <hex> [--ca-cert <file>]
//
// --ca-cert is required for pending/denied responses that name the signer by
// issuer/serial only (no certificate bag). Issued responses may embed the CA.
//
// Exit codes:
//
//	0  decoded successfully (disposition issued, pending, or denied)
//	1  response well-formed but disposition unknown / policy refuse
//	2  usage error or hard fail-closed parse/verify error
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"tokentimer-adcs-cmc/cmccore"
)

const exitOK = 0
const exitUnknown = 1
const exitFail = 2

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tokentimer-adcs-cmc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	responsePath := fs.String("response", "", "path to the CMC response bytes")
	caKey := fs.String("ca-key-sha256", "", "hex SHA-256 of the pinned CA public key")
	caCertPath := fs.String("ca-cert", "", "PEM/DER CA certificate for signature verify (required when the response omits the cert bag)")
	if err := fs.Parse(args); err != nil {
		return exitFail
	}
	if *responsePath == "" || *caKey == "" {
		fmt.Fprintln(stderr, "usage: tokentimer-adcs-cmc --response <file> --ca-key-sha256 <hex> [--ca-cert <file>]")
		return exitFail
	}
	raw, err := os.ReadFile(*responsePath)
	if err != nil {
		fmt.Fprintf(stderr, "read response: %v\n", err)
		return exitFail
	}
	var caCerts []*x509.Certificate
	if *caCertPath != "" {
		cert, err := loadCert(*caCertPath)
		if err != nil {
			fmt.Fprintf(stderr, "read ca-cert: %v\n", err)
			return exitFail
		}
		caCerts = append(caCerts, cert)
	}
	result, err := cmccore.Decode(raw, *caKey, caCerts...)
	if err != nil {
		// Hard fail-closed: parse/verify/usage-class errors (exit 2).
		_ = json.NewEncoder(stdout).Encode(cmccore.Result{Error: err.Error()})
		return exitFail
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return exitFail
	}
	// Policy refusals return disposition=unknown with err=nil (exit 1).
	if result.Disposition == "unknown" {
		return exitUnknown
	}
	return exitOK
}

func loadCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	return x509.ParseCertificate(raw)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

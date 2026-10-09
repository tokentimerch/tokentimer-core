// Command tokentimer-adcs-cmc decodes a CA-signed CMC response for the
// Windows AD CS enrollment path. The agent calls it with argv only (no
// shell) and reads a single JSON object from stdout.
//
// Usage:
//
//	tokentimer-adcs-cmc --response <file> --ca-key-sha256 <hex>
//
// Exit codes:
//
//	0  decoded successfully (disposition issued, pending, or denied)
//	1  response well-formed but disposition unknown / policy refuse
//	2  usage error or hard fail-closed parse/verify error
package main

import (
	"encoding/json"
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
	if err := fs.Parse(args); err != nil {
		return exitFail
	}
	if *responsePath == "" || *caKey == "" {
		fmt.Fprintln(stderr, "usage: tokentimer-adcs-cmc --response <file> --ca-key-sha256 <hex>")
		return exitFail
	}
	raw, err := os.ReadFile(*responsePath)
	if err != nil {
		fmt.Fprintf(stderr, "read response: %v\n", err)
		return exitFail
	}
	result, err := cmccore.Decode(raw, *caKey)
	if err != nil {
		_ = json.NewEncoder(stdout).Encode(cmccore.Result{Error: err.Error()})
		return exitFail
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return exitFail
	}
	if result.Disposition == "unknown" {
		return exitUnknown
	}
	return exitOK
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

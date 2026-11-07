//go:build windows && registrycredentialexperiment

package main

import (
	"fmt"
	"os"

	journal "tokentimer-verified-extraction"
)

func main() {
	if err := journal.RunExperimentalCredentialJournal(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		// Do not copy untrusted request data, native errors or credentials.
		fmt.Fprintln(os.Stderr, "credential journal request failed")
		os.Exit(1)
	}
}

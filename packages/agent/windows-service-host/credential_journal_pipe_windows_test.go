//go:build windows && credentialpipeexperiment && registrycredentialexperiment

package main

import (
	"strings"
	"testing"
)

func TestCredentialJournalFrameRejectsAmbiguousInputWithoutLeak(t *testing.T) {
	secret := "ttagent_" + strings.Repeat("1", 16) + "_" + strings.Repeat("2", 64)
	for _, input := range []string{
		`{"command":"read","command":"read"}`,
		`{"command":"read","record":{}}`,
		`{"command":"prepare"}`,
		`{"command":"prepare","record":"` + secret + `"} trailing`,
		`{"command":"read","extra":"` + secret + `"}`,
	} {
		result, err := handleCredentialJournalFrame([]byte(input))
		if err == nil || len(result) != 0 || strings.Contains(err.Error(), secret) {
			t.Fatal("invalid request accepted or exposed")
		}
	}
}

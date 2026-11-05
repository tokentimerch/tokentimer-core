//go:build windows && credentialpipeexperiment && registrycredentialexperiment

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	journal "tokentimer-verified-extraction"
)

// handleCredentialJournalFrame is experimental. Service startup does not wire
// it or send ACK; journal trust, process ownership and durable promotion need
// separate qualification before this can be used by an agent.
func handleCredentialJournalFrame(request []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(request))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("invalid journal frame")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		keyToken, err := d.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || (key != "command" && key != "record") {
			return nil, fmt.Errorf("invalid journal frame")
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate journal field")
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, fmt.Errorf("invalid journal frame")
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, fmt.Errorf("invalid journal frame")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("invalid journal frame")
	}
	var command string
	if json.Unmarshal(fields["command"], &command) != nil {
		return nil, fmt.Errorf("invalid journal frame")
	}
	var input io.Reader = bytes.NewReader(nil)
	switch command {
	case "prepare":
		if len(fields) != 2 || len(fields["record"]) == 0 {
			return nil, fmt.Errorf("invalid journal frame")
		}
		input = bytes.NewReader(fields["record"])
	case "read":
		if len(fields) != 1 {
			return nil, fmt.Errorf("invalid journal frame")
		}
	default:
		return nil, fmt.Errorf("invalid journal frame")
	}
	var output bytes.Buffer
	if err := journal.RunExperimentalCredentialJournal([]string{command}, input, &output); err != nil {
		return nil, fmt.Errorf("journal unavailable")
	}
	return output.Bytes(), nil
}

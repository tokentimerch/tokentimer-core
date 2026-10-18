// Package keyrefs inspects persisted certificate-provider metadata only. It never
// acquires private keys; incomplete inventory must prevent machine-key deletion.
package keyrefs

import (
	"regexp"
	"strings"
)

const MaxStores = 512
const MaxCertificates = 100000
const SoftwareKSP = "Microsoft Software Key Storage Provider"

type Request struct{ Container, ExcludeStore, ExcludeThumbprint string }
type Result struct {
	Complete            bool   `json:"complete"`
	Shared              bool   `json:"shared"`
	StoresScanned       int    `json:"storesScanned"`
	CertificatesScanned int    `json:"certificatesScanned"`
	Matches             int    `json:"matches"`
	Reason              string `json:"reason,omitempty"`
}

func (r Request) Valid() bool {
	if !regexp.MustCompile(`^tokentimer-[A-Za-z0-9_-]{1,118}$`).MatchString(r.Container) {
		return false
	}
	if r.ExcludeStore == "" && r.ExcludeThumbprint == "" {
		return true
	}
	return regexp.MustCompile(`^[A-Za-z0-9 _.-]{1,64}$`).MatchString(r.ExcludeStore) && r.ExcludeStore != "." && r.ExcludeStore != ".." && regexp.MustCompile(`^[A-Fa-f0-9]{40}$`).MatchString(r.ExcludeThumbprint)
}

// Conservative case folding retains ambiguous references without asserting
// provider-specific key-name case semantics. An extra retained key is safe.
func survivor(r Request, store, thumb, container, provider string, machine bool, provType uint32) bool {
	return machine && provType == 0 && strings.EqualFold(provider, SoftwareKSP) && strings.EqualFold(container, r.Container) && !(r.ExcludeStore != "" && strings.EqualFold(store, r.ExcludeStore) && strings.EqualFold(thumb, r.ExcludeThumbprint))
}
func incomplete(reason string, out Result) Result {
	out.Complete = false
	out.Shared = true
	out.Reason = reason
	return out
}

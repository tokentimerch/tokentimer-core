// Provider-reference identity tests exercise cross-store and machine-key scope
// without opening any key. A same-thumbprint mirror is a distinct survivor.
package keyrefs

import (
	"strings"
	"testing"
)

func TestSurvivorExactExclusionAndProviderScope(t *testing.T) {
	r := Request{"tokentimer-old-job-abcd1234", "My", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	if !r.Valid() {
		t.Fatal("valid request refused")
	}
	for _, tc := range []struct {
		name, store, thumb, container, provider string
		machine                                 bool
		provType                                uint32
		want                                    bool
	}{
		{"old exact", "my", r.ExcludeThumbprint, r.Container, SoftwareKSP, true, 0, false},
		{"same thumb other store", "WebHosting", r.ExcludeThumbprint, r.Container, SoftwareKSP, true, 0, true},
		{"different certificate same store", "My", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", r.Container, SoftwareKSP, true, 0, true},
		{"different container", "My", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "tokentimer-other", SoftwareKSP, true, 0, false},
		{"container case conservative", "WebHosting", r.ExcludeThumbprint, strings.ToUpper(r.Container), SoftwareKSP, true, 0, true},
		{"software provider case", "WebHosting", r.ExcludeThumbprint, r.Container, "microsoft software key storage provider", true, 0, true},
		{"hardware metadata only", "WebHosting", r.ExcludeThumbprint, r.Container, "Microsoft Platform Crypto Provider", true, 0, false},
		{"user scope", "WebHosting", r.ExcludeThumbprint, r.Container, SoftwareKSP, false, 0, false},
		{"legacy CSP", "WebHosting", r.ExcludeThumbprint, r.Container, SoftwareKSP, true, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := survivor(r, tc.store, tc.thumb, tc.container, tc.provider, tc.machine, tc.provType); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
func TestInvalidRequestsAndIncompleteAlwaysUnsafe(t *testing.T) {
	for _, r := range []Request{{"foreign", "My", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, {"tokentimer-owned", "..", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, {"tokentimer-owned", "My", "bad"}} {
		if r.Valid() {
			t.Fatal("invalid request accepted")
		}
	}
	result := incomplete("store_open_failed", Result{Complete: true, StoresScanned: 3, CertificatesScanned: 4})
	if result.Complete || !result.Shared || result.StoresScanned != 3 {
		t.Fatal("incomplete result became safe")
	}
}

// Without exclusions startup orphan cleanup must count every real reference,
// including a cert whose thumbprint/store would have been the retention target.
func TestGlobalReferenceModeAndPartialExclusionRefusal(t *testing.T) {
	r := Request{Container: "tokentimer-owned"}
	if !r.Valid() {
		t.Fatal("global request refused")
	}
	for _, store := range []string{"My", "WebHosting", "CustomStore"} {
		if !survivor(r, store, strings.Repeat("A", 40), r.Container, SoftwareKSP, true, 0) {
			t.Fatal("global reference excluded")
		}
	}
	for _, r := range []Request{{Container: r.Container, ExcludeStore: "My"}, {Container: r.Container, ExcludeThumbprint: strings.Repeat("A", 40)}} {
		if r.Valid() {
			t.Fatal("partial exclusion accepted")
		}
	}
}

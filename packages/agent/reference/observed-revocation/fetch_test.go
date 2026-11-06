package revocation

import (
	"context"
	"net/netip"
	"testing"
)

func TestResponderAddressPolicy(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "::ffff:169.254.169.254", "0.0.0.0", "224.0.0.1", "255.255.255.255"} {
		if safeResponderIP(netip.MustParseAddr(s)) {
			t.Errorf("accepted %s", s)
		}
	}
	for _, s := range []string{"10.1.2.3", "192.168.1.1", "fd00::1", "8.8.8.8"} {
		if !safeResponderIP(netip.MustParseAddr(s)) {
			t.Errorf("denied explicitly allowed PKI address %s", s)
		}
	}
}

func TestFetchRejectsUnapprovedDestinationsBeforeNetwork(t *testing.T) {
	for _, raw := range []string{"file:///etc/passwd", "http://user:pass@example.test/", "http://example.test/", "http://127.0.0.1/"} {
		if _, err := FetchPublicStatus(context.Background(), raw, nil, nil, nil); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

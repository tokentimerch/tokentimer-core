package revocation

import (
	"crypto/x509"
	"fmt"
	"time"
)

// VerifyChain builds a chain using explicitly supplied local trust anchors.
// It performs no network fetch and does not itself assert revocation status.
func VerifyChain(leaf *x509.Certificate, intermediates, roots []*x509.Certificate, now time.Time) ([][]*x509.Certificate, error) {
	if leaf == nil || len(roots) == 0 || now.IsZero() {
		return nil, fmt.Errorf("missing certificate, trust anchors, or verification time")
	}
	rootPool := x509.NewCertPool()
	intermediatePool := x509.NewCertPool()
	for _, root := range roots {
		if root == nil {
			return nil, fmt.Errorf("nil trust anchor")
		}
		rootPool.AddCert(root)
	}
	for _, intermediate := range intermediates {
		if intermediate == nil {
			return nil, fmt.Errorf("nil intermediate")
		}
		intermediatePool.AddCert(intermediate)
	}
	return leaf.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: intermediatePool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
}

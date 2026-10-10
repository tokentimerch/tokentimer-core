package chaincore

// Result is the JSON object written to stdout by tokentimer-adcs-chain.
type Result struct {
	Verdict     string `json:"verdict"`
	TrustStatus uint32 `json:"trustStatus,omitempty"`
	Error       string `json:"error,omitempty"`
}

const (
	VerdictValid             = "valid"
	VerdictInvalid           = "invalid"
	VerdictRevocationUnknown = "revocation_unknown"
	VerdictCAKeyChanged      = "ca_key_changed"
)

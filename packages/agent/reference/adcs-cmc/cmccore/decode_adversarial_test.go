package cmccore

import (
	"encoding/asn1"
	"path/filepath"
	"testing"
	"time"
)

func pendingInfo(t *testing.T, token []byte, timestamp any) []byte {
	t.Helper()
	first, err := asn1.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	var second []byte
	if date, ok := timestamp.(time.Time); ok {
		second, err = asn1.MarshalWithParams(date, "generalized")
	} else {
		second, err = asn1.Marshal(timestamp)
	}
	if err != nil {
		t.Fatal(err)
	}
	return append(first, second...)
}

func TestPendingTokenBoundariesAndMalformedTime(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for _, value := range []struct {
		name  string
		token []byte
		want  uint32
	}{
		{"minimum", []byte{1, 0, 0, 0}, 1},
		{"maximum-unsigned", []byte{255, 255, 255, 255}, 4294967295},
		{"little-endian", []byte{0, 1, 0, 0}, 256},
	} {
		t.Run(value.name, func(t *testing.T) {
			actual, err := parsePendToken(pendingInfo(t, value.token, now))
			if err != nil || actual != value.want {
				t.Fatalf("requestId=%d err=%v", actual, err)
			}
		})
	}
	for _, value := range []struct {
		name string
		body []byte
	}{
		{"zero-request-id", pendingInfo(t, []byte{0, 0, 0, 0}, now)},
		{"short-token", pendingInfo(t, []byte{1, 0, 0}, now)},
		{"long-token", pendingInfo(t, []byte{1, 0, 0, 0, 0}, now)},
		{"integer-time", pendingInfo(t, []byte{1, 0, 0, 0}, 42)},
		{"string-time", pendingInfo(t, []byte{1, 0, 0, 0}, "20261014000000Z")},
		{"utc-time-instead-of-generalized", pendingInfo(t, []byte{1, 0, 0, 0}, asn1.RawValue{Tag: asn1.TagUTCTime, Bytes: []byte("261014000000Z")})},
		{"invalid-calendar-time", pendingInfo(t, []byte{1, 0, 0, 0}, asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte("20261314000000Z")})},
		{"trailing-field", append(pendingInfo(t, []byte{1, 0, 0, 0}, now), 5, 0)},
	} {
		t.Run(value.name, func(t *testing.T) {
			if _, err := parsePendToken(value.body); err == nil {
				t.Fatal("malformed pending information accepted")
			}
		})
	}
}

func TestSignedResponseAdversarialEnvelopes(t *testing.T) {
	pin := readFile(t, filepath.Join("..", "testdata", "ca-key-sha256.txt"))
	ca := mustParseCert(t, filepath.Join("..", "testdata", "ca.cer"))
	for _, name := range []string{"issued", "pending", "denied"} {
		t.Run(name, func(t *testing.T) {
			raw := readFileBytes(t, filepath.Join("..", "testdata", name+".rsp"))
			der, err := normalizeDER(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(der, pin, ca); err != nil {
				t.Fatalf("signed positive control: %v", err)
			}
			corrupted := append([]byte(nil), der...)
			corrupted[len(corrupted)-1] ^= 1
			for _, body := range [][]byte{der[:len(der)-1], append(append([]byte(nil), der...), 5, 0), corrupted} {
				result, err := Decode(body, pin, ca)
				if err == nil || result.RequestID != nil || result.CertificateDerB64 != "" {
					t.Fatalf("adversarial signed response produced trusted facts: %+v err=%v", result, err)
				}
			}
		})
	}
}

func TestStatusInfoLocalizedTextAndExactFields(t *testing.T) {
	marshal := func(value any) []byte {
		raw, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	sequence := func(body []byte) []byte {
		return marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	}
	status := marshal(3)
	list := marshal([]int{1})
	pend := sequence(pendingInfo(t, []byte{5, 0, 0, 0}, time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)))
	for _, text := range []string{"Request pending", "Demande en attente", "Anforderung ausstehend"} {
		localized := marshal(asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(text)})
		body := sequence(append(append(append(append([]byte(nil), status...), list...), localized...), pend...))
		actual, id, err := parseCMCStatusInfo(body)
		if err != nil || actual != 3 || id == nil || *id != 5 {
			t.Fatalf("localized signed content fields: status=%d id=%v err=%v", actual, id, err)
		}
	}
	for _, value := range []struct {
		name string
		list []byte
		tail []byte
	}{
		{"integer-body-list", marshal(1), pend},
		{"empty-body-list", marshal([]int{}), pend},
		{"negative-body-id", marshal([]int{-1}), pend},
		{"overflow-body-id", marshal([]int64{4294967296}), pend},
		{"trailing-other-info", list, append(append([]byte(nil), pend...), 5, 0)},
		{"unknown-choice", list, marshal("unexpected")},
		{"malformed-failure-integer", list, []byte{2, 0}},
		{"invalid-utf8-text", list, append([]byte{12, 1, 255}, pend...)},
		{"context-specific-text", list, append([]byte{140, 1, 65}, pend...)},
	} {
		t.Run(value.name, func(t *testing.T) {
			body := sequence(append(append(append([]byte(nil), status...), value.list...), value.tail...))
			if _, _, err := parseCMCStatusInfo(body); err == nil {
				t.Fatal("malformed CMC status fields accepted")
			}
		})
	}
}

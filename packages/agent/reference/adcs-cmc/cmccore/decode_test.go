package cmccore

import "testing"

func TestDecodeRejectsEmptyAndOversized(t *testing.T) {
	if _, err := Decode(nil, "ab"); err == nil {
		t.Fatal("expected empty rejection")
	}
	big := make([]byte, MaxResponseBytes+1)
	if _, err := Decode(big, "ab"); err == nil {
		t.Fatal("expected oversized rejection")
	}
	if _, err := Decode([]byte{0x30, 0x00}, ""); err == nil {
		t.Fatal("expected missing pin rejection")
	}
}

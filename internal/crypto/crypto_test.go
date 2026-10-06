package crypto

import (
	"bytes"
	"testing"
)

// mkPair builds the dispatcher-side and runner-side Boxes for a fresh A/C pair.
func mkPair(t *testing.T) (aToC, cToA *Box) {
	t.Helper()
	a, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	c, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	aToC, err = NewBox(a.Private, c.Public) // A seals to C / opens from C
	if err != nil {
		t.Fatal(err)
	}
	cToA, err = NewBox(c.Private, a.Public) // C seals to A / opens from A
	if err != nil {
		t.Fatal(err)
	}
	return aToC, cToA
}

func TestSealOpenRoundTripBothDirections(t *testing.T) {
	aBox, cBox := mkPair(t)
	msg := []byte("fetch https://example.com")

	sealed, err := aBox.Seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cBox.Open(sealed)
	if err != nil {
		t.Fatalf("C could not open A's message: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("A->C mismatch: %q", got)
	}

	// Response direction.
	resp := []byte("200 OK body")
	sealed2, err := cBox.Seal(resp)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := aBox.Open(sealed2)
	if err != nil {
		t.Fatalf("A could not open C's response: %v", err)
	}
	if !bytes.Equal(got2, resp) {
		t.Fatalf("C->A mismatch: %q", got2)
	}
}

func TestOpenRejectsTamper(t *testing.T) {
	aBox, cBox := mkPair(t)
	sealed, _ := aBox.Seal([]byte("sensitive"))
	sealed[len(sealed)-1] ^= 0x01 // flip a ciphertext bit
	if _, err := cBox.Open(sealed); err == nil {
		t.Fatal("expected tamper to be rejected")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	aBox, _ := mkPair(t)
	_, stranger := mkPair(t) // unrelated keypair
	sealed, _ := aBox.Seal([]byte("sensitive"))
	if _, err := stranger.Open(sealed); err == nil {
		t.Fatal("expected wrong-key open to fail")
	}
}

func TestParseKeyRejectsBadInput(t *testing.T) {
	if _, err := NewBox("not-base64!!", "also-bad"); err == nil {
		t.Fatal("expected error on bad key material")
	}
}

package crypto

import (
	"bytes"
	"testing"
)

// mkIdentities builds a dispatcher (A) and runner (C) identity for a fresh pair.
func mkIdentities(t *testing.T) (a, c *Identity) {
	t.Helper()
	akp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ckp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	a, err = NewIdentity(akp.Private)
	if err != nil {
		t.Fatal(err)
	}
	c, err = NewIdentity(ckp.Private)
	if err != nil {
		t.Fatal(err)
	}
	return a, c
}

func TestDerivedPublicMatchesGenerated(t *testing.T) {
	kp, _ := GenerateKeypair()
	id, err := NewIdentity(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if id.PublicB64() != kp.Public {
		t.Fatalf("derived pub %q != generated %q", id.PublicB64(), kp.Public)
	}
}

func TestSealOpenRoundTripBothDirections(t *testing.T) {
	a, c := mkIdentities(t)

	sealed, err := a.SealTo(c.PublicB64(), []byte("fetch https://example.com"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.OpenFrom(a.PublicB64(), sealed)
	if err != nil {
		t.Fatalf("C could not open A's message: %v", err)
	}
	if string(got) != "fetch https://example.com" {
		t.Fatalf("A->C mismatch: %q", got)
	}

	sealed2, err := c.SealTo(a.PublicB64(), []byte("200 OK body"))
	if err != nil {
		t.Fatal(err)
	}
	got2, err := a.OpenFrom(c.PublicB64(), sealed2)
	if err != nil {
		t.Fatalf("A could not open C's response: %v", err)
	}
	if !bytes.Equal(got2, []byte("200 OK body")) {
		t.Fatalf("C->A mismatch: %q", got2)
	}
}

func TestOpenRejectsTamper(t *testing.T) {
	a, c := mkIdentities(t)
	sealed, _ := a.SealTo(c.PublicB64(), []byte("sensitive"))
	sealed[len(sealed)-1] ^= 0x01
	if _, err := c.OpenFrom(a.PublicB64(), sealed); err == nil {
		t.Fatal("expected tamper to be rejected")
	}
}

func TestOpenRejectsWrongSender(t *testing.T) {
	a, c := mkIdentities(t)
	_, stranger := mkIdentities(t)
	sealed, _ := a.SealTo(c.PublicB64(), []byte("sensitive"))
	// C tries to open claiming it came from the stranger, not A -> auth fails.
	if _, err := c.OpenFrom(stranger.PublicB64(), sealed); err == nil {
		t.Fatal("expected wrong-sender open to fail")
	}
}

func TestBadKeyMaterial(t *testing.T) {
	if _, err := NewIdentity("not-base64!!"); err == nil {
		t.Fatal("expected error on bad private key")
	}
	a, _ := mkIdentities(t)
	if _, err := a.SealTo("not-base64!!", []byte("x")); err == nil {
		t.Fatal("expected error on bad peer key")
	}
}

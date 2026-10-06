// Package crypto provides authenticated end-to-end encryption between a
// dispatcher (A) and a runner (C) using NaCl box (X25519 + XSalsa20-Poly1305).
//
// The queue (B) persists messages and can read them, so transport TLS is not
// enough: every envelope is sealed here and opened only by the peer. box is
// authenticated — opening also proves the message came from the holder of the
// expected key. B only ever holds {nonce||ciphertext}.
//
// Multi-tenant: an Identity holds this machine's private key and can seal to /
// open from ANY peer public key. A dispatcher seals to the runner's key; a
// runner (which may serve several authorized dispatchers) opens from and seals
// back to whichever sender's key the job named — see internal/runner.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	keySize   = 32
	nonceSize = 24
)

// Keypair holds base64-encoded X25519 keys for config/.env storage.
type Keypair struct {
	Public  string
	Private string
}

// GenerateKeypair creates a fresh X25519 keypair, base64-encoded.
func GenerateKeypair() (Keypair, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{
		Public:  base64.StdEncoding.EncodeToString(pub[:]),
		Private: base64.StdEncoding.EncodeToString(priv[:]),
	}, nil
}

func parseKey(b64 string) (*[keySize]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode key: %w", err)
	}
	if len(raw) != keySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", keySize, len(raw))
	}
	var k [keySize]byte
	copy(k[:], raw)
	return &k, nil
}

// Identity is this machine's keypair. It seals to / opens from a peer identified
// by their base64 public key.
type Identity struct {
	priv [keySize]byte
	pub  [keySize]byte
}

// NewIdentity builds an Identity from this machine's base64 private key,
// deriving the matching public key.
func NewIdentity(selfPrivB64 string) (*Identity, error) {
	priv, err := parseKey(selfPrivB64)
	if err != nil {
		return nil, fmt.Errorf("self private key: %w", err)
	}
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive public key: %w", err)
	}
	id := &Identity{priv: *priv}
	copy(id.pub[:], pubBytes)
	return id, nil
}

// PublicB64 is this identity's public key, base64-encoded. It is what a
// dispatcher advertises as its "sender" and what a runner lists in its
// allowlist.
func (id *Identity) PublicB64() string {
	return base64.StdEncoding.EncodeToString(id.pub[:])
}

// SealTo encrypts and authenticates plaintext for the peer, returning
// nonce||ciphertext.
func (id *Identity) SealTo(peerPubB64 string, plaintext []byte) ([]byte, error) {
	peer, err := parseKey(peerPubB64)
	if err != nil {
		return nil, fmt.Errorf("peer public key: %w", err)
	}
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return box.Seal(nonce[:], plaintext, &nonce, peer, &id.priv), nil
}

// OpenFrom verifies and decrypts a nonce||ciphertext produced by the peer's
// SealTo. A tampered message, or one not sealed by the holder of peerPub's
// private key, fails with an error (no partial plaintext).
func (id *Identity) OpenFrom(peerPubB64 string, sealed []byte) ([]byte, error) {
	peer, err := parseKey(peerPubB64)
	if err != nil {
		return nil, fmt.Errorf("peer public key: %w", err)
	}
	if len(sealed) < nonceSize {
		return nil, fmt.Errorf("crypto: sealed message too short")
	}
	var nonce [nonceSize]byte
	copy(nonce[:], sealed[:nonceSize])
	out, ok := box.Open(nil, sealed[nonceSize:], &nonce, peer, &id.priv)
	if !ok {
		return nil, fmt.Errorf("crypto: open failed (tampered, truncated, or wrong key)")
	}
	return out, nil
}

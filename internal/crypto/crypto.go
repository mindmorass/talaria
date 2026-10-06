// Package crypto provides authenticated end-to-end encryption between the
// dispatcher (A) and runner (C) using NaCl box (X25519 + XSalsa20-Poly1305).
//
// The queue (B) persists messages and can read them, so transport TLS is not
// enough: every envelope is sealed here before publishing and opened only by the
// peer. box is authenticated, so the opener also verifies the message came from
// the expected peer. B only ever holds {nonce||ciphertext} and cannot read or
// forge it.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

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

// Box seals to / opens from a single peer. Because NaCl box derives a symmetric
// shared secret from (selfPriv, peerPub), one Box both seals outbound and opens
// inbound for that peer. The dispatcher holds Box{A_priv, C_pub}; the runner
// holds Box{C_priv, A_pub}; they interoperate in both directions.
type Box struct {
	peerPub  *[keySize]byte
	selfPriv *[keySize]byte
}

// NewBox builds a Box from this machine's base64 private key and the peer's
// base64 public key.
func NewBox(selfPrivB64, peerPubB64 string) (*Box, error) {
	priv, err := parseKey(selfPrivB64)
	if err != nil {
		return nil, fmt.Errorf("self private key: %w", err)
	}
	pub, err := parseKey(peerPubB64)
	if err != nil {
		return nil, fmt.Errorf("peer public key: %w", err)
	}
	return &Box{peerPub: pub, selfPriv: priv}, nil
}

// Seal encrypts and authenticates plaintext for the peer, returning
// nonce||ciphertext.
func (b *Box) Seal(plaintext []byte) ([]byte, error) {
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	// Prepend the nonce so Open can recover it; box.Seal appends ciphertext.
	return box.Seal(nonce[:], plaintext, &nonce, b.peerPub, b.selfPriv), nil
}

// Open verifies and decrypts a nonce||ciphertext produced by the peer's Seal.
// A tampered message or wrong key fails with an error (no partial plaintext).
func (b *Box) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < nonceSize {
		return nil, fmt.Errorf("crypto: sealed message too short")
	}
	var nonce [nonceSize]byte
	copy(nonce[:], sealed[:nonceSize])
	out, ok := box.Open(nil, sealed[nonceSize:], &nonce, b.peerPub, b.selfPriv)
	if !ok {
		return nil, fmt.Errorf("crypto: open failed (tampered, truncated, or wrong key)")
	}
	return out, nil
}

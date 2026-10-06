// Package natsauth mints the NATS *decentralized* JWT credential chain used for
// multi-tenant auth: Operator -> Account -> User, each signed by an Ed25519
// nkey. This is NATS's own authorization model (subject permissions + JetStream
// limits in the claims), verified offline by the server — NOT an external OIDC
// IdP. One account per tenant gives hard, server-enforced isolation plus
// per-account JetStream quotas.
package natsauth

import (
	"fmt"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// Operator is the root of trust. Persist Seed on B's admin host; put JWT in the
// server's `operator:` setting.
type Operator struct {
	PublicKey string
	Seed      []byte
	JWT       string
	kp        nkeys.KeyPair
}

// Account is one tenant. Its JWT goes into the server's account resolver; Seed
// is kept by the provisioner to sign that tenant's users.
type Account struct {
	Name      string
	PublicKey string
	Seed      []byte
	JWT       string
	kp        nkeys.KeyPair
}

// User is one role credential (dispatcher or runner). Creds is the ready-to-use
// .creds file contents.
type User struct {
	Name      string
	PublicKey string
	Seed      []byte
	JWT       string
	Creds     []byte
}

// JSLimits bounds a tenant account's JetStream usage. -1 means unlimited.
type JSLimits struct {
	DiskBytes int64
	MemBytes  int64
	Streams   int64
	Consumers int64
}

// DefaultJSLimits is a sane per-tenant default.
func DefaultJSLimits() JSLimits {
	return JSLimits{DiskBytes: 1 << 30, MemBytes: 256 << 20, Streams: 16, Consumers: 128}
}

// GenerateOperator creates a fresh operator (self-signed JWT).
func GenerateOperator(name string) (*Operator, error) {
	kp, err := nkeys.CreateOperator()
	if err != nil {
		return nil, err
	}
	return encodeOperator(kp, name)
}

// LoadOperator reconstructs an operator from its seed so it can sign new
// accounts across onboarding runs.
func LoadOperator(seed []byte, name string) (*Operator, error) {
	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("operator seed: %w", err)
	}
	return encodeOperator(kp, name)
}

func encodeOperator(kp nkeys.KeyPair, name string) (*Operator, error) {
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, err
	}
	seed, err := kp.Seed()
	if err != nil {
		return nil, err
	}
	oc := jwt.NewOperatorClaims(pub)
	oc.Name = name
	tok, err := oc.Encode(kp)
	if err != nil {
		return nil, fmt.Errorf("encode operator jwt: %w", err)
	}
	return &Operator{PublicKey: pub, Seed: seed, JWT: tok, kp: kp}, nil
}

// GenerateAccount creates a tenant account signed by the operator, with
// JetStream enabled to the given limits.
func GenerateAccount(op *Operator, name string, lim JSLimits) (*Account, error) {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		return nil, err
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, err
	}
	seed, err := kp.Seed()
	if err != nil {
		return nil, err
	}
	ac := jwt.NewAccountClaims(pub)
	ac.Name = name
	ac.Limits.JetStreamLimits.DiskStorage = lim.DiskBytes
	ac.Limits.JetStreamLimits.MemoryStorage = lim.MemBytes
	ac.Limits.JetStreamLimits.Streams = lim.Streams
	ac.Limits.JetStreamLimits.Consumer = lim.Consumers
	tok, err := ac.Encode(op.kp) // signed by operator
	if err != nil {
		return nil, fmt.Errorf("encode account jwt: %w", err)
	}
	return &Account{Name: name, PublicKey: pub, Seed: seed, JWT: tok, kp: kp}, nil
}

// LoadAccount reconstructs an account from its seed to sign more users later.
func LoadAccount(seed []byte, name string) (*Account, error) {
	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("account seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, err
	}
	return &Account{Name: name, PublicKey: pub, Seed: seed, kp: kp}, nil
}

// GenerateUser creates a user signed by the account, limited to the given
// publish/subscribe subjects.
func GenerateUser(acc *Account, name string, pubAllow, subAllow []string) (*User, error) {
	kp, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, err
	}
	seed, err := kp.Seed()
	if err != nil {
		return nil, err
	}
	uc := jwt.NewUserClaims(pub)
	uc.Name = name
	uc.IssuerAccount = acc.PublicKey
	uc.Permissions.Pub.Allow = pubAllow
	uc.Permissions.Sub.Allow = subAllow
	tok, err := uc.Encode(acc.kp) // signed by account
	if err != nil {
		return nil, fmt.Errorf("encode user jwt: %w", err)
	}
	creds, err := jwt.FormatUserConfig(tok, seed)
	if err != nil {
		return nil, fmt.Errorf("format creds: %w", err)
	}
	return &User{Name: name, PublicKey: pub, Seed: seed, JWT: tok, Creds: creds}, nil
}

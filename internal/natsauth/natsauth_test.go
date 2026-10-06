package natsauth

import (
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
)

func TestChainAndPermissions(t *testing.T) {
	op, err := GenerateOperator("talaria")
	if err != nil {
		t.Fatal(err)
	}
	acc, err := GenerateAccount(op, "alice_work", DefaultJSLimits())
	if err != nil {
		t.Fatal(err)
	}
	pubAllow := []string{"fetch.alice.work.jobs", "$JS.API.>"}
	subAllow := []string{"fetch.alice.work.responses.>", "_INBOX.>"}
	u, err := GenerateUser(acc, "dispatcher", pubAllow, subAllow)
	if err != nil {
		t.Fatal(err)
	}

	// Decode verifies each token's embedded signature.
	oc, err := jwt.DecodeOperatorClaims(op.JWT)
	if err != nil {
		t.Fatalf("operator jwt invalid: %v", err)
	}
	ac, err := jwt.DecodeAccountClaims(acc.JWT)
	if err != nil {
		t.Fatalf("account jwt invalid: %v", err)
	}
	uc, err := jwt.DecodeUserClaims(u.JWT)
	if err != nil {
		t.Fatalf("user jwt invalid: %v", err)
	}

	// Chain: account issued by operator; user issued by account.
	if oc.Subject != op.PublicKey {
		t.Fatalf("operator subject mismatch")
	}
	if ac.Issuer != op.PublicKey {
		t.Fatalf("account not issued by operator: issuer=%s op=%s", ac.Issuer, op.PublicKey)
	}
	if uc.Issuer != acc.PublicKey || uc.IssuerAccount != acc.PublicKey {
		t.Fatalf("user not issued by account: issuer=%s acc=%s", uc.Issuer, acc.PublicKey)
	}

	// JetStream enabled with our limits.
	if ac.Limits.JetStreamLimits.DiskStorage != DefaultJSLimits().DiskBytes {
		t.Fatalf("JS disk limit not set: %+v", ac.Limits.JetStreamLimits)
	}

	// Permissions carried through.
	if !containsAll(uc.Permissions.Pub.Allow, pubAllow) {
		t.Fatalf("pub allow missing: %v", uc.Permissions.Pub.Allow)
	}
	if !containsAll(uc.Permissions.Sub.Allow, subAllow) {
		t.Fatalf("sub allow missing: %v", uc.Permissions.Sub.Allow)
	}

	// Creds file is usable shape.
	if !strings.Contains(string(u.Creds), "BEGIN NATS USER JWT") || !strings.Contains(string(u.Creds), "BEGIN USER NKEY SEED") {
		t.Fatalf("creds file malformed")
	}
}

func TestTamperedAccountRejected(t *testing.T) {
	op, _ := GenerateOperator("talaria")
	acc, _ := GenerateAccount(op, "x", DefaultJSLimits())
	bad := acc.JWT[:len(acc.JWT)-4] + "AAAA"
	if _, err := jwt.DecodeAccountClaims(bad); err == nil {
		t.Fatal("expected tampered account jwt to be rejected")
	}
}

func TestLoadOperatorRoundTrip(t *testing.T) {
	op, _ := GenerateOperator("talaria")
	op2, err := LoadOperator(op.Seed, "talaria")
	if err != nil {
		t.Fatal(err)
	}
	if op2.PublicKey != op.PublicKey {
		t.Fatalf("reloaded operator pub mismatch")
	}
	// An account signed by the reloaded operator still chains to the same pub.
	acc, err := GenerateAccount(op2, "y", DefaultJSLimits())
	if err != nil {
		t.Fatal(err)
	}
	ac, _ := jwt.DecodeAccountClaims(acc.JWT)
	if ac.Issuer != op.PublicKey {
		t.Fatal("reloaded operator produced wrong issuer")
	}
}

func containsAll(have []string, want []string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

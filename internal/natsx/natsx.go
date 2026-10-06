// Package natsx holds the shared NATS/JetStream wiring used by both roles:
// connecting (TLS/wss only in production), declaring the JOBS and RESPONSES
// streams, scoped subject construction, and configuration from the environment.
//
// Multi-tenant: traffic is namespaced by profile (one NATS account per profile).
// Subjects are fetch.<profile>.jobs and fetch.<profile>.responses.<id>. Each
// runner binds a per-profile consumer.
package natsx

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	StreamJobs      = "TALARIA_JOBS"
	StreamResponses = "TALARIA_RESP"

	// Wildcard subjects the shared streams capture.
	SubjectJobsWildcard = "fetch.*.jobs"
	SubjectRespWildcard = "fetch.*.responses.>"

	// HeaderSender carries the dispatcher's base64 public key in cleartext so the
	// runner can select the opening key before decrypting. It is authenticated
	// by the seal (a forged value just makes box.Open fail).
	HeaderSender = "Talaria-Sender"
)

// Scope namespaces all traffic for one tenant, identified by its profile name
// (which is also the NATS account name).
type Scope struct {
	Profile string
}

// token characters allowed in a scope segment (must be NATS-subject- and
// durable-name-safe: no '.', '*', '>', or whitespace).
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// Validate ensures the profile is safe to embed in subjects/durables.
func (s Scope) Validate() error {
	if !validToken(s.Profile) {
		return fmt.Errorf("scope: invalid profile %q (use [A-Za-z0-9_-])", s.Profile)
	}
	return nil
}

func (s Scope) String() string { return s.Profile }

// JobsSubject is where this profile's jobs are published/consumed.
func (s Scope) JobsSubject() string { return "fetch." + s.Profile + ".jobs" }

// RespSubject is where a single job's response is published/collected.
func (s Scope) RespSubject(id string) string {
	return "fetch." + s.Profile + ".responses." + id
}

// RespWildcard matches all of this profile's response subjects (for subscribe
// permissions).
func (s Scope) RespWildcard() string {
	return "fetch." + s.Profile + ".responses.>"
}

// Durable is the per-profile runner consumer name (shared by all runner
// instances in the profile so they load-balance).
func (s Scope) Durable() string { return "runners_" + s.Profile }

// Config is resolved from the environment. Secrets never get logged.
type Config struct {
	URL      string // TALARIA_NATS_URL (wss://... in prod)
	Token    string // TALARIA_NATS_TOKEN
	NatsUser string // TALARIA_NATS_USER
	NatsPass string // TALARIA_NATS_PASS
	Creds    string // TALARIA_NATS_CREDS (path to a .creds file)

	Scope Scope // TALARIA_PROFILE (the tenant / account name)

	SelfPriv       string   // TALARIA_SELF_PRIV (base64 X25519 private key)
	PeerPub        string   // TALARIA_PEER_PUB  (dispatcher: the runner's public key)
	AllowedSenders []string // TALARIA_ALLOWED_SENDERS (runner: authorized dispatcher pubkeys)

	MaxBody int           // TALARIA_MAX_BODY bytes (runner inline response cap)
	RespTTL time.Duration // TALARIA_RESP_TTL (RESPONSES retention)
}

// LoadConfig reads configuration from the environment, applying defaults. It
// validates transport and scope; key fields are validated by the role that
// needs them.
func LoadConfig() (Config, error) {
	c := Config{
		URL:      os.Getenv("TALARIA_NATS_URL"),
		Token:    os.Getenv("TALARIA_NATS_TOKEN"),
		NatsUser: os.Getenv("TALARIA_NATS_USER"),
		NatsPass: os.Getenv("TALARIA_NATS_PASS"),
		Creds:    os.Getenv("TALARIA_NATS_CREDS"),
		Scope:    Scope{Profile: os.Getenv("TALARIA_PROFILE")},
		SelfPriv: os.Getenv("TALARIA_SELF_PRIV"),
		PeerPub:  os.Getenv("TALARIA_PEER_PUB"),
		MaxBody:  700 * 1024,
		RespTTL:  time.Hour,
	}
	if v := os.Getenv("TALARIA_ALLOWED_SENDERS"); v != "" {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.AllowedSenders = append(c.AllowedSenders, p)
			}
		}
	} else if c.PeerPub != "" {
		// Back-compat / single-dispatcher: the configured peer is the sole sender.
		c.AllowedSenders = []string{c.PeerPub}
	}
	if v := os.Getenv("TALARIA_MAX_BODY"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c, fmt.Errorf("TALARIA_MAX_BODY: %w", err)
		}
		c.MaxBody = n
	}
	if v := os.Getenv("TALARIA_RESP_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("TALARIA_RESP_TTL: %w", err)
		}
		c.RespTTL = d
	}
	if c.URL == "" {
		return c, fmt.Errorf("TALARIA_NATS_URL is required")
	}
	if err := c.Scope.Validate(); err != nil {
		return c, fmt.Errorf("%w (set TALARIA_PROFILE)", err)
	}
	return c, nil
}

// Connect dials NATS with the configured auth. name identifies the role.
func Connect(cfg Config, name string) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name(name),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
	}
	switch {
	case cfg.Creds != "":
		opts = append(opts, nats.UserCredentials(cfg.Creds))
	case cfg.Token != "":
		opts = append(opts, nats.Token(cfg.Token))
	case cfg.NatsUser != "":
		opts = append(opts, nats.UserInfo(cfg.NatsUser, cfg.NatsPass))
	}
	return nats.Connect(cfg.URL, opts...)
}

// JetStream returns a JetStream context for the connection.
func JetStream(nc *nats.Conn) (jetstream.JetStream, error) {
	return jetstream.New(nc)
}

// EnsureStreams idempotently declares both shared streams. JOBS is a work queue
// (each job consumed once); RESPONSES is time-limited. Per-scope consumers bind
// with non-overlapping filter subjects.
func EnsureStreams(ctx context.Context, js jetstream.JetStream, cfg Config) error {
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      StreamJobs,
		Subjects:  []string{SubjectJobsWildcard},
		Retention: jetstream.WorkQueuePolicy,
		Storage:   jetstream.FileStorage,
	}); err != nil {
		return fmt.Errorf("ensure JOBS stream: %w", err)
	}
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      StreamResponses,
		Subjects:  []string{SubjectRespWildcard},
		Retention: jetstream.LimitsPolicy,
		Storage:   jetstream.FileStorage,
		MaxAge:    cfg.RespTTL,
	}); err != nil {
		return fmt.Errorf("ensure RESPONSES stream: %w", err)
	}
	return nil
}

// Package natsx holds the shared NATS/JetStream wiring used by both roles:
// connecting (TLS/wss only in production), declaring the JOBS and RESPONSES
// streams, and loading configuration from the environment.
//
// B is stock nats-server; this package only talks to it as a client. The plan
// mandates wss:// in production (no plaintext 4222), but the URL is taken from
// the environment so tests can point at an in-process nats:// server.
package natsx

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Stream and subject names. Only the opaque job id appears in a subject; see the
// design's cleartext-vs-sealed note.
const (
	StreamJobs      = "TALARIA_JOBS"
	StreamResponses = "TALARIA_RESP"

	SubjectJobs         = "fetch.jobs"
	SubjectRespPrefix   = "fetch.responses." // + <id>
	SubjectRespWildcard = "fetch.responses.>"

	RunnerDurable = "runners" // shared pull consumer; N runners load-balance
)

// Config is resolved from the environment. Secrets never get logged.
type Config struct {
	URL      string        // TALARIA_NATS_URL (wss://... in prod)
	Token    string        // TALARIA_NATS_TOKEN
	User     string        // TALARIA_NATS_USER
	Pass     string        // TALARIA_NATS_PASS
	Creds    string        // TALARIA_NATS_CREDS (path to a .creds file)
	SelfPriv string        // TALARIA_SELF_PRIV (base64 X25519 private key)
	PeerPub  string        // TALARIA_PEER_PUB  (base64 X25519 public key)
	MaxBody  int           // TALARIA_MAX_BODY bytes (runner inline response cap)
	RespTTL  time.Duration // TALARIA_RESP_TTL (RESPONSES retention)
}

// LoadConfig reads configuration from the environment, applying defaults.
func LoadConfig() (Config, error) {
	c := Config{
		URL:      os.Getenv("TALARIA_NATS_URL"),
		Token:    os.Getenv("TALARIA_NATS_TOKEN"),
		User:     os.Getenv("TALARIA_NATS_USER"),
		Pass:     os.Getenv("TALARIA_NATS_PASS"),
		Creds:    os.Getenv("TALARIA_NATS_CREDS"),
		SelfPriv: os.Getenv("TALARIA_SELF_PRIV"),
		PeerPub:  os.Getenv("TALARIA_PEER_PUB"),
		MaxBody:  700 * 1024, // ~ fits under the 1 MiB max_payload after base64+seal
		RespTTL:  time.Hour,
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
	return c, nil
}

// Connect dials NATS with the configured auth. name identifies the role in
// server logs/monitoring.
func Connect(cfg Config, name string) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name(name),
		nats.MaxReconnects(-1), // reconnect forever; survives WSS/Netskope blips
		nats.ReconnectWait(2 * time.Second),
	}
	switch {
	case cfg.Creds != "":
		opts = append(opts, nats.UserCredentials(cfg.Creds))
	case cfg.Token != "":
		opts = append(opts, nats.Token(cfg.Token))
	case cfg.User != "":
		opts = append(opts, nats.UserInfo(cfg.User, cfg.Pass))
	}
	return nats.Connect(cfg.URL, opts...)
}

// JetStream returns a JetStream context for the connection.
func JetStream(nc *nats.Conn) (jetstream.JetStream, error) {
	return jetstream.New(nc)
}

// EnsureStreams idempotently declares both streams. JOBS is a work queue (each
// job consumed once); RESPONSES is time-limited (responses linger for later
// collection, then expire).
func EnsureStreams(ctx context.Context, js jetstream.JetStream, cfg Config) error {
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      StreamJobs,
		Subjects:  []string{SubjectJobs},
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

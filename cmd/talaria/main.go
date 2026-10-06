// Command talaria is the single binary for the dispatcher and runner client
// sides, plus key/tenant provisioning:
//
//	talaria keygen                      generate one X25519 keypair
//	talaria onboard --user U --profile P  mint a scope's keypairs + config blocks
//	talaria run                         C-side runner: execute jobs for a scope
//	talaria send --url ...               A-side dispatcher: send one job, print result
//
// B is stock nats-server (see deploy/), not this binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/neuralcolony/talaria/internal/crypto"
	"github.com/neuralcolony/talaria/internal/dispatch"
	"github.com/neuralcolony/talaria/internal/job"
	"github.com/neuralcolony/talaria/internal/natsx"
	"github.com/neuralcolony/talaria/internal/runner"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	loadDotenv()
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "onboard":
		err = cmdOnboard(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "send":
		err = cmdSend(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `talaria — encrypted async remote-fetch dispatcher (multi-tenant)

usage:
  talaria keygen                        generate one X25519 keypair
  talaria onboard --user U --profile P  mint a scope's dispatcher+runner keys and
                                        config blocks (optionally -out DIR)
  talaria run                           start the runner for a scope (on C)
  talaria send --url URL                dispatch one fetch job for a scope (on A)

config via environment (or a .env file in the working dir):
  TALARIA_NATS_URL    wss://... (required)
  TALARIA_NATS_TOKEN | TALARIA_NATS_USER/PASS | TALARIA_NATS_CREDS
  TALARIA_USER, TALARIA_PROFILE   the scope (required for run/send)
  TALARIA_SELF_PRIV   this machine's base64 private key
  TALARIA_PEER_PUB    dispatcher: the runner's base64 public key
  TALARIA_ALLOWED_SENDERS  runner: comma-separated authorized dispatcher pubkeys
  TALARIA_MAX_BODY    runner inline response cap in bytes (default 716800)
  TALARIA_RESP_TTL    response retention, e.g. 1h (default 1h)
`)
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	_ = fs.Parse(args)
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return err
	}
	fmt.Printf("# Keep PRIVATE on this machine; share PUBLIC with the peer.\n")
	fmt.Printf("TALARIA_SELF_PRIV=%s\n", kp.Private)
	fmt.Printf("# peer configures this as a sender/peer:  %s\n", kp.Public)
	return nil
}

func cmdOnboard(args []string) error {
	fs := flag.NewFlagSet("onboard", flag.ExitOnError)
	user := fs.String("user", "", "user segment of the scope (required)")
	profile := fs.String("profile", "", "profile segment of the scope (required)")
	out := fs.String("out", "", "directory to write dispatcher.env and runner.env (0600); if empty, print")
	if err := fs.Parse(args); err != nil {
		return err
	}
	scope := natsx.Scope{User: *user, Profile: *profile}
	if err := scope.Validate(); err != nil {
		return err
	}
	disp, err := crypto.GenerateKeypair()
	if err != nil {
		return err
	}
	run, err := crypto.GenerateKeypair()
	if err != nil {
		return err
	}

	dispEnv := fmt.Sprintf(`# talaria DISPATCHER (machine A) — scope %s
TALARIA_USER=%s
TALARIA_PROFILE=%s
TALARIA_SELF_PRIV=%s
TALARIA_PEER_PUB=%s
# fill in transport + NATS auth for this scope:
TALARIA_NATS_URL=wss://b.example.com/talaria
TALARIA_NATS_USER=
TALARIA_NATS_PASS=
`, scope.String(), scope.User, scope.Profile, disp.Private, run.Public)

	runEnv := fmt.Sprintf(`# talaria RUNNER (machine C) — scope %s
TALARIA_USER=%s
TALARIA_PROFILE=%s
TALARIA_SELF_PRIV=%s
TALARIA_ALLOWED_SENDERS=%s
# fill in transport + NATS auth for this scope:
TALARIA_NATS_URL=wss://b.example.com/talaria
TALARIA_NATS_USER=
TALARIA_NATS_PASS=
`, scope.String(), scope.User, scope.Profile, run.Private, disp.Public)

	if *out == "" {
		fmt.Printf("# ===== dispatcher.env (machine A) =====\n%s\n", dispEnv)
		fmt.Printf("# ===== runner.env (machine C) =====\n%s\n", runEnv)
		fmt.Fprintln(os.Stderr, "note: these contain PRIVATE keys; prefer -out DIR to write 0600 files")
		return nil
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	dp := filepath.Join(*out, "dispatcher.env")
	rp := filepath.Join(*out, "runner.env")
	if err := os.WriteFile(dp, []byte(dispEnv), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(rp, []byte(runEnv), 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s (0600)\n", dp, rp)
	fmt.Println("deliver dispatcher.env to A and runner.env to C; set NATS auth in each.")
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	user := fs.String("user", "", "override TALARIA_USER")
	profile := fs.String("profile", "", "override TALARIA_PROFILE")
	_ = fs.Parse(args)
	applyScopeFlags(*user, *profile)

	cfg, err := natsx.LoadConfig()
	if err != nil {
		return err
	}
	if cfg.SelfPriv == "" {
		return fmt.Errorf("TALARIA_SELF_PRIV is required for the runner")
	}
	id, err := crypto.NewIdentity(cfg.SelfPriv)
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	nc, err := natsx.Connect(cfg, "talaria-runner")
	if err != nil {
		return err
	}
	defer nc.Drain()
	js, err := natsx.JetStream(nc)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := natsx.EnsureStreams(ctx, js, cfg); err != nil {
		return err
	}
	return runner.New(js, id, cfg.Scope, cfg.AllowedSenders, cfg.MaxBody, nil).Run(ctx)
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	user := fs.String("user", "", "override TALARIA_USER")
	profile := fs.String("profile", "", "override TALARIA_PROFILE")
	method := fs.String("method", "GET", "HTTP method")
	url := fs.String("url", "", "target URL (required)")
	data := fs.String("data", "", "request body")
	timeout := fs.Duration("timeout", 30*time.Second, "per-request timeout on the runner")
	wait := fs.Duration("wait", 35*time.Second, "how long to wait for the response")
	showHeaders := fs.Bool("i", false, "include response headers in output")
	var headers headerFlags
	fs.Var(&headers, "header", "request header 'Key: Value' (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" {
		return fmt.Errorf("--url is required")
	}
	applyScopeFlags(*user, *profile)

	cfg, err := natsx.LoadConfig()
	if err != nil {
		return err
	}
	if cfg.SelfPriv == "" || cfg.PeerPub == "" {
		return fmt.Errorf("TALARIA_SELF_PRIV and TALARIA_PEER_PUB are required for the dispatcher")
	}
	id, err := crypto.NewIdentity(cfg.SelfPriv)
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	nc, err := natsx.Connect(cfg, "talaria-dispatch")
	if err != nil {
		return err
	}
	defer nc.Drain()
	js, err := natsx.JetStream(nc)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := natsx.EnsureStreams(ctx, js, cfg); err != nil {
		return err
	}

	j := &job.Job{
		ID:        job.NewID(),
		Method:    strings.ToUpper(*method),
		URL:       *url,
		Headers:   headers.toMap(),
		TimeoutMS: int(timeout.Milliseconds()),
	}
	if *data != "" {
		j.Body = []byte(*data)
	}
	resp, err := dispatch.New(js, id, cfg.Scope, cfg.PeerPub).Do(ctx, j, *wait)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "runner error: %s\n", resp.Error)
	}
	if resp.Status != 0 {
		fmt.Printf("HTTP %d  (%d bytes, %dms, from runner)\n", resp.Status, resp.Bytes, resp.DurationMS)
	}
	if *showHeaders {
		for k, vs := range resp.Headers {
			for _, v := range vs {
				fmt.Printf("%s: %s\n", k, v)
			}
		}
		fmt.Println()
	}
	if len(resp.Body) > 0 {
		os.Stdout.Write(resp.Body)
		if resp.Body[len(resp.Body)-1] != '\n' {
			fmt.Println()
		}
	}
	if resp.Error != "" {
		os.Exit(1)
	}
	return nil
}

// applyScopeFlags lets --user/--profile override the env before LoadConfig.
func applyScopeFlags(user, profile string) {
	if user != "" {
		_ = os.Setenv("TALARIA_USER", user)
	}
	if profile != "" {
		_ = os.Setenv("TALARIA_PROFILE", profile)
	}
}

type headerFlags []string

func (h *headerFlags) String() string { return strings.Join(*h, ", ") }
func (h *headerFlags) Set(v string) error {
	*h = append(*h, v)
	return nil
}
func (h headerFlags) toMap() map[string][]string {
	if len(h) == 0 {
		return nil
	}
	m := map[string][]string{}
	for _, raw := range h {
		k, v, ok := strings.Cut(raw, ":")
		if !ok {
			continue
		}
		m[strings.TrimSpace(k)] = append(m[strings.TrimSpace(k)], strings.TrimSpace(v))
	}
	return m
}

// loadDotenv loads KEY=VALUE lines from $TALARIA_ENV or ./.env without
// overriding variables already present in the real environment.
func loadDotenv() {
	path := os.Getenv("TALARIA_ENV")
	if path == "" {
		path = ".env"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
}

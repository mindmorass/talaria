// Command talaria is the single binary for all three roles' client side:
//
//	talaria keygen            generate an X25519 keypair for A or C
//	talaria run               C-side runner: execute jobs from the lab
//	talaria send --url ...     A-side dispatcher: send one fetch job, print result
//
// B is stock nats-server (see deploy/), not this binary.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"flag"

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
	loadDotenv() // populate env from ./.env (or $TALARIA_ENV) without overriding real env
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
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
	fmt.Fprint(os.Stderr, `talaria — encrypted async remote-fetch dispatcher

usage:
  talaria keygen            generate an X25519 keypair (run on A and on C)
  talaria run               start the runner (on C): execute jobs, egress locally
  talaria send --url URL    dispatch one fetch job (on A) and print the response

config via environment (or a .env file in the working dir):
  TALARIA_NATS_URL   wss://... (required)
  TALARIA_NATS_TOKEN | TALARIA_NATS_USER/PASS | TALARIA_NATS_CREDS
  TALARIA_SELF_PRIV  this machine's base64 private key (required for run/send)
  TALARIA_PEER_PUB   the peer's base64 public key     (required for run/send)
  TALARIA_MAX_BODY   runner inline response cap in bytes (default 716800)
  TALARIA_RESP_TTL   response retention, e.g. 1h (default 1h)
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
	fmt.Printf("# peer configures:  TALARIA_PEER_PUB=%s\n", kp.Public)
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	_ = fs.Parse(args)

	cfg, err := natsx.LoadConfig()
	if err != nil {
		return err
	}
	box, err := crypto.NewBox(cfg.SelfPriv, cfg.PeerPub)
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
	return runner.New(js, box, cfg.MaxBody, nil).Run(ctx)
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
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

	cfg, err := natsx.LoadConfig()
	if err != nil {
		return err
	}
	box, err := crypto.NewBox(cfg.SelfPriv, cfg.PeerPub)
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

	cli := dispatch.New(js, box)
	resp, err := cli.Do(ctx, j, *wait)
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

// headerFlags collects repeated --header values.
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
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		m[k] = append(m[k], v)
	}
	return m
}

// loadDotenv loads KEY=VALUE lines from $TALARIA_ENV or ./.env, without
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

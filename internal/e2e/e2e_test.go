package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	natssrv "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/neuralcolony/talaria/internal/crypto"
	"github.com/neuralcolony/talaria/internal/dispatch"
	"github.com/neuralcolony/talaria/internal/job"
	"github.com/neuralcolony/talaria/internal/natsx"
	"github.com/neuralcolony/talaria/internal/runner"
)

// startServer runs an in-process nats-server with JetStream — no external binary.
func startServer(t *testing.T) string {
	t.Helper()
	opts := &natssrv.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()}
	s, err := natssrv.NewServer(opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("server not ready")
	}
	t.Cleanup(s.Shutdown)
	return s.ClientURL()
}

type rig struct {
	cfg    natsx.Config
	aBox   *crypto.Box // dispatcher
	cBox   *crypto.Box // runner
	dispJS jetstream.JetStream
	dispNC *nats.Conn
	cli    *dispatch.Client
}

func newRig(t *testing.T, maxBody int) *rig {
	t.Helper()
	url := startServer(t)
	a, _ := crypto.GenerateKeypair()
	c, _ := crypto.GenerateKeypair()
	aBox, err := crypto.NewBox(a.Private, c.Public)
	if err != nil {
		t.Fatal(err)
	}
	cBox, err := crypto.NewBox(c.Private, a.Public)
	if err != nil {
		t.Fatal(err)
	}
	cfg := natsx.Config{URL: url, MaxBody: maxBody, RespTTL: time.Hour}

	nc, err := natsx.Connect(cfg, "test-dispatch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Drain() })
	js, err := natsx.JetStream(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := natsx.EnsureStreams(ctx, js, cfg); err != nil {
		t.Fatal(err)
	}
	return &rig{cfg: cfg, aBox: aBox, cBox: cBox, dispJS: js, dispNC: nc, cli: dispatch.New(js, aBox)}
}

// startRunner wires a runner on its own connection and returns a stop func.
func (r *rig) startRunner(t *testing.T) context.CancelFunc {
	t.Helper()
	nc, err := natsx.Connect(r.cfg, "test-runner")
	if err != nil {
		t.Fatal(err)
	}
	js, err := natsx.JetStream(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = runner.New(js, r.cBox, r.cfg.MaxBody, nil).Run(ctx)
		nc.Drain()
	}()
	return cancel
}

func TestEndToEndFetch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Echo-UA", req.Header.Get("User-Agent"))
		w.WriteHeader(201)
		fmt.Fprintf(w, "hello from %s", req.Method)
	}))
	defer ts.Close()

	rig := newRig(t, 700*1024)
	stop := rig.startRunner(t)
	defer stop()

	j := &job.Job{ID: job.NewID(), Method: "GET", URL: ts.URL,
		Headers: map[string][]string{"User-Agent": {"talaria-test/1.0"}}}
	resp, err := rig.cli.Do(context.Background(), j, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 201 {
		t.Fatalf("status = %d, want 201 (err=%q)", resp.Status, resp.Error)
	}
	if !bytes.Equal(resp.Body, []byte("hello from GET")) {
		t.Fatalf("body = %q", resp.Body)
	}
	if got := resp.Headers["X-Echo-Ua"]; len(got) == 0 || got[0] != "talaria-test/1.0" {
		t.Fatalf("header not forwarded to origin: %v", resp.Headers)
	}
}

func TestZeroKnowledgeAtRest(t *testing.T) {
	rig := newRig(t, 700*1024)
	secretURL := "https://super-secret.example.internal/path?token=abc"
	j := &job.Job{ID: job.NewID(), Method: "GET", URL: secretURL}
	if err := rig.cli.Publish(context.Background(), j); err != nil {
		t.Fatal(err)
	}

	// Read the raw message at rest from the JOBS stream.
	ctx := context.Background()
	stream, err := rig.dispJS.Stream(ctx, natsx.StreamJobs)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := stream.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw.Data), "super-secret") || strings.Contains(string(raw.Data), "token=abc") {
		t.Fatalf("plaintext leaked at rest in B: %q", raw.Data)
	}
	// But the runner's box can recover it.
	plain, err := rig.cBox.Open(raw.Data)
	if err != nil {
		t.Fatalf("runner cannot open sealed job: %v", err)
	}
	got, err := job.UnmarshalJob(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != secretURL {
		t.Fatalf("decrypted url = %q", got.URL)
	}
}

func TestDurabilityCollectAfterRunnerStarts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, "late")
	}))
	defer ts.Close()

	rig := newRig(t, 700*1024)
	// Publish while NO runner is up — job waits durably in JOBS.
	j := &job.Job{ID: job.NewID(), Method: "GET", URL: ts.URL}
	if err := rig.cli.Publish(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	// Now bring the runner up and collect.
	stop := rig.startRunner(t)
	defer stop()
	resp, err := rig.cli.Collect(context.Background(), j.ID, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || !bytes.Equal(resp.Body, []byte("late")) {
		t.Fatalf("unexpected response: %d %q %q", resp.Status, resp.Body, resp.Error)
	}
}

func TestOversizeBodyReturnsError(t *testing.T) {
	big := strings.Repeat("A", 4096)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, big)
	}))
	defer ts.Close()

	rig := newRig(t, 1024) // cap below the response size
	stop := rig.startRunner(t)
	defer stop()

	resp, err := rig.cli.Do(context.Background(), &job.Job{ID: job.NewID(), Method: "GET", URL: ts.URL}, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error == "" {
		t.Fatal("expected oversize error")
	}
	if len(resp.Body) != 0 {
		t.Fatalf("oversize body should be dropped, got %d bytes", len(resp.Body))
	}
}

func TestBadURLReturnsErrorNotHang(t *testing.T) {
	rig := newRig(t, 700*1024)
	stop := rig.startRunner(t)
	defer stop()

	// Unroutable port → connection refused quickly; runner must report, not hang.
	j := &job.Job{ID: job.NewID(), Method: "GET", URL: "http://127.0.0.1:1/nope", TimeoutMS: 2000}
	resp, err := rig.cli.Do(context.Background(), j, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error == "" {
		t.Fatalf("expected request error, got status %d", resp.Status)
	}
}

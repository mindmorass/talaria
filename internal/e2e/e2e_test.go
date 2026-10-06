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

	"github.com/mindmorass/talaria/internal/crypto"
	"github.com/mindmorass/talaria/internal/dispatch"
	"github.com/mindmorass/talaria/internal/job"
	"github.com/mindmorass/talaria/internal/natsx"
	"github.com/mindmorass/talaria/internal/runner"
)

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

func mustID(t *testing.T) *crypto.Identity {
	t.Helper()
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypto.NewIdentity(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type rig struct {
	cfg   natsx.Config
	scope natsx.Scope
	aID   *crypto.Identity // dispatcher
	cID   *crypto.Identity // runner
	js    jetstream.JetStream
	nc    *nats.Conn
	cli   *dispatch.Client
}

func newRig(t *testing.T, maxBody int) *rig {
	t.Helper()
	url := startServer(t)
	scope := natsx.Scope{Profile: "alice"}
	aID, cID := mustID(t), mustID(t)
	cfg := natsx.Config{URL: url, Scope: scope, MaxBody: maxBody, RespTTL: time.Hour}

	nc, err := natsx.Connect(cfg, "test-dispatch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Drain() })
	js, err := natsx.JetStream(nc)
	if err != nil {
		t.Fatal(err)
	}
	if err := natsx.EnsureStreams(context.Background(), js, cfg); err != nil {
		t.Fatal(err)
	}
	return &rig{
		cfg: cfg, scope: scope, aID: aID, cID: cID, js: js, nc: nc,
		cli: dispatch.New(js, aID, scope, cID.PublicB64()),
	}
}

// startRunner runs a runner for the rig's scope, allowing the given senders.
func (r *rig) startRunner(t *testing.T, allow ...string) context.CancelFunc {
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
		_ = runner.New(js, r.cID, r.scope, allow, r.cfg.MaxBody, nil).Run(ctx)
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

	r := newRig(t, 700*1024)
	defer r.startRunner(t, r.aID.PublicB64())()

	j := &job.Job{Method: "GET", URL: ts.URL, Headers: map[string][]string{"User-Agent": {"talaria-test/1.0"}}}
	resp, err := r.cli.Do(context.Background(), j, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 201 {
		t.Fatalf("status = %d want 201 (err=%q)", resp.Status, resp.Error)
	}
	if !bytes.Equal(resp.Body, []byte("hello from GET")) {
		t.Fatalf("body = %q", resp.Body)
	}
	if got := resp.Headers["X-Echo-Ua"]; len(got) == 0 || got[0] != "talaria-test/1.0" {
		t.Fatalf("header not forwarded: %v", resp.Headers)
	}
}

func TestZeroKnowledgeAtRest(t *testing.T) {
	r := newRig(t, 700*1024)
	secretURL := "https://super-secret.example.internal/path?token=abc"
	if err := r.cli.Publish(context.Background(), &job.Job{Method: "GET", URL: secretURL}); err != nil {
		t.Fatal(err)
	}
	stream, err := r.js.Stream(context.Background(), natsx.StreamJobs)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := stream.GetMsg(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw.Data), "super-secret") || strings.Contains(string(raw.Data), "token=abc") {
		t.Fatalf("plaintext leaked at rest in B: %q", raw.Data)
	}
	plain, err := r.cID.OpenFrom(r.aID.PublicB64(), raw.Data)
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
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, "late") }))
	defer ts.Close()

	r := newRig(t, 700*1024)
	j := &job.Job{Method: "GET", URL: ts.URL}
	if err := r.cli.Publish(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	defer r.startRunner(t, r.aID.PublicB64())()
	resp, err := r.cli.Collect(context.Background(), j.ID, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || !bytes.Equal(resp.Body, []byte("late")) {
		t.Fatalf("unexpected: %d %q %q", resp.Status, resp.Body, resp.Error)
	}
}

func TestOversizeBodyReturnsError(t *testing.T) {
	big := strings.Repeat("A", 4096)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, big) }))
	defer ts.Close()

	r := newRig(t, 1024)
	defer r.startRunner(t, r.aID.PublicB64())()
	resp, err := r.cli.Do(context.Background(), &job.Job{Method: "GET", URL: ts.URL}, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error == "" || len(resp.Body) != 0 {
		t.Fatalf("expected oversize error with dropped body, got err=%q len=%d", resp.Error, len(resp.Body))
	}
}

func TestBadURLReturnsErrorNotHang(t *testing.T) {
	r := newRig(t, 700*1024)
	defer r.startRunner(t, r.aID.PublicB64())()
	j := &job.Job{Method: "GET", URL: "http://127.0.0.1:1/nope", TimeoutMS: 2000}
	resp, err := r.cli.Do(context.Background(), j, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error == "" {
		t.Fatalf("expected request error, got status %d", resp.Status)
	}
}

// TestRejectsUnauthorizedSender: a rogue dispatcher (not in the runner's
// allowlist) publishes into the scope; the runner must drop it and no response
// appears.
func TestRejectsUnauthorizedSender(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, "ok") }))
	defer ts.Close()

	r := newRig(t, 700*1024)
	// Runner allows only the legit dispatcher aID.
	defer r.startRunner(t, r.aID.PublicB64())()

	rogue := mustID(t)
	rogueCli := dispatch.New(r.js, rogue, r.scope, r.cID.PublicB64())
	j := &job.Job{Method: "GET", URL: ts.URL}
	if err := rogueCli.Publish(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if _, err := rogueCli.Collect(context.Background(), j.ID, 2*time.Second); err == nil {
		t.Fatal("rogue sender should get no response")
	}
}

// TestCrossScopeNoDelivery: a dispatcher in a different scope gets no response
// when the only runner serves another scope.
func TestCrossScopeNoDelivery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, "ok") }))
	defer ts.Close()

	r := newRig(t, 700*1024)                    // scope alice/work
	defer r.startRunner(t, r.aID.PublicB64())() // runner only for alice/work

	otherScope := natsx.Scope{Profile: "bob"}
	otherCli := dispatch.New(r.js, r.aID, otherScope, r.cID.PublicB64())
	j := &job.Job{Method: "GET", URL: ts.URL}
	if err := otherCli.Publish(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if _, err := otherCli.Collect(context.Background(), j.ID, 2*time.Second); err == nil {
		t.Fatal("cross-scope request should not be served")
	}
}

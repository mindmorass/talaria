// Package runner is the C-side worker: it consumes sealed jobs for its scope,
// authenticates the sender against an allowlist, opens the job, performs the
// HTTP request from inside the lab (egress — and Netskope inspection — happen
// here), then seals the response back to that sender and publishes it. It always
// publishes something, so the dispatcher never blocks.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/mindmorass/talaria/internal/crypto"
	"github.com/mindmorass/talaria/internal/job"
	"github.com/mindmorass/talaria/internal/natsx"
	"github.com/nats-io/nats.go/jetstream"
)

const defaultTimeout = 30 * time.Second

// Runner executes jobs for one scope. The zero HTTP client deliberately uses the
// system trust store (no cert pinning) so Netskope's inline CA is honored.
type Runner struct {
	js      jetstream.JetStream
	id      *crypto.Identity
	scope   natsx.Scope
	allow   map[string]bool // authorized dispatcher public keys (base64)
	client  *http.Client
	maxBody int
	log     *slog.Logger
}

// New builds a Runner. allow is the set of authorized dispatcher public keys;
// jobs whose sender is not in it are rejected without decryption.
func New(js jetstream.JetStream, id *crypto.Identity, scope natsx.Scope, allow []string, maxBody int, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	set := make(map[string]bool, len(allow))
	for _, k := range allow {
		set[k] = true
	}
	return &Runner{
		js:      js,
		id:      id,
		scope:   scope,
		allow:   set,
		client:  &http.Client{},
		maxBody: maxBody,
		log:     log,
	}
}

// Run binds this scope's durable pull consumer and processes jobs until ctx is
// cancelled. Multiple Runner processes in the same scope load-balance.
func (r *Runner) Run(ctx context.Context) error {
	if len(r.allow) == 0 {
		return fmt.Errorf("runner: empty sender allowlist (set TALARIA_ALLOWED_SENDERS or TALARIA_PEER_PUB)")
	}
	cons, err := r.js.CreateOrUpdateConsumer(ctx, natsx.StreamJobs, jetstream.ConsumerConfig{
		Durable:       r.scope.Durable(),
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: r.scope.JobsSubject(),
		AckWait:       time.Minute,
	})
	if err != nil {
		return fmt.Errorf("create runner consumer: %w", err)
	}
	cc, err := cons.Consume(func(msg jetstream.Msg) { r.handle(ctx, msg) })
	if err != nil {
		return fmt.Errorf("consume: %w", err)
	}
	defer cc.Stop()
	r.log.Info("runner started", "scope", r.scope.String(), "senders", len(r.allow))
	<-ctx.Done()
	return nil
}

func (r *Runner) handle(ctx context.Context, msg jetstream.Msg) {
	sender := msg.Headers().Get(natsx.HeaderSender)
	if sender == "" || !r.allow[sender] {
		r.log.Warn("drop job from unauthorized sender", "scope", r.scope.String(), "sender", sender)
		_ = msg.Term()
		return
	}
	plain, err := r.id.OpenFrom(sender, msg.Data())
	if err != nil {
		// Named an allowed sender but not sealed by that sender's key.
		r.log.Error("drop job: open failed", "sender", sender, "err", err)
		_ = msg.Term()
		return
	}
	j, err := job.UnmarshalJob(plain)
	if err != nil {
		r.log.Error("drop malformed job", "err", err)
		_ = msg.Term()
		return
	}
	// Defense in depth: the authenticated envelope must agree with the routing.
	if j.Sender != sender || j.Profile != r.scope.Profile {
		r.log.Error("drop job: profile/sender mismatch", "job_profile", j.Profile, "runner_profile", r.scope.String())
		_ = msg.Term()
		return
	}
	resp := r.fetch(ctx, j)
	if err := r.publish(ctx, sender, resp); err != nil {
		r.log.Error("publish response failed; will redeliver", "id", j.ID, "err", err)
		_ = msg.Nak()
		return
	}
	_ = msg.Ack()
}

// fetch performs the HTTP request and ALWAYS returns a Response.
func (r *Runner) fetch(ctx context.Context, j *job.Job) *job.Response {
	start := time.Now()
	out := &job.Response{ID: j.ID}
	finish := func() *job.Response {
		out.DurationMS = time.Since(start).Milliseconds()
		out.FinishedAt = time.Now().UTC()
		return out
	}
	if err := j.Validate(); err != nil {
		out.Error = err.Error()
		return finish()
	}
	timeout := defaultTimeout
	if j.TimeoutMS > 0 {
		timeout = time.Duration(j.TimeoutMS) * time.Millisecond
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var body io.Reader
	if len(j.Body) > 0 {
		body = bytes.NewReader(j.Body)
	}
	req, err := http.NewRequestWithContext(reqCtx, j.Method, j.URL, body)
	if err != nil {
		out.Error = fmt.Sprintf("build request: %v", err)
		return finish()
	}
	for k, vs := range j.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := r.client.Do(req)
	if err != nil {
		out.Error = fmt.Sprintf("request failed: %v", err)
		return finish()
	}
	defer resp.Body.Close()
	out.Status = resp.StatusCode
	out.Headers = map[string][]string(resp.Header)

	limited := io.LimitReader(resp.Body, int64(r.maxBody)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		out.Error = fmt.Sprintf("read body: %v", err)
		return finish()
	}
	if len(data) > r.maxBody {
		out.Body = nil
		out.Error = fmt.Sprintf("response body exceeds inline cap of %d bytes (use large-response path)", r.maxBody)
		return finish()
	}
	out.Body = data
	out.Bytes = len(data)
	return finish()
}

func (r *Runner) publish(ctx context.Context, sender string, resp *job.Response) error {
	raw, err := resp.Marshal()
	if err != nil {
		return err
	}
	sealed, err := r.id.SealTo(sender, raw) // seal back to the requester
	if err != nil {
		return err
	}
	_, err = r.js.Publish(ctx, r.scope.RespSubject(resp.ID), sealed)
	return err
}

// Package runner is the C-side worker: it consumes sealed jobs from the queue,
// opens them, performs the HTTP request from inside the lab (this is where
// egress — and Netskope inspection — happens), then seals and publishes the
// response. It always publishes something, so the dispatcher never blocks.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/neuralcolony/talaria/internal/crypto"
	"github.com/neuralcolony/talaria/internal/job"
	"github.com/neuralcolony/talaria/internal/natsx"
)

const defaultTimeout = 30 * time.Second

// Runner executes jobs. The zero HTTP client deliberately uses the system trust
// store (no cert pinning) so Netskope's inline CA is honored on the managed box.
type Runner struct {
	js      jetstream.JetStream
	box     *crypto.Box
	client  *http.Client
	maxBody int
	log     *slog.Logger
}

func New(js jetstream.JetStream, box *crypto.Box, maxBody int, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	return &Runner{
		js:      js,
		box:     box,
		client:  &http.Client{}, // per-request timeout applied via context
		maxBody: maxBody,
		log:     log,
	}
}

// Run binds the shared durable pull consumer and processes jobs until ctx is
// cancelled. Multiple Runner processes on the same durable load-balance.
func (r *Runner) Run(ctx context.Context) error {
	cons, err := r.js.CreateOrUpdateConsumer(ctx, natsx.StreamJobs, jetstream.ConsumerConfig{
		Durable:       natsx.RunnerDurable,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: natsx.SubjectJobs,
		AckWait:       time.Minute,
	})
	if err != nil {
		return fmt.Errorf("create runner consumer: %w", err)
	}
	cc, err := cons.Consume(func(msg jetstream.Msg) {
		r.handle(ctx, msg)
	})
	if err != nil {
		return fmt.Errorf("consume: %w", err)
	}
	defer cc.Stop()
	r.log.Info("runner started", "stream", natsx.StreamJobs, "durable", natsx.RunnerDurable)
	<-ctx.Done()
	return nil
}

func (r *Runner) handle(ctx context.Context, msg jetstream.Msg) {
	sealed := msg.Data()
	plain, err := r.box.Open(sealed)
	if err != nil {
		// Can't decrypt/authenticate — this is not ours to retry. Drop it.
		r.log.Error("drop undecryptable job", "err", err)
		_ = msg.Term()
		return
	}
	j, err := job.UnmarshalJob(plain)
	if err != nil {
		r.log.Error("drop malformed job", "err", err)
		_ = msg.Term()
		return
	}
	resp := r.fetch(ctx, j)
	if err := r.publish(ctx, resp); err != nil {
		// Could not publish the response; NAK so it redelivers and we retry.
		r.log.Error("publish response failed; will redeliver", "id", j.ID, "err", err)
		_ = msg.Nak()
		return
	}
	_ = msg.Ack()
}

// fetch performs the HTTP request and ALWAYS returns a Response (error field set
// on failure).
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
		// Includes Netskope-enforced blocks surfacing as connection/TLS errors.
		out.Error = fmt.Sprintf("request failed: %v", err)
		return finish()
	}
	defer resp.Body.Close()

	out.Status = resp.StatusCode
	out.Headers = map[string][]string(resp.Header)

	// Enforce the inline body cap: read one extra byte to detect overflow.
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

func (r *Runner) publish(ctx context.Context, resp *job.Response) error {
	raw, err := resp.Marshal()
	if err != nil {
		return err
	}
	sealed, err := r.box.Seal(raw)
	if err != nil {
		return err
	}
	_, err = r.js.Publish(ctx, natsx.SubjectRespPrefix+resp.ID, sealed)
	return err
}

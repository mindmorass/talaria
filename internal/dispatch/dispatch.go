// Package dispatch is the A-side client: it seals a job to its scope's runner,
// publishes it (tagging the sender so the runner can authenticate), and collects
// the sealed response by id. The CLI's `send` uses Do; an LLM tool-call imports
// this package and uses the same methods.
package dispatch

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/neuralcolony/talaria/internal/crypto"
	"github.com/neuralcolony/talaria/internal/job"
	"github.com/neuralcolony/talaria/internal/natsx"
)

const defaultCollectWait = 35 * time.Second

// Client publishes jobs and collects responses for one scope.
type Client struct {
	js        jetstream.JetStream
	id        *crypto.Identity
	scope     natsx.Scope
	runnerPub string // the scope's runner public key (base64)
}

func New(js jetstream.JetStream, id *crypto.Identity, scope natsx.Scope, runnerPub string) *Client {
	return &Client{js: js, id: id, scope: scope, runnerPub: runnerPub}
}

// Do publishes the job and blocks until its response arrives or wait elapses.
func (c *Client) Do(ctx context.Context, j *job.Job, wait time.Duration) (*job.Response, error) {
	if err := c.Publish(ctx, j); err != nil {
		return nil, err
	}
	return c.Collect(ctx, j.ID, wait)
}

// Publish stamps the scope/sender, seals to the runner, and publishes.
func (c *Client) Publish(ctx context.Context, j *job.Job) error {
	if j.ID == "" {
		j.ID = job.NewID()
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now().UTC()
	}
	j.User = c.scope.User
	j.Profile = c.scope.Profile
	j.Sender = c.id.PublicB64()
	if err := j.Validate(); err != nil {
		return err
	}
	raw, err := j.Marshal()
	if err != nil {
		return err
	}
	sealed, err := c.id.SealTo(c.runnerPub, raw)
	if err != nil {
		return err
	}
	msg := &nats.Msg{
		Subject: c.scope.JobsSubject(),
		Data:    sealed,
		Header:  nats.Header{natsx.HeaderSender: []string{c.id.PublicB64()}},
	}
	_, err = c.js.PublishMsg(ctx, msg, jetstream.WithMsgID(j.ID))
	return err
}

// Collect waits for the response with the given id, opening it from the runner.
func (c *Client) Collect(ctx context.Context, id string, wait time.Duration) (*job.Response, error) {
	if wait <= 0 {
		wait = defaultCollectWait
	}
	cons, err := c.js.CreateConsumer(ctx, natsx.StreamResponses, jetstream.ConsumerConfig{
		FilterSubject:     c.scope.RespSubject(id),
		AckPolicy:         jetstream.AckNonePolicy,
		DeliverPolicy:     jetstream.DeliverAllPolicy,
		InactiveThreshold: 5 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("create collect consumer: %w", err)
	}
	batch, err := cons.Fetch(1, jetstream.FetchMaxWait(wait))
	if err != nil {
		return nil, fmt.Errorf("fetch response: %w", err)
	}
	for msg := range batch.Messages() {
		plain, err := c.id.OpenFrom(c.runnerPub, msg.Data())
		if err != nil {
			return nil, fmt.Errorf("open response: %w", err)
		}
		return job.UnmarshalResponse(plain)
	}
	if err := batch.Error(); err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}
	return nil, fmt.Errorf("timed out after %s waiting for response %s", wait, id)
}

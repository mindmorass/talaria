// Package dispatch is the A-side client: it seals a job, publishes it to the
// queue, and collects the sealed response by id. The CLI's `send` uses Do;
// an LLM tool-call imports this package and uses the same methods.
package dispatch

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/neuralcolony/talaria/internal/crypto"
	"github.com/neuralcolony/talaria/internal/job"
	"github.com/neuralcolony/talaria/internal/natsx"
)

const defaultCollectWait = 35 * time.Second

// Client publishes jobs and collects responses.
type Client struct {
	js  jetstream.JetStream
	box *crypto.Box
}

func New(js jetstream.JetStream, box *crypto.Box) *Client {
	return &Client{js: js, box: box}
}

// Do publishes the job and blocks until its response arrives or wait elapses.
// wait <= 0 uses the default.
func (c *Client) Do(ctx context.Context, j *job.Job, wait time.Duration) (*job.Response, error) {
	if err := c.Publish(ctx, j); err != nil {
		return nil, err
	}
	return c.Collect(ctx, j.ID, wait)
}

// Publish seals the job and publishes it, using the id as the dedup Msg-Id.
func (c *Client) Publish(ctx context.Context, j *job.Job) error {
	if j.ID == "" {
		j.ID = job.NewID()
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now().UTC()
	}
	if err := j.Validate(); err != nil {
		return err
	}
	raw, err := j.Marshal()
	if err != nil {
		return err
	}
	sealed, err := c.box.Seal(raw)
	if err != nil {
		return err
	}
	_, err = c.js.Publish(ctx, natsx.SubjectJobs, sealed, jetstream.WithMsgID(j.ID))
	return err
}

// Collect waits for the response with the given id. Because RESPONSES is
// durable, this works whether the response is already queued or arrives later.
func (c *Client) Collect(ctx context.Context, id string, wait time.Duration) (*job.Response, error) {
	if wait <= 0 {
		wait = defaultCollectWait
	}
	cons, err := c.js.CreateConsumer(ctx, natsx.StreamResponses, jetstream.ConsumerConfig{
		FilterSubject:     natsx.SubjectRespPrefix + id,
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
		plain, err := c.box.Open(msg.Data())
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

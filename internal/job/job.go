// Package job defines the wire envelopes exchanged between the Talaria
// dispatcher (A) and runner (C). These types are the single source of truth for
// the message shape; both roles serialize through them so they cannot drift.
//
// The envelope is marshaled to JSON and then SEALED (see internal/crypto) before
// it ever touches the queue, so the queue (B) only stores ciphertext. []byte
// fields marshal as base64 in JSON automatically.
package job

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Job is a single HTTP request for the runner to execute from C's network.
type Job struct {
	ID        string              `json:"id"`
	Method    string              `json:"method"`
	URL       string              `json:"url"`
	Headers   map[string][]string `json:"headers,omitempty"`
	Body      []byte              `json:"body,omitempty"`
	TimeoutMS int                 `json:"timeout_ms,omitempty"`
	CreatedAt time.Time           `json:"created_at"`
}

// Response is the result of executing a Job. On failure, Error is set and the
// HTTP fields may be zero — the runner ALWAYS returns a Response so the
// dispatcher never blocks forever.
type Response struct {
	ID         string              `json:"id"`
	Status     int                 `json:"status,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       []byte              `json:"body,omitempty"`
	Error      string              `json:"error,omitempty"`
	Bytes      int                 `json:"bytes"`
	DurationMS int64               `json:"duration_ms"`
	FinishedAt time.Time           `json:"finished_at"`
}

// NewID returns an opaque 128-bit random id as 32 hex chars. It is the only part
// of a message that travels in cleartext (as the NATS subject component), so it
// must reveal nothing — a random value does.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("talaria: cannot read randomness: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// Validate checks the minimum fields the runner needs to act.
func (j *Job) Validate() error {
	if j.ID == "" {
		return fmt.Errorf("job: empty id")
	}
	if j.Method == "" {
		return fmt.Errorf("job: empty method")
	}
	if j.URL == "" {
		return fmt.Errorf("job: empty url")
	}
	return nil
}

func (j *Job) Marshal() ([]byte, error)      { return json.Marshal(j) }
func (r *Response) Marshal() ([]byte, error) { return json.Marshal(r) }

func UnmarshalJob(b []byte) (*Job, error) {
	var j Job
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

func UnmarshalResponse(b []byte) (*Response, error) {
	var r Response
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

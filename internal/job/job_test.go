package job

import (
	"bytes"
	"testing"
	"time"
)

func TestJobRoundTripWithBinaryBody(t *testing.T) {
	in := &Job{
		ID:        NewID(),
		Method:    "POST",
		URL:       "https://example.com/x",
		Headers:   map[string][]string{"User-Agent": {"Mozilla/5.0"}, "X-Multi": {"a", "b"}},
		Body:      []byte{0x00, 0x01, 0xff, 0xfe, 0x7f}, // non-UTF8 to prove base64 safety
		TimeoutMS: 5000,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnmarshalJob(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.ID != in.ID || out.Method != in.Method || out.URL != in.URL {
		t.Fatalf("scalar mismatch: %+v", out)
	}
	if !bytes.Equal(out.Body, in.Body) {
		t.Fatalf("body mismatch: %v != %v", out.Body, in.Body)
	}
	if len(out.Headers["X-Multi"]) != 2 {
		t.Fatalf("multi-header lost: %v", out.Headers)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	in := &Response{ID: NewID(), Status: 200, Body: []byte("hello"), Bytes: 5, DurationMS: 12}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnmarshalResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != 200 || !bytes.Equal(out.Body, []byte("hello")) {
		t.Fatalf("mismatch: %+v", out)
	}
}

func TestNewIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if len(id) != 32 {
			t.Fatalf("bad id len %d", len(id))
		}
		if seen[id] {
			t.Fatalf("collision %s", id)
		}
		seen[id] = true
	}
}

func TestValidate(t *testing.T) {
	if err := (&Job{ID: "x", Method: "GET", URL: "http://a"}).Validate(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if err := (&Job{Method: "GET", URL: "http://a"}).Validate(); err == nil {
		t.Fatal("expected error for empty id")
	}
}

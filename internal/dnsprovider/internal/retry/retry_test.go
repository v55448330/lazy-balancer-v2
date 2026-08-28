package retry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// countingTransport returns scripted status codes, then a final 200. It
// records each request body so replay correctness can be asserted.
type countingTransport struct {
	statuses []int
	attempts int
	bodies   []string
}

func (t *countingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if closeErr := request.Body.Close(); closeErr != nil {
		return nil, closeErr
	}
	t.bodies = append(t.bodies, string(body))
	status := http.StatusOK
	if t.attempts < len(t.statuses) {
		status = t.statuses[t.attempts]
	}
	t.attempts++
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"1"}}`)),
		Request:    request,
	}, nil
}

// retryAfterTransport decorates responses from next with a Retry-After header.
type retryAfterTransport struct {
	next http.RoundTripper
}

func (t *retryAfterTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	resp.Header.Set("Retry-After", strconv.Itoa(3600))
	return resp, nil
}

func newRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://dns.example/Record.Create", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return req
}

func TestTransport_retries_transient_5xx_then_succeeds(t *testing.T) {
	// Given: first two attempts return 500/502, third returns 200
	base := &countingTransport{statuses: []int{http.StatusInternalServerError, http.StatusBadGateway}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if base.attempts != 3 {
		t.Fatalf("attempts=%d, want 3", base.attempts)
	}
}

func TestTransport_replays_identical_body(t *testing.T) {
	// Given: a retried POST whose body must be replayed byte-for-byte
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequest(t, "value=abc&ttl=600"))

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if len(base.bodies) != 2 {
		t.Fatalf("attempts=%d, want 2", len(base.bodies))
	}
	if base.bodies[0] != base.bodies[1] {
		t.Fatalf("replayed body %q differs from original %q", base.bodies[1], base.bodies[0])
	}
}

func TestTransport_returns_last_response_when_attempts_exhausted(t *testing.T) {
	// Given: persistent 429 responses
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))

	// Then: the final 429 is returned, not turned into an error
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429", resp.StatusCode)
	}
	if base.attempts != 3 {
		t.Fatalf("attempts=%d, want 3", base.attempts)
	}
}

func TestTransport_does_not_retry_client_errors(t *testing.T) {
	// Given: a plain 404
	base := &countingTransport{statuses: []int{http.StatusNotFound}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if base.attempts != 1 {
		t.Fatalf("attempts=%d, want 1", base.attempts)
	}
}

func TestTransport_caps_wait_at_max_backoff(t *testing.T) {
	// Given: 429 with a huge Retry-After; MaxBackoff clamps the wait
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests}}
	transport := &Transport{Base: &retryAfterTransport{next: base}, InitialBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}

	start := time.Now()

	// When
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))
	elapsed := time.Since(start)

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if elapsed > time.Second {
		t.Fatalf("elapsed=%v, want capped well below 1s", elapsed)
	}
	if base.attempts != 2 {
		t.Fatalf("attempts=%d, want 2", base.attempts)
	}
}

func TestTransport_stops_on_context_cancellation(t *testing.T) {
	// Given: a 429 response followed by a long backoff, and an already
	// cancelled context
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests, http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: 10 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://dns.example/Record.Create", strings.NewReader("value=abc"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	// When
	resp, err := transport.RoundTrip(req)

	// Then
	if err == nil {
		resp.Body.Close()
		t.Fatal("round trip succeeded, want context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	if base.attempts != 1 {
		t.Fatalf("attempts=%d, want 1 (no retry after cancellation)", base.attempts)
	}
}

func TestRetryable_classifies_status(t *testing.T) {
	// Given/When/Then
	for _, status := range []int{429, 500, 502, 503, 504} {
		if !Retryable(status) {
			t.Fatalf("status %d should be retryable", status)
		}
	}
	for _, status := range []int{200, 301, 400, 401, 403, 404, 422} {
		if Retryable(status) {
			t.Fatalf("status %d should not be retryable", status)
		}
	}
}

func TestAfter_parses_retry_after_header(t *testing.T) {
	// Given/When/Then: seconds form
	if got := After("2"); got != 2*time.Second {
		t.Fatalf("After(\"2\")=%v, want 2s", got)
	}
	// HTTP-date form in the near future
	future := time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)
	if got := After(future); got <= 0 || got > 3*time.Second {
		t.Fatalf("After(date)=%v, want within (0,3s]", got)
	}
	// garbage and past dates yield zero
	if got := After("not-a-date"); got != 0 {
		t.Fatalf("After(garbage)=%v, want 0", got)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := After(past); got != 0 {
		t.Fatalf("After(past)=%v, want 0", got)
	}
	if got := After(""); got != 0 {
		t.Fatalf("After(empty)=%v, want 0", got)
	}
}

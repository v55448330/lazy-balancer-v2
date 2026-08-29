package tencent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsprovider/internal/retry"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

type recordTransport struct {
	mu      sync.Mutex
	records map[uint64]string
	nextID  uint64
}

func (transport *recordTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	responseBody := `{"Response":{"RequestId":"test"}}`
	transport.mu.Lock()
	switch request.Header.Get("X-TC-Action") {
	case "CreateRecord":
		transport.nextID++
		recordID := 199 + transport.nextID
		transport.records[recordID] = "owned"
		responseBody = fmt.Sprintf(`{"Response":{"RecordId":%d,"RequestId":"test"}}`, recordID)
	case "DeleteRecord":
		var payload struct {
			RecordID uint64 `json:"RecordId"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			transport.mu.Unlock()
			return nil, err
		}
		delete(transport.records, payload.RecordID)
	}
	transport.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

// flakyRecordTransport answers the first failCount requests of failAction
// with an HTTP failure status, then behaves like recordTransport.
type flakyRecordTransport struct {
	recordTransport
	failAction string
	failStatus int
	failCount  int
	attempts   int
}

func (transport *flakyRecordTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	transport.attempts++
	failing := request.Header.Get("X-TC-Action") == transport.failAction && transport.attempts <= transport.failCount
	status := transport.failStatus
	transport.mu.Unlock()
	if failing {
		if _, err := io.ReadAll(request.Body); err != nil {
			return nil, err
		}
		if closeErr := request.Body.Close(); closeErr != nil {
			return nil, closeErr
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"Response":{"Error":{"Code":"InternalError","Message":"transient"}}}`)),
			Request:    request,
		}, nil
	}
	return transport.recordTransport.RoundTrip(request)
}

// missingRecordTransport answers DeleteRecord with Tencent's
// ResourceNotFound.NoDataOfRecord API error envelope.
type missingRecordTransport struct {
	recordTransport
}

func (transport *missingRecordTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Header.Get("X-TC-Action") == "DeleteRecord" {
		if _, err := io.ReadAll(request.Body); err != nil {
			return nil, err
		}
		if closeErr := request.Body.Close(); closeErr != nil {
			return nil, closeErr
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"Response":{"Error":{"Code":"ResourceNotFound.NoDataOfRecord","Message":"记录不存在"},"RequestId":"test"}}`)),
			Request:    request,
		}, nil
	}
	return transport.recordTransport.RoundTrip(request)
}

type blockingTransport struct {
	started chan struct{}
}

func (transport *blockingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	close(transport.started)
	<-request.Context().Done()
	return nil, request.Context().Err()
}

func TestProvider_Present_returns_when_context_is_canceled(t *testing.T) {
	// Given
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	transport := &blockingTransport{started: make(chan struct{})}
	provider.client.WithHttpTransport(transport)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "value", 600)
	}()
	<-transport.started

	// When
	cancel()

	// Then
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("present error=%v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Tencent request did not return after context cancellation")
	}
}

func TestProvider_CleanUp_deletes_persisted_record_after_restart(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	transport := &recordTransport{records: map[uint64]string{100: "another-task"}}
	first, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	first.client.WithHttpTransport(transport)
	if err := first.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "this-task", 600); err != nil {
		t.Fatalf("present persisted record: %v", err)
	}
	restarted, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("restart persistent provider: %v", err)
	}
	restarted.client.WithHttpTransport(transport)

	// When
	err = restarted.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then
	if err != nil {
		t.Fatalf("clean up persisted record: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.records) != 1 || transport.records[100] != "another-task" {
		t.Fatalf("remaining records=%v, want only unrelated record", transport.records)
	}
}

func TestProvider_Present_retries_transient_5xx(t *testing.T) {
	// Given: CreateRecord hits a 502 then succeeds; the retrying transport
	// (the provider's production wiring) absorbs the transient failure
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	transport := &flakyRecordTransport{failAction: "CreateRecord", failStatus: http.StatusBadGateway, failCount: 1}
	transport.records = map[uint64]string{100: "another-task"}
	provider.client.WithHttpTransport(&retry.Transport{Base: transport, InitialBackoff: time.Millisecond})

	// When
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present: %v", err)
	}

	// Then
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.attempts != 2 {
		t.Fatalf("attempts=%d, want 2", transport.attempts)
	}
}

func TestProvider_CleanUp_retries_transient_429(t *testing.T) {
	// Given: DeleteRecord hits a 429 then succeeds
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	transport := &flakyRecordTransport{failAction: "DeleteRecord", failStatus: http.StatusTooManyRequests, failCount: 1}
	transport.records = map[uint64]string{100: "another-task"}
	provider.client.WithHttpTransport(&retry.Transport{Base: transport, InitialBackoff: time.Millisecond})
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present: %v", err)
	}

	// When
	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then
	if err != nil {
		t.Fatalf("clean up: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.records) != 1 || transport.records[100] != "another-task" {
		t.Fatalf("remaining records=%v, want only unrelated record", transport.records)
	}
}

func TestProvider_CleanUp_treats_missing_record_as_success(t *testing.T) {
	// Given: the TXT record was already removed, so DeleteRecord answers
	// with the ResourceNotFound.NoDataOfRecord error envelope
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	transport := &missingRecordTransport{}
	transport.records = map[uint64]string{}
	provider.client.WithHttpTransport(transport)
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present record: %v", err)
	}

	// When
	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then: cleanup stays idempotent despite the not-found error
	if err != nil {
		t.Fatalf("clean up missing record: %v", err)
	}
}

func TestProvider_CleanUpValue_deletes_only_own_record(t *testing.T) {
	// Given: two concurrent issuances presented different values for the
	// same challenge name (persistent ownership, shared file)
	dataDir := t.TempDir()
	transport := &recordTransport{records: map[uint64]string{}}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "alpha", 600); err != nil {
		t.Fatalf("present alpha: %v", err)
	}
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "beta", 600); err != nil {
		t.Fatalf("present beta: %v", err)
	}

	// When: the alpha issuance cleans up by value
	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "alpha"); err != nil {
		t.Fatalf("clean up alpha: %v", err)
	}

	// Then: only alpha's record was deleted; beta's record survives
	transport.mu.Lock()
	remaining := len(transport.records)
	transport.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("remaining records=%d, want 1 (beta)", remaining)
	}
}

func TestProvider_CleanUpValue_memory_mode_tracks_values(t *testing.T) {
	// Given: memory-mode ownership with two same-name records of different
	// values
	transport := &recordTransport{records: map[uint64]string{}}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "alpha", 600); err != nil {
		t.Fatalf("present alpha: %v", err)
	}
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "beta", 600); err != nil {
		t.Fatalf("present beta: %v", err)
	}

	// When
	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "beta"); err != nil {
		t.Fatalf("clean up beta: %v", err)
	}

	// Then: alpha's record survives
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.records) != 1 {
		t.Fatalf("remaining records=%v, want only alpha's record", transport.records)
	}
}

// slowFlakyTransport answers the first failCount CreateRecord calls with a
// slow 5xx response, then behaves like recordTransport.
type slowFlakyTransport struct {
	recordTransport
	failCount int
	attempts  int
	delay     time.Duration
}

func (transport *slowFlakyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	transport.attempts++
	failing := request.Header.Get("X-TC-Action") == "CreateRecord" && transport.attempts <= transport.failCount
	transport.mu.Unlock()
	time.Sleep(transport.delay)
	if failing {
		if _, err := io.ReadAll(request.Body); err != nil {
			return nil, err
		}
		if closeErr := request.Body.Close(); closeErr != nil {
			return nil, closeErr
		}
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"Response":{"Error":{"Code":"InternalError","Message":"transient"}}}`)),
			Request:    request,
		}, nil
	}
	return transport.recordTransport.RoundTrip(request)
}

func TestProvider_Present_survives_slow_5xx_sequence(t *testing.T) {
	// Given: a slow 502,502,200 sequence replayed inside the SDK client's
	// request timeout, which must cover the whole retry envelope rather than
	// cutting the backoff loop short
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	transport := &slowFlakyTransport{failCount: 2, delay: 100 * time.Millisecond}
	transport.records = map[uint64]string{100: "another-task"}
	provider.client.WithHttpTransport(&retry.Transport{Base: transport, InitialBackoff: time.Millisecond})

	// When
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present: %v", err)
	}

	// Then: the delayed retry sequence completes within the client timeout
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.attempts != 3 {
		t.Fatalf("attempts=%d, want 3", transport.attempts)
	}
}

// deleteFailTransport fails DeleteRecord for one specific record ID while
// every other deletion succeeds.
type deleteFailTransport struct {
	recordTransport
	failRecordID uint64
}

func (transport *deleteFailTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if closeErr := request.Body.Close(); closeErr != nil {
		return nil, closeErr
	}
	if request.Header.Get("X-TC-Action") == "DeleteRecord" {
		var payload struct {
			RecordID uint64 `json:"RecordId"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}
		if payload.RecordID == transport.failRecordID {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"Response":{"Error":{"Code":"UnauthorizedOperation","Message":"无权限"},"RequestId":"test"}}`)),
				Request:    request,
			}, nil
		}
	}
	request.Body = io.NopCloser(strings.NewReader(string(body)))
	return transport.recordTransport.RoundTrip(request)
}

func TestProvider_CleanUp_removes_ownership_of_independently_deleted_records(t *testing.T) {
	// Given: two persisted records under one challenge name; the DNS API
	// fails deleting record 200 but succeeds deleting record 201
	dataDir := t.TempDir()
	transport := &deleteFailTransport{recordTransport: recordTransport{records: map[uint64]string{}}, failRecordID: 200}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "alpha", 600); err != nil {
		t.Fatalf("present alpha: %v", err)
	}
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "beta", 600); err != nil {
		t.Fatalf("present beta: %v", err)
	}

	// When
	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then: the record 200 failure is reported, yet record 201 — which WAS
	// deleted at the API — loses its ownership entry; an earlier miss must
	// not orphan later already-deleted records
	if err == nil {
		t.Fatal("clean up swallowed the record 200 deletion failure")
	}
	transport.mu.Lock()
	_, record201Alive := transport.records[201]
	transport.mu.Unlock()
	if record201Alive {
		t.Fatal("record 201 was not deleted at the API")
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	left, err := store.Matching("tencent", "example.com", "_acme-challenge.example.com.")
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 1 || left[0].RecordID != "200" {
		t.Fatalf("ownership left=%+v, want only the failed record 200", left)
	}
}

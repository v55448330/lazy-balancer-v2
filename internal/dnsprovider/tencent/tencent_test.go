package tencent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordTransport struct {
	mu      sync.Mutex
	records map[uint64]string
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
		transport.records[200] = "owned"
		responseBody = `{"Response":{"RecordId":200,"RequestId":"test"}}`
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

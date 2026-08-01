package dnspod

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type dnsPodRecordTransport struct {
	mu      sync.Mutex
	records map[string]string
}

func (transport *dnsPodRecordTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	responseBody := `{"status":{"code":"1","message":"ok"}}`
	transport.mu.Lock()
	switch {
	case strings.HasSuffix(request.URL.Path, "Domain.List"):
		responseBody = `{"status":{"code":"1","message":"ok"},"domains":[{"id":"1","name":"example.com"}]}`
	case strings.HasSuffix(request.URL.Path, "Record.Create"):
		transport.records["200"] = params.Get("value")
		responseBody = `{"status":{"code":"1","message":"ok"},"record":{"id":"200"}}`
	case strings.HasSuffix(request.URL.Path, "Record.Remove"):
		delete(transport.records, params.Get("record_id"))
	}
	transport.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

func TestProvider_CleanUp_deletes_only_record_created_by_provider(t *testing.T) {
	// Given
	transport := &dnsPodRecordTransport{records: map[string]string{"100": "another-task"}}
	provider := New("id,token")
	provider.client.Transport = transport
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "this-task", 600); err != nil {
		t.Fatalf("present owned record: %v", err)
	}

	// When
	err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then
	if err != nil {
		t.Fatalf("clean up owned record: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.records) != 1 || transport.records["100"] != "another-task" {
		t.Fatalf("remaining records=%v, want only unrelated record", transport.records)
	}
}

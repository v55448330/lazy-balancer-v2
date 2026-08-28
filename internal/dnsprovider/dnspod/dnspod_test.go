package dnspod

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsprovider/internal/retry"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

type dnsPodRecordTransport struct {
	mu      sync.Mutex
	records map[string]string
	nextID  int
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
		transport.nextID++
		recordID := strconv.Itoa(199 + transport.nextID)
		transport.records[recordID] = params.Get("value")
		responseBody = fmt.Sprintf(`{"status":{"code":"1","message":"ok"},"record":{"id":%q}}`, recordID)
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

func TestProvider_CleanUp_deletes_persisted_record_after_restart(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	transport := &dnsPodRecordTransport{records: map[string]string{"100": "another-task"}}
	first, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	first.client.Transport = transport
	if err := first.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "this-task", 600); err != nil {
		t.Fatalf("present persisted record: %v", err)
	}
	restarted, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("restart persistent provider: %v", err)
	}
	restarted.client.Transport = transport

	// When
	err = restarted.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then
	if err != nil {
		t.Fatalf("clean up persisted record: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.records) != 1 || transport.records["100"] != "another-task" {
		t.Fatalf("remaining records=%v, want only unrelated record", transport.records)
	}
}

// paginatedTransport serves Domain.List from a scripted domain list,
// honoring the offset parameter and capping each response page at pageSize
// entries (mimicking the DNSPod API's server-side pagination).
type paginatedTransport struct {
	mu       sync.Mutex
	domains  []string
	pageSize int
	requests []url.Values
}

func (transport *paginatedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if closeErr := request.Body.Close(); closeErr != nil {
		return nil, closeErr
	}
	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	transport.requests = append(transport.requests, params)
	responseBody := `{"status":{"code":"1","message":"ok"}}`
	if strings.HasSuffix(request.URL.Path, "Domain.List") {
		offset, _ := strconv.Atoi(params.Get("offset"))
		end := offset + transport.pageSize
		if end > len(transport.domains) {
			end = len(transport.domains)
		}
		var entries []string
		for i := offset; i < end; i++ {
			entries = append(entries, fmt.Sprintf(`{"id":%d,"name":%q}`, i+1, transport.domains[i]))
		}
		responseBody = fmt.Sprintf(
			`{"status":{"code":"1","message":"ok"},"domains":[%s],"info":{"domain_total":%d}}`,
			strings.Join(entries, ","), len(transport.domains))
	}
	transport.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

func TestProvider_getDomainID_paginates_beyond_first_page(t *testing.T) {
	// Given: more domains than one DNSPod response page, with the target
	// zone on the last page
	domains := make([]string, 25)
	for i := range domains {
		domains[i] = fmt.Sprintf("zone-%02d.example.com", i)
	}
	domains[24] = "example.com"
	transport := &paginatedTransport{domains: domains, pageSize: 7}
	provider := New("id,token")
	provider.client.Transport = transport

	// When
	domainID, err := provider.getDomainID(t.Context(), "example.com")

	// Then
	if err != nil {
		t.Fatalf("get domain id: %v", err)
	}
	if domainID != "25" {
		t.Fatalf("domainID=%q, want 25", domainID)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.requests) < 4 {
		t.Fatalf("requests=%d, want at least 4 pages", len(transport.requests))
	}
	for index, request := range transport.requests {
		if request.Get("offset") != strconv.Itoa(index*7) {
			t.Fatalf("request %d offset=%q, want %d", index, request.Get("offset"), index*7)
		}
	}
}

func TestProvider_getDomainID_paginates_large_accounts(t *testing.T) {
	// Given: an account with more domains than the DNSPod hard page cap
	// (3000); the target sits past the first page
	domains := make([]string, 3001)
	for i := range domains {
		domains[i] = fmt.Sprintf("zone-%04d.example.com", i)
	}
	domains[3000] = "example.com"
	transport := &paginatedTransport{domains: domains, pageSize: 3000}
	provider := New("id,token")
	provider.client.Transport = transport

	// When
	domainID, err := provider.getDomainID(t.Context(), "example.com")

	// Then
	if err != nil {
		t.Fatalf("get domain id: %v", err)
	}
	if domainID != "3001" {
		t.Fatalf("domainID=%q, want 3001", domainID)
	}
}

func TestProvider_getDomainID_not_found_after_all_pages(t *testing.T) {
	// Given: the zone is not in the account at all
	domains := []string{"a.example.com", "b.example.com"}
	transport := &paginatedTransport{domains: domains, pageSize: 1}
	provider := New("id,token")
	provider.client.Transport = transport

	// When
	_, err := provider.getDomainID(t.Context(), "missing.com")

	// Then
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err=%v, want domain not found", err)
	}
}

// flakyTransport answers the first failCount requests with failStatus, then
// with the DNSPod success envelope.
type flakyTransport struct {
	mu         sync.Mutex
	failStatus int
	failCount  int
	attempts   int
}

func (transport *flakyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if _, err := io.ReadAll(request.Body); err != nil {
		return nil, err
	}
	if closeErr := request.Body.Close(); closeErr != nil {
		return nil, closeErr
	}
	transport.mu.Lock()
	transport.attempts++
	failing := transport.attempts <= transport.failCount
	status := transport.failStatus
	transport.mu.Unlock()

	responseBody := `{"status":{"code":"1","message":"ok"},"record":{"id":"200"}}`
	if strings.HasSuffix(request.URL.Path, "Domain.List") {
		responseBody = `{"status":{"code":"1","message":"ok"},"domains":[{"id":"1","name":"example.com"}],"info":{"domain_total":1}}`
	}
	if failing {
		responseBody = `{"status":{"code":"-1","message":"transient"}}`
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(responseBody)),
			Request:    request,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

func TestProvider_apiCall_retries_transient_failures(t *testing.T) {
	// Given: transient HTTP failures precede a success; the retrying
	// transport (the provider's production wiring) must absorb them
	testCases := []struct {
		name     string
		statuses []int
	}{
		{name: "500 then success", statuses: []int{http.StatusInternalServerError}},
		{name: "429 then success", statuses: []int{http.StatusTooManyRequests}},
		{name: "503 twice then success", statuses: []int{http.StatusServiceUnavailable, http.StatusServiceUnavailable}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			provider := New("id,token")
			transport := &flakyTransport{failCount: len(testCase.statuses), failStatus: testCase.statuses[len(testCase.statuses)-1]}
			provider.client.Transport = &retry.Transport{
				Base:           transport,
				InitialBackoff: time.Millisecond,
			}

			// When
			err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

			// Then: without the retrying transport the first transient
			// response would already fail the challenge
			if err != nil {
				t.Fatalf("present: %v", err)
			}
			transport.mu.Lock()
			defer transport.mu.Unlock()
			if transport.attempts < len(testCase.statuses)+1 {
				t.Fatalf("attempts=%d, want at least %d (failures retried)", transport.attempts, len(testCase.statuses)+1)
			}
		})
	}
}

// missingRecordTransport makes Record.Remove answer with DNSPod's
// record-ID-error body code (8) instead of deleting.
type missingRecordTransport struct {
	dnsPodRecordTransport
}

func (transport *missingRecordTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, "Record.Remove") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"8","message":"记录ID错误"}}`)),
			Request:    request,
		}, nil
	}
	return transport.dnsPodRecordTransport.RoundTrip(request)
}

func TestProvider_CleanUp_treats_missing_record_as_success(t *testing.T) {
	// Given: the TXT record was already removed, so Record.Remove answers
	// body code 8 (记录ID错误)
	transport := &missingRecordTransport{dnsPodRecordTransport{records: map[string]string{}}}
	provider := New("id,token")
	provider.client.Transport = transport
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present record: %v", err)
	}

	// When
	err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then: cleanup stays idempotent despite the not-found response
	if err != nil {
		t.Fatalf("clean up missing record: %v", err)
	}
}

func TestProvider_CleanUpValue_deletes_only_own_record(t *testing.T) {
	// Given: two concurrent issuances presented different values for the
	// same challenge name (persistent ownership, shared file)
	dataDir := t.TempDir()
	transport := &dnsPodRecordTransport{records: map[string]string{}}
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport
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
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	left, err := store.Matching("dnspod", "example.com", "_acme-challenge.example.com.")
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 1 || left[0].Value != "beta" {
		t.Fatalf("ownership left=%+v, want beta only", left)
	}
}

func TestProvider_CleanUpValue_memory_mode_tracks_values(t *testing.T) {
	// Given: memory-mode ownership with two same-name records of different
	// values
	transport := &dnsPodRecordTransport{records: map[string]string{}}
	provider := New("id,token")
	provider.client.Transport = transport
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
	if len(transport.records) != 1 || transport.records["200"] != "alpha" {
		t.Fatalf("remaining records=%v, want only alpha/200", transport.records)
	}
}

func TestProvider_CleanUpValue_removes_stale_ownership_entries(t *testing.T) {
	// Given: an ownership file containing a provably stale record from an
	// abandoned order, alongside a fresh record of another value
	dataDir := t.TempDir()
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	transport := &dnsPodRecordTransport{records: map[string]string{"100": "abandoned", "200": "beta"}}
	provider.client.Transport = transport
	ownershipPath := filepath.Join(dataDir, "acme_dns_ownership.json")
	raw := fmt.Sprintf(`{"version":1,"records":[
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com.","value":"abandoned","record_id":"100","created_at":%q},
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com.","value":"beta","record_id":"200","created_at":%q}
	]}`,
		time.Now().Add(-90*time.Minute).UTC().Format(time.RFC3339),
		time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(ownershipPath, []byte(raw), 0600); err != nil {
		t.Fatalf("seed ownership file: %v", err)
	}

	// When: a new issuance cleans up its own value
	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "gamma"); err != nil {
		t.Fatalf("clean up gamma: %v", err)
	}

	// Then: the stale abandoned record was removed; the fresh beta record
	// (possible live concurrent challenge) was spared
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if _, exists := transport.records["100"]; exists {
		t.Fatal("stale record 100 was not deleted")
	}
	if _, exists := transport.records["200"]; !exists {
		t.Fatal("fresh concurrent record 200 must be spared")
	}
}

func TestNew_wires_retrying_transport(t *testing.T) {
	// Given/When
	provider := New("id,token")

	// Then: transient 429/5xx failures are retried by the default wiring
	if _, ok := provider.client.Transport.(*retry.Transport); !ok {
		t.Fatalf("default transport=%T, want *retry.Transport", provider.client.Transport)
	}
}

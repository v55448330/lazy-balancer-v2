package dnspod

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
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
	// CERT40-4:清进程内 zone 缓存——前序用例可能已缓存同名 zone。
	domainIDCacheMu.Lock()
	domainIDCache = map[string]string{}
	domainIDCacheMu.Unlock()
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
	// CERT40-4:清进程内 zone 缓存——前序用例可能已缓存同名 zone。
	domainIDCacheMu.Lock()
	domainIDCache = map[string]string{}
	domainIDCacheMu.Unlock()
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

// flakyTransport answers the first failCount requests of failPath with
// failStatus, then with the DNSPod success envelope.
type flakyTransport struct {
	mu         sync.Mutex
	failStatus int
	failCount  int
	failPath   string
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
	// F50-6：失败注入限定 failPath 动作——创建类 5xx 不再重放（见
	// TestProvider_Present_does_not_replay_create_on_5xx），接线本意
	// 「瞬时故障重试」由非创建动作承载。
	failing := transport.attempts <= transport.failCount && strings.HasSuffix(request.URL.Path, transport.failPath)
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
	// Given: transient HTTP failures on the non-create Domain.List action
	// precede a success; the retrying transport (the provider's production
	// wiring) must absorb them
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
			// 包级 domainID 缓存按账户共享——清空以保证 Domain.List 真实走线。
			seedDomainIDCache(t, "id,token", map[string]string{})
			provider := New("id,token")
			transport := &flakyTransport{failCount: len(testCase.statuses), failStatus: testCase.statuses[len(testCase.statuses)-1], failPath: "Domain.List"}
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

// F50-6（第 50 轮审计）：Record.Create 命中 5xx 不得重放——创建响应丢失时
// 重试会产生无 ID 幽灵 TXT（ownership 清理只按记录 ID 删除），首个 5xx
// 原样上抛、创建动作单次调用。
func TestProvider_Present_does_not_replay_create_on_5xx(t *testing.T) {
	// Given：Domain.List 正常、Record.Create 持续 500
	// （清空包级 domainID 缓存，保证 Domain.List 真实走线）
	seedDomainIDCache(t, "id,token", map[string]string{})
	provider := New("id,token")
	transport := &flakyTransport{failCount: 5, failStatus: http.StatusInternalServerError, failPath: "Record.Create"}
	provider.client.Transport = &retry.Transport{
		Base:           transport,
		InitialBackoff: time.Millisecond,
	}

	// When
	err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	// Then：500 直接失败且创建只调用一次（Domain.List 一次 + Create 一次）
	if err == nil {
		t.Fatal("present succeeded, want 500 surfaced（创建类 5xx 不重放）")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.attempts != 2 {
		t.Fatalf("attempts=%d, want 2（Domain.List 一次 + Record.Create 单次不重放）", transport.attempts)
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

func TestNew_client_timeout_covers_retry_envelope(t *testing.T) {
	// Given/When
	provider := New("id,token")

	// Then: http.Client.Timeout spans the whole retry loop (3 attempts plus
	// backoff/Retry-After waits capped at 30s each), so it must exceed that
	// envelope instead of cutting it short
	if provider.client.Timeout < 90*time.Second {
		t.Fatalf("client timeout=%v, want >= 90s retry-envelope headroom", provider.client.Timeout)
	}
}

// removeFailTransport fails Record.Remove for one specific record ID while
// every other removal succeeds.
type removeFailTransport struct {
	dnsPodRecordTransport
	failRecordID string
}

func (transport *removeFailTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if closeErr := request.Body.Close(); closeErr != nil {
		return nil, closeErr
	}
	if strings.HasSuffix(request.URL.Path, "Record.Remove") {
		params, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		if params.Get("record_id") == transport.failRecordID {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"7","message":"没有权限"}}`)),
				Request:    request,
			}, nil
		}
	}
	request.Body = io.NopCloser(strings.NewReader(string(body)))
	return transport.dnsPodRecordTransport.RoundTrip(request)
}

func TestProvider_CleanUp_removes_ownership_of_independently_deleted_records(t *testing.T) {
	// Given: two persisted records under one challenge name; the DNS API
	// fails deleting record 200 but succeeds deleting record 201
	dataDir := t.TempDir()
	transport := &removeFailTransport{dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{}}, failRecordID: "200"}
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

	// When
	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then: the record 200 failure is reported, yet record 201 — which WAS
	// deleted at the API — loses its ownership entry; an earlier miss must
	// not orphan later already-deleted records
	if err == nil {
		t.Fatal("clean up swallowed the record 200 deletion failure")
	}
	transport.mu.Lock()
	_, record201Alive := transport.records["201"]
	transport.mu.Unlock()
	if record201Alive {
		t.Fatal("record 201 was not deleted at the API")
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	left, err := store.Matching("dnspod", "example.com", "_acme-challenge.example.com.")
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 1 || left[0].RecordID != "200" {
		t.Fatalf("ownership left=%+v, want only the failed record 200", left)
	}
}

// staleRemoveTransport 模拟 cleanUp 阶段的陈旧 zone→domain_id（U5-1）：
// Domain.List 恒返回 currentID；Record.Remove 对 staleID 报「域名不存在」
// （code 7），对 currentID 默认删除成功（failFreshID 时改报非域名类错误）。
// 记录每次 Remove 的 {domain_id, record_id} 与 Domain.List 调用数。
type staleRemoveTransport struct {
	mu          sync.Mutex
	currentID   string
	staleID     string
	failFreshID bool
	records     map[string]string
	nextID      int
	removes     [][2]string
	listCalls   int
}

func (transport *staleRemoveTransport) RoundTrip(request *http.Request) (*http.Response, error) {
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
	responseBody := `{"status":{"code":"1","message":"ok"}}`
	transport.mu.Lock()
	switch {
	case strings.HasSuffix(request.URL.Path, "Domain.List"):
		transport.listCalls++
		responseBody = fmt.Sprintf(`{"status":{"code":"1","message":"ok"},"domains":[{"id":%q,"name":"example.com"}],"info":{"domain_total":1}}`, transport.currentID)
	case strings.HasSuffix(request.URL.Path, "Record.Create"):
		transport.nextID++
		recordID := strconv.Itoa(299 + transport.nextID)
		transport.records[recordID] = params.Get("value")
		responseBody = fmt.Sprintf(`{"status":{"code":"1","message":"ok"},"record":{"id":%q}}`, recordID)
	case strings.HasSuffix(request.URL.Path, "Record.Remove"):
		removal := [2]string{params.Get("domain_id"), params.Get("record_id")}
		transport.removes = append(transport.removes, removal)
		switch {
		case removal[0] == transport.staleID:
			responseBody = `{"status":{"code":"7","message":"域名不存在"}}`
		case transport.failFreshID:
			responseBody = `{"status":{"code":"11","message":"没有权限"}}`
		default:
			delete(transport.records, removal[1])
		}
	}
	transport.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

// flipStaleDomain 把已缓存的 id 变为陈旧值：API 侧域名重建为 freshID，对旧
// cachedID 的删除报「域名不存在」；failFresh 置位时对 freshID 的删除也失败。
func (transport *staleRemoveTransport) flipStaleDomain(cachedID, freshID string, failFresh bool) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.staleID = cachedID
	transport.currentID = freshID
	transport.failFreshID = failFresh
}

// U5-1（第 45 轮审计）：cleanUp 侧的 CERT42-7 同族自愈——缓存的 zone→
// domain_id 陈旧（域名移出账户/删除重建）时，deleteRecord 对旧 ID 报「域名
// 不存在」类错误，须作废缓存重解析后重试一次，而非把清理失败抛给签发链。
func TestDNSPodCleanUp_staleDomainIDInvalidatesAndRetries(t *testing.T) {
	// Given: the zone is cached as id 1 while the API now serves it as id 2
	seedDomainIDCache(t, "id,token", map[string]string{})
	transport := &staleRemoveTransport{currentID: "1", records: map[string]string{}}
	dataDir := t.TempDir()
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "this-task", 600); err != nil {
		t.Fatalf("present owned record: %v", err)
	}
	transport.flipStaleDomain("1", "2", false)

	// When
	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then: the stale id was invalidated, re-resolved once and the deletion
	// retried against the fresh id
	if err != nil {
		t.Fatalf("clean up with stale cached domain id: %v", err)
	}
	transport.mu.Lock()
	removes := append([][2]string(nil), transport.removes...)
	listCalls := transport.listCalls
	transport.mu.Unlock()
	want := [][2]string{{"1", "300"}, {"2", "300"}}
	if !reflect.DeepEqual(removes, want) {
		t.Fatalf("Record.Remove sequence=%v, want %v（陈旧一次+重解析后重试一次）", removes, want)
	}
	if listCalls != 2 {
		t.Fatalf("Domain.List calls=%d, want 2（Present 解析一次+作废后重解析一次）", listCalls)
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	left, err := store.Matching("dnspod", "example.com", "_acme-challenge.example.com.")
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("ownership left=%+v, want empty after successful cleanup", left)
	}
}

// U5-1 回归形状一：未命中陈旧 ID 时清理恰好删除一次——不作废缓存、不重解析、
// 不发第二次删除。
func TestDNSPodCleanUp_freshDomainIDDeletesOnce(t *testing.T) {
	// Given: the cached id still matches the API
	seedDomainIDCache(t, "id,token", map[string]string{})
	transport := &staleRemoveTransport{currentID: "1", records: map[string]string{}}
	provider, err := NewPersistent("id,token", t.TempDir())
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "this-task", 600); err != nil {
		t.Fatalf("present owned record: %v", err)
	}

	// When
	if err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("clean up with fresh domain id: %v", err)
	}

	// Then: exactly one deletion against the cached id, no re-resolution
	transport.mu.Lock()
	defer transport.mu.Unlock()
	want := [][2]string{{"1", "300"}}
	if !reflect.DeepEqual(transport.removes, want) {
		t.Fatalf("Record.Remove sequence=%v, want %v（删除恰好一次）", transport.removes, want)
	}
	if transport.listCalls != 1 {
		t.Fatalf("Domain.List calls=%d, want 1（仅 Present 的初始解析，清理命中缓存）", transport.listCalls)
	}
}

// U5-1 回归形状二 + U5-2 基线钉：重试仍失败照旧记 failed（不循环）——内存
// 模式下失败记录须回到 owned 表（failed 存储的唯一消费者），供同进程后续
// 清理重试。
func TestDNSPodCleanUp_staleRetryStillFailsReappendsOwnedRecord(t *testing.T) {
	// Given: a stale cached id and an API that also fails the fresh-id retry
	seedDomainIDCache(t, "id,token", map[string]string{})
	transport := &staleRemoveTransport{currentID: "1", records: map[string]string{}}
	provider := New("id,token")
	provider.client.Transport = transport
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "this-task", 600); err != nil {
		t.Fatalf("present owned record: %v", err)
	}
	transport.flipStaleDomain("1", "2", true)

	// When
	err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then: exactly one invalidation+retry (no loop), the failure is
	// reported and the record returns to the in-memory owned table
	if err == nil {
		t.Fatal("clean up swallowed the persistent deletion failure")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	want := [][2]string{{"1", "300"}, {"2", "300"}}
	if !reflect.DeepEqual(transport.removes, want) {
		t.Fatalf("Record.Remove sequence=%v, want %v（重试一次后停止，不循环）", transport.removes, want)
	}
	provider.mu.Lock()
	entries := provider.owned["1|_acme-challenge"]
	provider.mu.Unlock()
	if len(entries) != 1 || entries[0].recordID != "300" {
		t.Fatalf("owned entries=%+v, want failed record 300 re-appended", entries)
	}
}

// U5-1 回归形状三（生产形状）：ownership 模式下重试仍失败时，失败记录保留
// ownership 条目（DNS 记录可能仍存在），后续清理可自愈。
func TestDNSPodCleanUp_staleRetryFailureKeepsOwnershipEntry(t *testing.T) {
	// Given: a stale cached id and an API that also fails the fresh-id retry
	seedDomainIDCache(t, "id,token", map[string]string{})
	transport := &staleRemoveTransport{currentID: "1", records: map[string]string{}}
	dataDir := t.TempDir()
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "this-task", 600); err != nil {
		t.Fatalf("present owned record: %v", err)
	}
	transport.flipStaleDomain("1", "2", true)

	// When
	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then: one retry, failure reported, ownership entry kept
	if err == nil {
		t.Fatal("clean up swallowed the persistent deletion failure")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	want := [][2]string{{"1", "300"}, {"2", "300"}}
	if !reflect.DeepEqual(transport.removes, want) {
		t.Fatalf("Record.Remove sequence=%v, want %v（重试一次后停止，不循环）", transport.removes, want)
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	left, err := store.Matching("dnspod", "example.com", "_acme-challenge.example.com.")
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 1 || left[0].RecordID != "300" {
		t.Fatalf("ownership left=%+v, want failed record 300 kept", left)
	}
}

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

// createRecordRequest 是 SDK 发出的 CreateRecord 请求体（字段名与腾讯云
// API 一致，JSON 解码不区分大小写）。fake 留档这些参数，供断言挑战记录
// 落在正确的 domain/sub_domain/type/line/ttl 上。
type createRecordRequest struct {
	Domain     string
	SubDomain  string
	RecordType string
	RecordLine string
	Value      string
	TTL        uint64
}

type recordTransport struct {
	mu      sync.Mutex
	records map[uint64]string
	nextID  uint64
	creates []createRecordRequest
	deletes []uint64
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
		var payload createRecordRequest
		if err := json.Unmarshal(body, &payload); err != nil {
			transport.mu.Unlock()
			return nil, err
		}
		transport.nextID++
		recordID := 199 + transport.nextID
		// 保存真实 value：按值清理若删错记录，只有断言「幸存记录的 value」
		// 才能发现（仅数记录条数时删 alpha 留 beta 与删 beta 留 alpha 同形）。
		transport.records[recordID] = payload.Value
		transport.creates = append(transport.creates, payload)
		responseBody = fmt.Sprintf(`{"Response":{"RecordId":%d,"RequestId":"test"}}`, recordID)
	case "DeleteRecord":
		var payload struct {
			RecordID uint64 `json:"RecordId"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			transport.mu.Unlock()
			return nil, err
		}
		transport.deletes = append(transport.deletes, payload.RecordID)
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
	// actionAttempts 按动作计数失败注入：跨动作共享一个计数器会让「先
	// Present 再 CleanUp」的用例把 Create 的消耗算进 Delete 的失败注入，
	// 429/5xx 重试实际一次都没触发而用例假绿。
	actionAttempts map[string]int
}

func (transport *flakyRecordTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	action := request.Header.Get("X-TC-Action")
	transport.mu.Lock()
	transport.attempts++
	if transport.actionAttempts == nil {
		transport.actionAttempts = make(map[string]int)
	}
	transport.actionAttempts[action]++
	failing := action == transport.failAction && transport.actionAttempts[action] <= transport.failCount
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

func TestProvider_Present_does_not_replay_create_on_5xx(t *testing.T) {
	// （迁移自 retries_transient_5xx）：CreateRecord 命中
	// 502 不得重放——创建响应丢失时重试会产生无 ID 幽灵 TXT（ownership 清理
	// 只按记录 ID 删除），首个 502 原样上抛、单次调用。
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	transport := &flakyRecordTransport{failAction: "CreateRecord", failStatus: http.StatusBadGateway, failCount: 3}
	transport.records = map[uint64]string{100: "another-task"}
	provider.client.WithHttpTransport(&retry.Transport{Base: transport, InitialBackoff: time.Millisecond})

	// When
	err = provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	// Then：502 直接失败且不产生第二条创建调用
	if err == nil {
		t.Fatal("present succeeded, want 502 surfaced（创建类 5xx 不重放）")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if got := transport.actionAttempts["CreateRecord"]; got != 1 {
		t.Fatalf("CreateRecord attempts=%d, want 1（创建类 5xx 单次调用不重放；复用扫描 DescribeRecordList 不计入）", got)
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
	if got := transport.actionAttempts["DeleteRecord"]; got != 2 {
		t.Fatalf("DeleteRecord attempts=%d, want 2（首次 429 + 重试成功）", got)
	}
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

	// Then: only alpha's record was deleted; beta's record survives with its
	// own value (仅数条数时「删 beta 留 alpha」同样通过)
	transport.mu.Lock()
	remaining := transport.records
	deleted := append([]uint64(nil), transport.deletes...)
	transport.mu.Unlock()
	if len(remaining) != 1 || remaining[201] != "beta" {
		t.Fatalf("remaining records=%v, want only beta's record (id 201)", remaining)
	}
	if len(deleted) != 1 || deleted[0] != 200 {
		t.Fatalf("deleted record IDs=%v, want [200]（alpha）——按值清理不得删除并发签发的 beta", deleted)
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

	// Then: alpha's record survives with its own value
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.records) != 1 || transport.records[200] != "alpha" {
		t.Fatalf("remaining records=%v, want only alpha's record (id 200)", transport.records)
	}
	if len(transport.deletes) != 1 || transport.deletes[0] != 201 {
		t.Fatalf("deleted record IDs=%v, want [201]（beta）", transport.deletes)
	}
}

// Present 的核心契约是把挑战写进 _acme-challenge.<domain> 之下：domain/
// sub_domain 派生错位会把 TXT 写到别的名字，ACME 验证失败白烧订单配额；
// record_type/record_line/ttl 写错会被 API 拒绝或落到错误线路。
func TestProvider_Present_sendsExpectedChallengeRecordFields(t *testing.T) {
	transport := &recordTransport{records: map[uint64]string{}}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)

	cases := []struct {
		zone, tokenFQDN, value, wantSubDomain string
	}{
		{"example.com.", "_acme-challenge.example.com.", "apex-value", "_acme-challenge"},
		{"example.com.", "_acme-challenge.www.example.com.", "www-value", "_acme-challenge.www"},
	}
	for _, tc := range cases {
		if err := provider.Present(t.Context(), tc.zone, tc.tokenFQDN, tc.value, 600); err != nil {
			t.Fatalf("present %s: %v", tc.tokenFQDN, err)
		}
	}

	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.creates) != len(cases) {
		t.Fatalf("CreateRecord calls=%d, want %d", len(transport.creates), len(cases))
	}
	for i, tc := range cases {
		want := createRecordRequest{
			Domain: "example.com", SubDomain: tc.wantSubDomain, RecordType: "TXT",
			RecordLine: "默认", Value: tc.value, TTL: 600,
		}
		if transport.creates[i] != want {
			t.Fatalf("CreateRecord[%d]=%+v, want %+v", i, transport.creates[i], want)
		}
	}
}

// 大小写不敏感必须贯通到 sub_domain 派生：保存前探针用「ResolveZone 归一后的
// 小写 zone + 输入原样的混合大小写 FQDN」，后缀比较若不做归一便失配，整个
// FQDN 会被当作子域名写进 API——探针 TXT 落到错误名字（与 dnspod 侧同契约）。
func TestProvider_mixedCaseFQDN_derivesRelativeSubDomain(t *testing.T) {
	transport := &recordTransport{records: map[uint64]string{}}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	const mixedFQDN = "_acme-challenge.lb-test.Example.COM."

	// When
	if err := provider.Present(t.Context(), "example.com", mixedFQDN, "probe", 600); err != nil {
		t.Fatalf("present mixed-case fqdn: %v", err)
	}
	if got := provider.CountCleanupRecords("example.com", mixedFQDN, "probe"); got != 1 {
		t.Fatalf("CountCleanupRecords(mixed-case fqdn)=%d, want 1（派生口径必须与 Present 一致）", got)
	}
	if err := provider.CleanUpValue(t.Context(), "example.com", mixedFQDN, "probe"); err != nil {
		t.Fatalf("clean up mixed-case fqdn: %v", err)
	}

	// Then
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.creates) != 1 {
		t.Fatalf("CreateRecord calls=%d, want 1", len(transport.creates))
	}
	if got := transport.creates[0].SubDomain; got != "_acme-challenge.lb-test" {
		t.Fatalf("SubDomain=%q, want %q（大小写归一无贯通到相对子域派生）", got, "_acme-challenge.lb-test")
	}
	if len(transport.records) != 0 {
		t.Fatalf("remaining records=%v, want none after cleanup", transport.records)
	}
}

// slowFlakyTransport answers the first failCount calls of failAction with a
// slow 5xx response, then behaves like recordTransport.
type slowFlakyTransport struct {
	recordTransport
	failAction string
	failCount  int
	attempts   int
	delay      time.Duration
	// actionAttempts 同 flakyRecordTransport：失败注入必须按动作隔离。
	actionAttempts map[string]int
}

func (transport *slowFlakyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	action := request.Header.Get("X-TC-Action")
	transport.mu.Lock()
	transport.attempts++
	if transport.actionAttempts == nil {
		transport.actionAttempts = make(map[string]int)
	}
	transport.actionAttempts[action]++
	failing := action == transport.failAction && transport.actionAttempts[action] <= transport.failCount
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

func TestProvider_CleanUp_survives_slow_5xx_sequence(t *testing.T) {
	// 迁移（原 Present 慢 502 序列）：创建类 5xx 不再重放，超时不截断
	// 语义改由非创建动作承载——DeleteRecord 的慢 502,502,200 序列必须在 SDK
	// 客户端单次请求超时内完成整个重试包络，而非被退避循环截断。
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	transport := &slowFlakyTransport{failAction: "DeleteRecord", failCount: 2, delay: 100 * time.Millisecond}
	transport.records = map[uint64]string{100: "another-task"}
	provider.client.WithHttpTransport(&retry.Transport{Base: transport, InitialBackoff: time.Millisecond})
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present: %v", err)
	}

	// When
	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then：延迟重试序列在客户端超时内完成
	if err != nil {
		t.Fatalf("clean up: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.attempts != 5 {
		t.Fatalf("total attempts=%d, want 5（复用扫描 1 + Create 1 + Delete 3）", transport.attempts)
	}
	if got := transport.actionAttempts["DeleteRecord"]; got != 3 {
		t.Fatalf("DeleteRecord attempts=%d, want 3（502,502,200 全部命中注入）", got)
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

// 不可解析的持久化 RecordID 只告警一次并移除，正常兄弟条目不受影响。
func TestProvider_CleanUp_malformedPersistedRecordIDRemovedAfterWarning(t *testing.T) {
	// Given 同一 challenge 下一条不可解析的持久化 ID 与一条正常 ID（真实 ownership 文件）。
	dataDir := t.TempDir()
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	fqdn := "_acme-challenge.example.com."
	for _, record := range []ownership.Record{
		{Provider: "tencent", Zone: "example.com", FQDN: fqdn, Value: "broken", RecordID: "broken-record-id"},
		{Provider: "tencent", Zone: "example.com", FQDN: fqdn, Value: "valid", RecordID: "200"},
	} {
		if err := store.Add(record); err != nil {
			t.Fatalf("seed ownership record %+v: %v", record, err)
		}
	}
	transport := &recordTransport{records: map[uint64]string{200: "owned"}}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	var warnings strings.Builder
	oldLogf := logf
	logf = func(level, format string, args ...any) {
		if level == "warn" {
			warnings.WriteString(fmt.Sprintf(format, args...))
		}
	}
	t.Cleanup(func() { logf = oldLogf })

	// When 首次清理同时遇到畸形与正常条目。
	err = provider.CleanUp(t.Context(), "example.com", fqdn)

	// Then 本轮仍上报解析错误，但畸形条目被移除，正常条目照常删除。
	if err == nil || !strings.Contains(err.Error(), "broken-record-id") {
		t.Fatalf("first cleanup error=%v, want malformed record ID surfaced", err)
	}
	left, err := store.Matching("tencent", "example.com", fqdn)
	if err != nil {
		t.Fatalf("read ownership after cleanup: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("ownership left=%+v, want malformed and successfully deleted entries removed", left)
	}
	transport.mu.Lock()
	_, validStillAlive := transport.records[200]
	transport.mu.Unlock()
	if validStillAlive {
		t.Fatal("valid record 200 was not deleted while handling malformed sibling")
	}
	if got := strings.Count(warnings.String(), "无法解析"); got != 1 {
		t.Fatalf("malformed record warnings=%d, want exactly 1; warnings=%q", got, warnings.String())
	}

	// And 第二次清理为空操作，不再形成永久 cleanup_warning 循环。
	if err := provider.CleanUp(t.Context(), "example.com", fqdn); err != nil {
		t.Fatalf("second cleanup after malformed entry removal: %v", err)
	}
}

// 基线钉：内存模式下删除失败仍回填 owned——failed 存储
// 的唯一消费者是 ownership==nil 分支，失败条目门控后该既有形状不得破坏。
func TestProvider_CleanUp_memoryModeReappendsFailedRecord(t *testing.T) {
	// Given: memory-mode ownership whose only record fails to delete
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	transport := &deleteFailTransport{recordTransport: recordTransport{records: map[uint64]string{}}, failRecordID: 200}
	provider.client.WithHttpTransport(transport)
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present record: %v", err)
	}

	// When
	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then: the failure is reported and the record returns to the in-memory
	// owned table for a later cleanup within this process
	if err == nil {
		t.Fatal("clean up swallowed the deletion failure")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	entries := provider.owned["example.com|_acme-challenge"]
	if len(entries) != 1 || entries[0].recordID != 200 {
		t.Fatalf("owned entries=%+v, want failed record 200 re-appended", entries)
	}
}

// ctxCanceledApiErrorTransport 模拟「请求在途时 ctx 取消、服务端仍返回
// API 错误包」：阻塞至 request ctx 结束后回 500 + TencentCloudSDKError
// 错误体。ctx 已取消时 RoundTrip 立即返回，无需额外同步。
type ctxCanceledApiErrorTransport struct{}

func (transport *ctxCanceledApiErrorTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	<-request.Context().Done()
	return &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"Response":{"Error":{"Code":"InternalError.ApiGateway","Message":"api down"}},"RequestId":"ad5"}}`)),
		Request:    request,
	}, nil
}

// createRecord 失败时 ctx 已取消不得以 ctx.Err()
// 整体覆写 provider 错误（对齐 deleteOne:142-146 口径）——
// errors.Join 保留两者：具体 API 失败原因可诊断，取消事实不丢。
func TestProvider_createRecord_keeps_provider_error_when_context_canceled(t *testing.T) {
	// Given
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	transport := &ctxCanceledApiErrorTransport{}
	provider.client.WithHttpTransport(transport)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "value", 600)
	}()

	// When：请求在途时取消 ctx → API 侧返回 InternalError 错误包
	cancel()

	// Then：错误同时携带 ctx 取消与 provider 失败原因
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("present error=%v, want context cancellation preserved", err)
		}
		if !strings.Contains(err.Error(), "InternalError.ApiGateway") {
			t.Fatalf("present error=%v, want provider error preserved（不得被 ctx.Err() 覆写）", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Tencent request did not return after context cancellation")
	}
}

// 内存模式失败回填必须保留 challenge value——否则后续
// 按值清理（CleanUpValue）的 entry.value != value 过滤会永久跳过该条目，
// 「失败回填供后续清理重试」的意图落空。
func TestProvider_CleanUp_memoryModeFailedValueRetriedByCleanUpValue(t *testing.T) {
	// Given: memory-mode ownership whose only record fails to delete
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	transport := &deleteFailTransport{recordTransport: recordTransport{records: map[uint64]string{}}, failRecordID: 200}
	provider.client.WithHttpTransport(transport)
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present record: %v", err)
	}

	// When: first by-value cleanup fails at the API
	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "value"); err == nil {
		t.Fatal("first cleanup swallowed the deletion failure")
	}
	// Then: the re-appended entry still carries the challenge value
	provider.mu.Lock()
	entries := append([]ownedRecord(nil), provider.owned["example.com|_acme-challenge"]...)
	provider.mu.Unlock()
	if len(entries) != 1 || entries[0].recordID != 200 || entries[0].value != "value" {
		t.Fatalf("owned entries=%+v, want failed record 200 with value preserved", entries)
	}

	// When: the API recovers and the same value is cleaned again
	transport.failRecordID = 0
	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "value"); err != nil {
		t.Fatalf("second cleanup must retry the failed entry, got error: %v", err)
	}

	// Then: the record is deleted at the API and the owned table is drained
	transport.mu.Lock()
	_, alive := transport.records[200]
	transport.mu.Unlock()
	if alive {
		t.Fatal("record 200 was never retried (value lost in failed backfill)")
	}
	provider.mu.Lock()
	left := append([]ownedRecord(nil), provider.owned["example.com|_acme-challenge"]...)
	provider.mu.Unlock()
	if len(left) != 0 {
		t.Fatalf("owned entries=%+v, want drained after successful retry", left)
	}
}

// codedDeleteErrorTransport 让 DeleteRecord 返回指定错误码的 API 错误包络，
// 用于覆盖 isRecordNotFound 的精确码分支（只测 ResourceNotFound 前缀时，
// 删掉精确码分支会让记录 ID 失效场景的清理变成非幂等失败而测试仍绿）。
type codedDeleteErrorTransport struct {
	recordTransport
	code string
}

func (transport *codedDeleteErrorTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Header.Get("X-TC-Action") == "DeleteRecord" {
		if request.Body != nil {
			_, _ = io.Copy(io.Discard, request.Body)
			_ = request.Body.Close()
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"Response":{"Error":{"Code":%q,"Message":"record id invalid"},"RequestId":"test"}}`, transport.code))),
			Request:    request,
		}, nil
	}
	return transport.recordTransport.RoundTrip(request)
}

// 记录 ID 失效类错误码必须与「记录不存在」同语义（幂等清理），否则换账户/
// 手工删除后 ownership 条目永远删不掉、TXT 追踪链断裂。
func TestProvider_CleanUp_treatsInvalidRecordIDCodesAsSuccess(t *testing.T) {
	for _, code := range []string{"InvalidParameter.RecordIdInvalid", "InvalidRecord.Id"} {
		t.Run(code, func(t *testing.T) {
			provider, err := New("secret-id", "secret-key")
			if err != nil {
				t.Fatalf("create provider: %v", err)
			}
			transport := &codedDeleteErrorTransport{code: code}
			transport.records = map[uint64]string{}
			provider.client.WithHttpTransport(transport)
			if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
				t.Fatalf("present: %v", err)
			}

			if err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
				t.Fatalf("clean up with %s: %v（记录 ID 失效必须按删除成功处理）", code, err)
			}
		})
	}
}

// missingRecordIDTransport 对 CreateRecord 返回成功但缺 RecordId。
type missingRecordIDTransport struct {
	recordTransport
}

func (transport *missingRecordIDTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Header.Get("X-TC-Action") == "CreateRecord" {
		if request.Body != nil {
			_, _ = io.Copy(io.Discard, request.Body)
			_ = request.Body.Close()
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"Response":{"RequestId":"test"}}`)),
			Request:    request,
		}, nil
	}
	return transport.recordTransport.RoundTrip(request)
}

// CreateRecord 未返回记录 ID = TXT 已落 DNS 却不可追踪（清理只能靠 stale 兜底
// 或永久残留）。必须报错，且不得把该记录计入 owned。
func TestProvider_Present_createWithoutRecordIDFails(t *testing.T) {
	transport := &missingRecordIDTransport{}
	transport.records = map[uint64]string{}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)

	err = provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	if err == nil || !strings.Contains(err.Error(), "no record ID") {
		t.Fatalf("err=%v, want CreateRecord returned no record ID", err)
	}
	provider.mu.Lock()
	owned := 0
	for _, entries := range provider.owned {
		owned += len(entries)
	}
	provider.mu.Unlock()
	if owned != 0 {
		t.Fatalf("owned records=%d, want 0（无 ID 记录不得登记为已归属）", owned)
	}
}

// scriptedDefaultTransport 作为 http.DefaultTransport 的替身：按脚本返回
// 状态码，用于观察 New 的 retry.Transport 是否真的接在 SDK 客户端上
// （所有用例都用 WithHttpTransport 覆盖时，生产装配的重试层无守护）。
type scriptedDefaultTransport struct {
	mu       sync.Mutex
	statuses []int
	calls    int
}

func (transport *scriptedDefaultTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
	}
	transport.mu.Lock()
	status := http.StatusOK
	if transport.calls < len(transport.statuses) {
		status = transport.statuses[transport.calls]
	}
	transport.calls++
	transport.mu.Unlock()
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"Response":{"RecordId":201,"RequestId":"test"}}`)),
		Request:    request,
	}, nil
}

func TestNew_wires_retrying_transport(t *testing.T) {
	oldDefault := http.DefaultTransport
	base := &scriptedDefaultTransport{statuses: []int{http.StatusTooManyRequests}}
	http.DefaultTransport = base
	t.Cleanup(func() { http.DefaultTransport = oldDefault })

	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present through production wiring: %v", err)
	}
	base.mu.Lock()
	calls := base.calls
	base.mu.Unlock()
	if calls != 3 {
		t.Fatalf("http calls=%d, want 3（New 必须装配 429 重试层；复用扫描 1 + Create 429 重试 2）", calls)
	}
}

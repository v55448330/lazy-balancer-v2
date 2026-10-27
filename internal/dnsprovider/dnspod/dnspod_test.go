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

// dnsPodCreateRequest 是 Record.Create 请求参数留档（domain_id 正常路径也
// 从不断言，而它决定 TXT 落在哪个域）。
type dnsPodCreateRequest struct {
	DomainID   string
	SubDomain  string
	RecordType string
	RecordLine string
	Value      string
	TTL        string
}

type dnsPodRecordTransport struct {
	mu      sync.Mutex
	records map[string]string
	nextID  int
	creates []dnsPodCreateRequest
	removes []string
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
		transport.creates = append(transport.creates, dnsPodCreateRequest{
			DomainID:   params.Get("domain_id"),
			SubDomain:  params.Get("sub_domain"),
			RecordType: params.Get("record_type"),
			RecordLine: params.Get("record_line"),
			Value:      params.Get("value"),
			TTL:        params.Get("ttl"),
		})
		responseBody = fmt.Sprintf(`{"status":{"code":"1","message":"ok"},"record":{"id":%q}}`, recordID)
	case strings.HasSuffix(request.URL.Path, "Record.Remove"):
		transport.removes = append(transport.removes, params.Get("record_id"))
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

// Present 的核心契约是把挑战写进 _acme-challenge.<domain> 之下：domain_id/
// sub_domain 派生错位会把 TXT 写到别的名字，ACME 验证失败白烧订单配额；
// record_type/record_line/ttl 写错会被 API 拒绝或落到错误线路。
func TestProvider_Present_sendsExpectedChallengeRecordFields(t *testing.T) {
	transport := &dnsPodRecordTransport{records: map[string]string{}}
	provider := New("id,token")
	provider.client.Transport = transport

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
		t.Fatalf("Record.Create calls=%d, want %d", len(transport.creates), len(cases))
	}
	for i, tc := range cases {
		want := dnsPodCreateRequest{
			DomainID: "1", SubDomain: tc.wantSubDomain, RecordType: "TXT",
			RecordLine: "默认", Value: tc.value, TTL: "600",
		}
		if transport.creates[i] != want {
			t.Fatalf("Record.Create[%d]=%+v, want %+v", i, transport.creates[i], want)
		}
	}
}

// 大小写不敏感必须贯通到 sub_domain 派生：保存前探针用「ResolveZone 归一后的
// 小写 zone + 输入原样的混合大小写 FQDN」，后缀比较若不做归一便失配，整个
// FQDN（`_acme-challenge.lb-test.Example.COM`）会被当作子域名写进 API——探针
// TXT 落到错误名字，ACME 验证与清理都跟着偏。
func TestProvider_mixedCaseFQDN_derivesRelativeSubDomain(t *testing.T) {
	transport := &dnsPodRecordTransport{records: map[string]string{}}
	provider := New("id,token")
	provider.client.Transport = transport
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
		t.Fatalf("Record.Create calls=%d, want 1", len(transport.creates))
	}
	if got := transport.creates[0].SubDomain; got != "_acme-challenge.lb-test" {
		t.Fatalf("sub_domain=%q, want %q（大小写归一无贯通到相对子域派生）", got, "_acme-challenge.lb-test")
	}
	if len(transport.records) != 0 {
		t.Fatalf("remaining records=%v, want none after cleanup", transport.records)
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
	// 清进程内 zone 缓存——前序用例可能已缓存同名 zone。
	seedDomainIDCache(t, "id,token", nil)
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
	// 清进程内 zone 缓存——前序用例可能已缓存同名 zone。
	seedDomainIDCache(t, "id,token", nil)
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

func TestProvider_getDomainID_normalizesZoneCase(t *testing.T) {
	// DNS 名大小写不敏感：Domain.List 返回服务端规范形态（小写），混合大小写
	// 的 zone 输入必须命中同一域名，且缓存键随之归一——同一 zone 的不同书写
	// 形态不得各存一份 domain_id，也不得把「大小写不同」报成「域名不在账户」。
	seedDomainIDCache(t, "id,token", nil)
	transport := &paginatedTransport{domains: []string{"example.com"}, pageSize: 10}
	provider := New("id,token")
	provider.client.Transport = transport

	// When：混合大小写 + 尾点
	domainID, err := provider.getDomainID(t.Context(), "Example.COM.")
	if err != nil {
		t.Fatalf("get domain id with mixed case: %v", err)
	}
	if domainID != "1" {
		t.Fatalf("domainID=%q, want 1", domainID)
	}

	// Then：小写形态直接命中同一缓存键（不再发请求）
	transport.mu.Lock()
	requestsBefore := len(transport.requests)
	transport.mu.Unlock()
	if _, err := provider.getDomainID(t.Context(), "example.com"); err != nil {
		t.Fatalf("get domain id after normalization: %v", err)
	}
	transport.mu.Lock()
	requestsAfter := len(transport.requests)
	transport.mu.Unlock()
	if requestsAfter != requestsBefore {
		t.Fatalf("requests=%d→%d, want 同一 zone 的不同大小写复用同一缓存键", requestsBefore, requestsAfter)
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
	// actionAttempts 按动作（路径末段）计数：跨动作共享一个计数器时，
	// 前置 Domain.List 的调用会提前耗尽 Record.Create 的失败注入额度，
	// 「重试确实发生」的断言就可能靠无关调用的次数凑够。
	actionAttempts map[string]int
}

func (transport *flakyTransport) actionOf(request *http.Request) string {
	path := request.URL.Path
	return path[strings.LastIndex(path, "/")+1:]
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
	if transport.actionAttempts == nil {
		transport.actionAttempts = make(map[string]int)
	}
	action := transport.actionOf(request)
	transport.actionAttempts[action]++
	// 失败注入限定 failPath 动作——创建类 5xx 不再重放（见
	// TestProvider_Present_does_not_replay_create_on_5xx），接线本意
	// 「瞬时故障重试」由非创建动作承载。
	failing := transport.actionAttempts[action] <= transport.failCount && strings.HasSuffix(request.URL.Path, transport.failPath)
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
			// 按动作精确计数：Domain.List 恰为「失败次数 + 1」次；Record.Create
			// 每次 Present 只 1 次。只看全局至少 N 次时，多一次 Domain.List 分页
			// 或创建重放都能凑够次数。
			if got := transport.actionAttempts["Domain.List"]; got != len(testCase.statuses)+1 {
				t.Fatalf("Domain.List attempts=%d, want %d（瞬时故障必须重试到成功）", got, len(testCase.statuses)+1)
			}
			if got := transport.actionAttempts["Record.Create"]; got != 1 {
				t.Fatalf("Record.Create attempts=%d, want 1（创建类不得重放）", got)
			}
		})
	}
}

// gatewayBodyTransport 返回网关错误页（非 JSON），用于观察 apiCall 的失败形态。
type gatewayBodyTransport struct {
	status int
	body   string
}

func (transport *gatewayBodyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
	}
	return &http.Response{
		StatusCode: transport.status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(transport.body)),
		Request:    request,
	}, nil
}

// 网关返回 HTML/空体（502/503）时解码失败必须带
// HTTP 状态码与动作名——原文案只剩「decode response: invalid character '<'…」，
// 排障只能翻 network 日志（429/5xx 已由 retry.Transport 吸收，这里是最终失败形态）。
func TestProvider_apiCall_decodeErrorCarriesStatusAndMethod(t *testing.T) {
	// Given
	provider := New("id,token")
	provider.client.Transport = &gatewayBodyTransport{status: http.StatusBadGateway, body: "<html>bad gateway</html>"}
	var result struct {
		Status struct{ Code string } `json:"status"`
	}

	// When
	err := provider.apiCall(t.Context(), "Record.Create", url.Values{}, &result)

	// Then
	if err == nil {
		t.Fatal("HTML body was accepted as a JSON response")
	}
	if !strings.Contains(err.Error(), "HTTP 502") || !strings.Contains(err.Error(), "Record.Create") {
		t.Fatalf("error=%q, want action name and HTTP status in the decode failure", err)
	}
}

// HTTP 5xx 即使带回可解析 JSON 也必须按失败处理。网关兜底体
// 或厂商错误体恰好含 {"status":{"code":"1"}} 时，原实现解码成功即 return nil，
// 记录内 code 被当业务成功——Record.Remove 因此把「未删除」当「已删除」，
// 所有权条目被清除而 TXT 永久残留且脱离追踪。
func TestProvider_apiCall_rejectsHTTPErrorWithDecodableBody(t *testing.T) {
	// Given：Record.Remove 返回 503 + 可解析 JSON（体内 code 仍是成功值）
	transport := &gatewayBodyTransport{status: http.StatusServiceUnavailable, body: `{"status":{"code":"1","message":"ok"}}`}
	provider := New("id,token")
	provider.client.Transport = transport
	var result struct {
		Status struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
	}

	// When
	err := provider.apiCall(t.Context(), "Record.Remove", url.Values{}, &result)

	// Then：错误必须自明（动作名 + HTTP 状态 + 响应体取样），且不得把体内
	// code 当成功
	if err == nil {
		t.Fatal("HTTP 503 with decodable body was accepted as success")
	}
	if !strings.Contains(err.Error(), "HTTP 503") || !strings.Contains(err.Error(), "Record.Remove") {
		t.Fatalf("error=%q, want action name and HTTP status", err)
	}
	if !strings.Contains(err.Error(), `"code":"1"`) {
		t.Fatalf("error=%q, want truncated body sampled for diagnostics", err)
	}
}

// 错误体取样上限防止网关错误页（数百 KB）整读进错误文案。
func TestProvider_apiCall_truncatesErrorBody(t *testing.T) {
	// Given：6 KiB 的错误体
	body := strings.Repeat("x", 6*1024)
	provider := New("id,token")
	provider.client.Transport = &gatewayBodyTransport{status: http.StatusBadGateway, body: body}

	// When
	err := provider.apiCall(t.Context(), "Domain.List", url.Values{}, nil)

	// Then：只保留前缀（httpErrorBodyLimit 字节），不整读
	if err == nil {
		t.Fatal("HTTP 502 accepted as success")
	}
	if len(err.Error()) > httpErrorBodyLimit+128 {
		t.Fatalf("error length=%d, want bounded near the %d-byte sample", len(err.Error()), httpErrorBodyLimit)
	}
	if !strings.Contains(err.Error(), strings.Repeat("x", httpErrorBodyLimit)) {
		t.Fatal("error dropped the sampled body prefix")
	}
}

// Record.Create 命中 5xx 不得重放——创建响应丢失时
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
	// 条目带本账户摘要——「同账户的陈旧条目由后续清理回收」
	// 是 既有契约（崩溃遗留的 TXT 必须能被清掉）；账户维度只保护
	// 无法归属当前账户的条目（见 TestProvider_CleanUpValue_dropsStaleLegacyRecordWithoutDeleting）。
	raw := fmt.Sprintf(`{"version":1,"records":[
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com.","value":"abandoned","record_id":"100","account":%q,"created_at":%q},
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com.","value":"beta","record_id":"200","account":%q,"created_at":%q}
	]}`,
		ownership.AccountDigest("id,token"), time.Now().Add(-90*time.Minute).UTC().Format(time.RFC3339),
		ownership.AccountDigest("id,token"), time.Now().UTC().Format(time.RFC3339))
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
	// backoff/ waits capped at 30s each), so it must exceed that
	// envelope instead of cutting it short
	if provider.client.Timeout < 90*time.Second {
		t.Fatalf("client timeout=%v, want >= 90s retry-envelope headroom", provider.client.Timeout)
	}
}

// removeFailTransport fails Record.Remove for one specific record ID while
// every other removal succeeds. 失败形态用 code 7（官方码表=没有权限）——
// 权限错误是普通失败，不得触发「域名失效」自愈（缓存作废+重解析+重试）。
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

// staleRemoveTransport 模拟 cleanUp 阶段的陈旧 zone→domain_id
// Domain.List 恒返回 currentID；Record.Remove 对 staleID 报「域名 ID 失效」
// （code 6，官方码表 Record.Remove 的 Invalid domain id），对 currentID 默认
// 删除成功（failFreshID 时改报权限错误 code 11——权限码不得参与陈旧分类）。
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
			responseBody = `{"status":{"code":"6","message":"域名ID错误"}}`
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

// cleanUp 侧的同族自愈——缓存的 zone→
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

// 回归形状一：未命中陈旧 ID 时清理恰好删除一次——不作废缓存、不重解析、
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

// 回归形状二 + 基线钉：重试仍失败照旧记 failed（不循环）——内存
// 模式下失败记录须回到 owned 表（failed 存储的唯一消费者），供同进程后续
// 清理重试。自愈重解析已把 domain_id 换代（1→2），
// 回填与残留条目必须落在新键——旧键条目对后续 cleanUp/Present 永不可达，
// 「failed 回填供后续清理重试」形同虚设（旧钉测钉住了这个自相矛盾形态）。
func TestDNSPodCleanUp_staleRetryStillFailsReappendsUnderFreshKey(t *testing.T) {
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

	// Then: exactly one invalidation+retry (no loop), the failure is reported
	// and the record returns to the in-memory owned table under the FRESH key
	if err == nil {
		t.Fatal("clean up swallowed the persistent deletion failure")
	}
	transport.mu.Lock()
	removes := append([][2]string(nil), transport.removes...)
	transport.mu.Unlock()
	want := [][2]string{{"1", "300"}, {"2", "300"}}
	if !reflect.DeepEqual(removes, want) {
		t.Fatalf("Record.Remove sequence=%v, want %v（重试一次后停止，不循环）", removes, want)
	}
	provider.mu.Lock()
	entries := provider.owned["2|_acme-challenge"]
	_, oldKeyLeft := provider.owned["1|_acme-challenge"]
	provider.mu.Unlock()
	if len(entries) != 1 || entries[0].recordID != "300" {
		t.Fatalf("owned entries=%+v, want failed record 300 re-appended under fresh key 2", entries)
	}
	if oldKeyLeft {
		t.Fatal("stale-key entries must migrate to the fresh key after self-heal (历史修复)")
	}

	// And：可达性——回填记录在下一轮 cleanUp 真正被重试删除（fresh-id 放行后）
	transport.flipStaleDomain("1", "2", false)
	if err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("retry cleanup after self-heal: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	wantRetry := [][2]string{{"1", "300"}, {"2", "300"}, {"2", "300"}}
	if !reflect.DeepEqual(transport.removes, wantRetry) {
		t.Fatalf("Record.Remove sequence=%v, want %v（回填记录按新键被重删）", transport.removes, wantRetry)
	}
}

// 回归形状三（生产形状）：ownership 模式下重试仍失败时，失败记录保留
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

// 内存模式失败回填必须保留 challenge value——否则后续
// 按值清理（CleanUpValue）的 entry.value != value 过滤会永久跳过该条目，
// 「失败回填供后续清理重试」的意图落空。
func TestProvider_CleanUp_memoryModeFailedValueRetriedByCleanUpValue(t *testing.T) {
	// Given: memory-mode ownership whose only record fails to delete
	provider := New("id,token")
	transport := &removeFailTransport{dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{}}, failRecordID: "200"}
	provider.client.Transport = transport
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present record: %v", err)
	}

	// When: first by-value cleanup fails at the API
	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "value"); err == nil {
		t.Fatal("first cleanup swallowed the deletion failure")
	}
	// Then: the re-appended entry still carries the challenge value
	provider.mu.Lock()
	entries := append([]ownedRecord(nil), provider.owned["1|_acme-challenge"]...)
	provider.mu.Unlock()
	if len(entries) != 1 || entries[0].recordID != "200" || entries[0].value != "value" {
		t.Fatalf("owned entries=%+v, want failed record 200 with value preserved", entries)
	}

	// When: the API recovers and the same value is cleaned again
	transport.failRecordID = ""
	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "value"); err != nil {
		t.Fatalf("second cleanup must retry the failed entry, got error: %v", err)
	}

	// Then: the record is deleted at the API and the owned table is drained
	transport.mu.Lock()
	_, alive := transport.records["200"]
	transport.mu.Unlock()
	if alive {
		t.Fatal("record 200 was never retried (value lost in failed backfill)")
	}
	provider.mu.Lock()
	left := append([]ownedRecord(nil), provider.owned["1|_acme-challenge"]...)
	provider.mu.Unlock()
	if len(left) != 0 {
		t.Fatalf("owned entries=%+v, want drained after successful retry", left)
	}
}

// missingRecordIDTransport 对 Record.Create 返回成功但缺 record.id。
type missingRecordIDTransport struct {
	dnsPodRecordTransport
}

func (transport *missingRecordIDTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, "Record.Create") {
		if request.Body != nil {
			_, _ = io.Copy(io.Discard, request.Body)
			_ = request.Body.Close()
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"1","message":"ok"},"record":{}}`)),
			Request:    request,
		}, nil
	}
	return transport.dnsPodRecordTransport.RoundTrip(request)
}

// Record.Create 未返回记录 ID = TXT 已落 DNS 却不可追踪（清理只能等 stale
// 兜底或永久残留）。必须报错，且不得登记为已归属。
func TestProvider_Present_createWithoutRecordIDFails(t *testing.T) {
	transport := &missingRecordIDTransport{}
	transport.records = map[string]string{}
	provider := New("id,token")
	provider.client.Transport = transport

	err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	if err == nil || !strings.Contains(err.Error(), "no record ID") {
		t.Fatalf("err=%v, want Record.Create returned no record ID", err)
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

// CountCleanupRecords 决定 deferred 清理预算（acme/issuer 用它排定预算）：
// 内存模式只数本挑战值；空 value 退化为按名计数；他值不参与。
func TestProvider_CountCleanupRecords_countsOnlyOwnValue(t *testing.T) {
	transport := &dnsPodRecordTransport{records: map[string]string{}}
	provider := New("id,token")
	provider.client.Transport = transport
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "alpha", 600); err != nil {
		t.Fatalf("present alpha: %v", err)
	}
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "beta", 600); err != nil {
		t.Fatalf("present beta: %v", err)
	}

	if got := provider.CountCleanupRecords("example.com", "_acme-challenge.example.com.", "alpha"); got != 1 {
		t.Fatalf("count(alpha)=%d, want 1（只数本挑战值）", got)
	}
	if got := provider.CountCleanupRecords("example.com", "_acme-challenge.example.com.", ""); got != 2 {
		t.Fatalf("count(empty)=%d, want 2（空值为按名计数）", got)
	}
	if got := provider.CountCleanupRecords("example.com", "_acme-challenge.other.example.com.", "alpha"); got != 0 {
		t.Fatalf("count(other name)=%d, want 0", got)
	}
}

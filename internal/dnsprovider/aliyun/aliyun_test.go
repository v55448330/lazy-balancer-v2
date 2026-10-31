package aliyun

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsprovider/internal/retry"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// ---------------------------------------------------------------------------
// 假 Alidns 服务端：真实 HTTP 通路（签名头/查询串/重试包络全部真实走一遍），
// 按 x-acs-action 分派；支持对指定 action 的前 N 次请求注入固定故障响应。
// ---------------------------------------------------------------------------

type fakeRecord struct {
	rr    string
	value string
}

type fakeAlidns struct {
	mu             sync.Mutex
	records        map[uint64]fakeRecord
	nextID         uint64
	actionAttempts map[string]int
	deleted        []uint64
	captures       map[string][]url.Values
	lastHeaders    http.Header

	// 故障注入：failAction 的前 failTimes 次请求返回 failStatus/failBody。
	failAction string
	failStatus int
	failBody   string
	failTimes  int
}

func newFakeAlidns() *fakeAlidns {
	return &fakeAlidns{
		records:        map[uint64]fakeRecord{},
		actionAttempts: map[string]int{},
		captures:       map[string][]url.Values{},
	}
}

func (f *fakeAlidns) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	action := r.Header.Get("x-acs-action")
	if action == "" {
		action = query.Get("Action")
	}
	f.mu.Lock()
	f.actionAttempts[action]++
	attempt := f.actionAttempts[action]
	f.captures[action] = append(f.captures[action], query)
	f.lastHeaders = r.Header.Clone()
	fail := action == f.failAction && attempt <= f.failTimes
	status, body := f.failStatus, f.failBody
	f.mu.Unlock()
	if fail {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
		return
	}
	switch action {
	case "AddDomainRecord":
		rr := query.Get("RR")
		value := query.Get("Value")
		f.mu.Lock()
		f.nextID++
		id := 1000 + f.nextID
		f.records[id] = fakeRecord{rr: rr, value: value}
		f.mu.Unlock()
		writeFakeJSON(w, http.StatusOK, map[string]any{"RecordId": strconv.FormatUint(id, 10), "RequestId": "req-add"})
	case "DeleteDomainRecord":
		id, _ := strconv.ParseUint(query.Get("RecordId"), 10, 64)
		f.mu.Lock()
		if _, ok := f.records[id]; !ok {
			f.mu.Unlock()
			writeFakeJSON(w, http.StatusBadRequest, map[string]any{
				"Code": "InvalidRecordId", "Message": "The specified record is not found", "RequestId": "req-del-missing",
			})
			return
		}
		delete(f.records, id)
		f.deleted = append(f.deleted, id)
		f.mu.Unlock()
		writeFakeJSON(w, http.StatusOK, map[string]any{"RecordId": strconv.FormatUint(id, 10), "RequestId": "req-del"})
	case "DescribeDomainRecords":
		type listed struct {
			RecordId string `json:"RecordId"`
			RR       string `json:"RR"`
			Type     string `json:"Type"`
			Value    string `json:"Value"`
		}
		f.mu.Lock()
		list := make([]listed, 0, len(f.records))
		ids := make([]uint64, 0, len(f.records))
		for id := range f.records {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			record := f.records[id]
			list = append(list, listed{RecordId: strconv.FormatUint(id, 10), RR: record.rr, Type: "TXT", Value: record.value})
		}
		f.mu.Unlock()
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"TotalCount": len(list), "DomainRecords": map[string]any{"Record": list}, "RequestId": "req-list",
		})
	default:
		writeFakeJSON(w, http.StatusBadRequest, map[string]any{"Code": "InvalidAction", "Message": "unknown action " + action, "RequestId": "req-x"})
	}
}

func writeFakeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (f *fakeAlidns) alive(recordID uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.records[recordID]
	return ok
}

func (f *fakeAlidns) attempts(action string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.actionAttempts[action]
}

func (f *fakeAlidns) inject(action string, status int, body string, times int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failAction, f.failStatus, f.failBody, f.failTimes = action, status, body, times
}

// newFakeProvider 构造指向假服务端的 provider，重试包络按测试速度缩放。
func newFakeProvider(t *testing.T, serverURL string, attempts int) *Provider {
	t.Helper()
	provider, err := New("test-access-key-id", "test-access-key-secret")
	if err != nil {
		t.Fatalf("create aliyun provider: %v", err)
	}
	provider.endpoint = serverURL
	provider.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &retry.Transport{
			Base:           &throttlingTransport{base: http.DefaultTransport},
			Attempts:       attempts,
			InitialBackoff: time.Millisecond,
			MaxBackoff:     5 * time.Millisecond,
		},
	}
	return provider
}

func newFakeServer(t *testing.T, fake *fakeAlidns) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return server
}

const (
	testZone     = "example.com"
	testFQDN     = "_acme-challenge.www.example.com."
	testValue    = "challenge-value"
	foreignAcct  = "ffffffff"
	accountMatch = "_acme-challenge.www"
)

// captureWarnings 截获包级 logf 告警（镜像 tencent 侧同名 helper）。
func captureWarnings(t *testing.T) *strings.Builder {
	t.Helper()
	var warnings strings.Builder
	oldLogf := logf
	logf = func(level, format string, args ...any) {
		if level == "warn" {
			fmt.Fprintf(&warnings, format, args...)
		}
	}
	t.Cleanup(func() { logf = oldLogf })
	return &warnings
}

func seedOwnershipRecord(t *testing.T, dataDir string, record ownership.Record) {
	t.Helper()
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	if err := store.Add(record); err != nil {
		t.Fatalf("seed ownership record %+v: %v", record, err)
	}
}

// ---------------------------------------------------------------------------
// 行为用例
// ---------------------------------------------------------------------------

// Present 落 TXT（RR 为相对名、Type=TXT、TTL 原样透传）并把 RecordId 写入
// 所有权账本（带账户摘要）。签名头形态在真实 HTTP 通路上断言。
func TestProvider_Present_createsChallengeRecordAndPersistsOwnership(t *testing.T) {
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	dataDir := t.TempDir()
	provider, err := NewPersistent("test-access-key-id", "test-access-key-secret", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.endpoint = server.URL

	if err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600); err != nil {
		t.Fatalf("present: %v", err)
	}

	// 请求形态：RR 必须是相对 zone 的子域（不得带 zone 后缀整体落名），
	// Type=TXT、TTL 透传、DomainName 为归一 zone。
	fake.mu.Lock()
	queries := fake.captures["AddDomainRecord"]
	headers := fake.lastHeaders
	fake.mu.Unlock()
	if len(queries) != 1 {
		t.Fatalf("AddDomainRecord calls=%d, want 1", len(queries))
	}
	query := queries[0]
	if query.Get("DomainName") != testZone {
		t.Fatalf("DomainName=%q, want %q", query.Get("DomainName"), testZone)
	}
	if query.Get("RR") != accountMatch {
		t.Fatalf("RR=%q, want %q（相对名，不带 zone 后缀）", query.Get("RR"), accountMatch)
	}
	if query.Get("Type") != "TXT" || query.Get("Value") != testValue || query.Get("TTL") != "600" {
		t.Fatalf("record params=%v, want Type=TXT Value=%s TTL=600", query, testValue)
	}
	if headers.Get("x-acs-version") != apiVersion {
		t.Fatalf("x-acs-version=%q, want %q", headers.Get("x-acs-version"), apiVersion)
	}
	if headers.Get("x-acs-action") != "AddDomainRecord" {
		t.Fatalf("x-acs-action=%q", headers.Get("x-acs-action"))
	}
	if headers.Get("x-acs-content-sha256") == "" || headers.Get("x-acs-date") == "" || headers.Get("x-acs-signature-nonce") == "" {
		t.Fatalf("acs3 signing headers incomplete: %v", headers)
	}
	if !strings.HasPrefix(headers.Get("Authorization"), signAlgorithm+" Credential=test-access-key-id,") {
		t.Fatalf("Authorization=%q", headers.Get("Authorization"))
	}
	if strings.Contains(headers.Get("Authorization"), "test-access-key-secret") {
		t.Fatal("Authorization 不得出现 AccessKeySecret")
	}

	// 账本：条目带 provider=aliyun + 本实例账户摘要 + 真实 RecordId。
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen ownership store: %v", err)
	}
	entries, err := store.Matching("aliyun", testZone, testFQDN)
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ownership entries=%d, want 1", len(entries))
	}
	wantAccount := ownership.AccountDigest("test-access-key-id\x00test-access-key-secret")
	if entries[0].Account != wantAccount {
		t.Fatalf("account=%q, want %q", entries[0].Account, wantAccount)
	}
	recordID, err := strconv.ParseUint(entries[0].RecordID, 10, 64)
	if err != nil {
		t.Fatalf("persisted RecordID %q: %v", entries[0].RecordID, err)
	}
	if !fake.alive(recordID) {
		t.Fatalf("record %d not alive on fake", recordID)
	}
	if entries[0].Value != testValue {
		t.Fatalf("ownership value=%q, want %q", entries[0].Value, testValue)
	}
}

// CleanUpValue 只删本值记录：同名并发签发的另一值记录必须幸存，
// 账本也只移除本值条目。账本命中路径不做网络枚举（与 tencent/dnspod 同构）。
func TestProvider_CleanUpValue_deletesOnlyMatchingValue(t *testing.T) {
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	dataDir := t.TempDir()
	provider, err := NewPersistent("test-access-key-id", "test-access-key-secret", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.endpoint = server.URL

	if err := provider.Present(t.Context(), testZone, testFQDN, "value-alpha", 600); err != nil {
		t.Fatalf("present alpha: %v", err)
	}
	if err := provider.Present(t.Context(), testZone, testFQDN, "value-beta", 600); err != nil {
		t.Fatalf("present beta: %v", err)
	}
	fake.mu.Lock()
	ids := make([]uint64, 0, len(fake.records))
	values := map[uint64]string{}
	for id, record := range fake.records {
		ids = append(ids, id)
		values[id] = record.value
	}
	fake.mu.Unlock()
	var alphaID, betaID uint64
	for _, id := range ids {
		switch values[id] {
		case "value-alpha":
			alphaID = id
		case "value-beta":
			betaID = id
		}
	}
	if alphaID == 0 || betaID == 0 {
		t.Fatalf("fake records=%v", values)
	}

	if err := provider.CleanUpValue(t.Context(), testZone, testFQDN, "value-alpha"); err != nil {
		t.Fatalf("clean up value: %v", err)
	}
	if fake.alive(alphaID) {
		t.Fatal("alpha 记录必须被删除")
	}
	if !fake.alive(betaID) {
		t.Fatal("beta 记录（并发签发）必须幸存")
	}
	if fake.attempts("DescribeDomainRecords") != 0 {
		t.Fatal("账本命中路径不得做网络枚举")
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	left, err := store.Matching("aliyun", testZone, testFQDN)
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 1 || left[0].Value != "value-beta" {
		t.Fatalf("ownership left=%+v, want 仅 beta 条目", left)
	}
}

// 删除时记录已不存在（InvalidRecordId 族）按删除成功处理：清理幂等，
// 不残留所有权条目。
func TestProvider_CleanUpValue_treatsRecordNotFoundAsSuccess(t *testing.T) {
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	dataDir := t.TempDir()
	provider, err := NewPersistent("test-access-key-id", "test-access-key-secret", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.endpoint = server.URL
	if err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600); err != nil {
		t.Fatalf("present: %v", err)
	}
	fake.mu.Lock()
	for id := range fake.records {
		delete(fake.records, id) // 直接从服务端消失（控制台手工删除）
	}
	fake.mu.Unlock()

	if err := provider.CleanUpValue(t.Context(), testZone, testFQDN, testValue); err != nil {
		t.Fatalf("clean up on missing record must be idempotent success: %v", err)
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	left, err := store.Matching("aliyun", testZone, testFQDN)
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("ownership left=%+v, want 空（幂等删除后条目移除）", left)
	}
}

// 账本未命中（TXT 在 provider 侧存在但无账本条目可追踪）→ DescribeDomainRecords
// 兜底排空按值匹配删除；另一值的残余记录不得被误删。
func TestProvider_CleanUpValue_sweepsUntrackedRecordByValue(t *testing.T) {
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	writer := newFakeProvider(t, server.URL, 3)
	if err := writer.Present(t.Context(), testZone, testFQDN, "stale-value", 600); err != nil {
		t.Fatalf("present stale: %v", err)
	}
	if err := writer.Present(t.Context(), testZone, testFQDN, "other-value", 600); err != nil {
		t.Fatalf("present other: %v", err)
	}
	// sweeper 是全新 provider 实例（账本/内存均无条目——模拟账本退役/丢失）。
	sweeper := newFakeProvider(t, server.URL, 3)

	if err := sweeper.CleanUpValue(t.Context(), testZone, testFQDN, "stale-value"); err != nil {
		t.Fatalf("clean up with empty ledger: %v", err)
	}
	alive := 0
	fake.mu.Lock()
	for _, record := range fake.records {
		if record.value == "stale-value" {
			alive++
		}
	}
	fake.mu.Unlock()
	if alive != 0 {
		t.Fatal("按值兜底排空必须删除无账本条目的同值记录")
	}
	if !fake.alive(1002) {
		t.Fatal("另一值记录不得被误删")
	}
	if fake.attempts("DescribeDomainRecords") == 0 {
		t.Fatal("账本未命中必须触发 DescribeDomainRecords 兜底枚举")
	}
}

// 兜底枚举失败（provider 5xx）必须上抛，不得静默。
func TestProvider_CleanUpValue_sweepFailureSurfacesError(t *testing.T) {
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	fake.inject("DescribeDomainRecords", http.StatusInternalServerError,
		`{"Code":"InternalError","Message":"boom","RequestId":"req-500"}`, 5)
	provider := newFakeProvider(t, server.URL, 1)

	err := provider.CleanUpValue(t.Context(), testZone, testFQDN, testValue)
	if err == nil {
		t.Fatal("DescribeDomainRecords 5xx 必须上抛")
	}
	if !strings.Contains(err.Error(), "DescribeDomainRecords") {
		t.Fatalf("error=%v, want 点名 DescribeDomainRecords", err)
	}
}

// 账户归属：他账户遗留条目 MUST NOT 按 record_id 调删除（ID 可能指向无关
// 记录），只丢弃本地条目并留告警；账本有候选时不做兜底枚举。
func TestProvider_CleanUpValue_doesNotDeleteForeignAccountRecord(t *testing.T) {
	dataDir := t.TempDir()
	seedOwnershipRecord(t, dataDir, ownership.Record{
		Provider:  "aliyun",
		Zone:      testZone,
		FQDN:      testFQDN,
		Value:     testValue,
		RecordID:  "200",
		Account:   foreignAcct,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})
	fake := newFakeAlidns()
	fake.mu.Lock()
	fake.records[200] = fakeRecord{rr: accountMatch, value: testValue}
	fake.mu.Unlock()
	server := newFakeServer(t, fake)
	provider, err := NewPersistent("test-access-key-id", "test-access-key-secret", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.endpoint = server.URL
	warnings := captureWarnings(t)

	if err := provider.CleanUpValue(t.Context(), testZone, testFQDN, testValue); err != nil {
		t.Fatalf("clean up: %v", err)
	}
	if !fake.alive(200) {
		t.Fatal("他账户条目的 record_id 被调用删除（DeleteDomainRecord 不应被调用）")
	}
	if fake.attempts("DescribeDomainRecords") != 0 {
		t.Fatal("账本有候选时不得做兜底枚举")
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	left, err := store.Matching("aliyun", testZone, testFQDN)
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("ownership left=%+v, want 他账户条目被丢弃", left)
	}
	if !strings.Contains(warnings.String(), "无法归属当前账户") {
		t.Fatalf("warnings=%q, want 丢弃原因留痕", warnings.String())
	}
}

// ownership.Add 失败且回滚删除亦失败：告警留痕 + 回填内存兜底表；
// 恢复后 cleanUp 排空兜底表重试删除（无追踪窗口收口）。
func TestProvider_Present_ownershipAddAndRollbackFailureRefillsFallback(t *testing.T) {
	dataDir := t.TempDir()
	fake := newFakeAlidns()
	fake.inject("DeleteDomainRecord", http.StatusInternalServerError,
		`{"Code":"InternalError","Message":"boom","RequestId":"req-500"}`, 1)
	server := newFakeServer(t, fake)
	provider, err := NewPersistent("test-access-key-id", "test-access-key-secret", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.endpoint = server.URL
	provider.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &retry.Transport{
			Base:           &throttlingTransport{base: http.DefaultTransport},
			Attempts:       1,
			InitialBackoff: time.Millisecond,
			MaxBackoff:     5 * time.Millisecond,
		},
	}
	warnings := captureWarnings(t)
	ownershipPath := filepath.Join(dataDir, "acme_dns_ownership.json")
	if err := os.Mkdir(ownershipPath, 0o755); err != nil {
		t.Fatalf("block ownership file with directory: %v", err)
	}

	err = provider.Present(t.Context(), testZone, testFQDN, testValue, 600)
	if err == nil {
		t.Fatal("ownership.Add 失败 + 回滚删除失败必须上报，不得静默")
	}
	if !strings.Contains(warnings.String(), "aliyun: 所有权写入失败") {
		t.Fatalf("残留告警必须经 logf 接缝进入统一日志链，captured=%q", warnings.String())
	}
	provider.mu.Lock()
	entries := append([]ownedRecord(nil), provider.owned["example.com|"+accountMatch]...)
	provider.mu.Unlock()
	if len(entries) != 1 {
		t.Fatalf("owned fallback=%+v, want 孤儿记录回填", entries)
	}
	orphan := entries[0].recordID
	if !fake.alive(orphan) {
		t.Fatalf("orphan %d not alive on fake", orphan)
	}

	// 恢复：存储与删除均可用 → CleanUp 排空兜底表并删除孤儿记录。
	if err := os.Remove(ownershipPath); err != nil {
		t.Fatalf("remove blocking ownership directory: %v", err)
	}
	fake.mu.Lock()
	fake.failTimes = 0
	fake.mu.Unlock()
	if err := provider.CleanUp(t.Context(), testZone, testFQDN); err != nil {
		t.Fatalf("clean up after recovery: %v", err)
	}
	if fake.alive(orphan) {
		t.Fatal("兜底条目必须在 cleanUp 中被删除（无追踪窗口未收口）")
	}
	provider.mu.Lock()
	left := provider.owned["example.com|"+accountMatch]
	provider.mu.Unlock()
	if len(left) != 0 {
		t.Fatalf("排空成功后兜底表须清空, got %+v", left)
	}
}

// CountCleanupRecords 纯本地计数（账本 + 内存兜底），不得发起网络请求。
func TestProvider_CountCleanupRecords_pureLocalCount(t *testing.T) {
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	dataDir := t.TempDir()
	provider, err := NewPersistent("test-access-key-id", "test-access-key-secret", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.endpoint = server.URL
	if err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600); err != nil {
		t.Fatalf("present: %v", err)
	}
	provider.mu.Lock()
	provider.owned["example.com|"+accountMatch] = append(provider.owned["example.com|"+accountMatch],
		ownedRecord{recordID: 424242, value: testValue})
	provider.mu.Unlock()

	if got := provider.CountCleanupRecords(testZone, testFQDN, testValue); got != 2 {
		t.Fatalf("count=%d, want 2（账本 1 + 兜底 1）", got)
	}
	if fake.attempts("DescribeDomainRecords") != 0 {
		t.Fatal("计数必须纯本地，不得网络往返")
	}
}

// 空值按值清理必须 fail-fast（与 dnspod/tencent 同口径：防退化为按名清空）。
func TestProvider_CleanUpValue_rejectsEmptyValue(t *testing.T) {
	provider, err := New("ak", "sk")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	if err := provider.CleanUpValue(t.Context(), testZone, testFQDN, "  "); err == nil {
		t.Fatal("空值 CleanUpValue 必须报错")
	}
}

// String 脱敏形态：只暴露账户摘要，任何序列化/日志路径不得回显凭据。
func TestProvider_StringDoesNotLeakSecrets(t *testing.T) {
	provider, err := New("id-abcdef1234", "secret-abcdef1234")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	text := provider.String()
	if strings.Contains(text, "secret-abcdef1234") || strings.Contains(text, "id-abcdef1234") {
		t.Fatalf("String()=%q 泄露凭据", text)
	}
	if !strings.Contains(text, "account:") {
		t.Fatalf("String()=%q 缺账户摘要", text)
	}
}

// 错误链脱敏：provider 错误体回显凭据明文时必须被定向替换；
// 变体回声（替换后仍残留）整段丢弃。
func TestProvider_errorsSanitizeCredentialEcho(t *testing.T) {
	echoBody := `{"Code":"InvalidAccessKeyId","Message":"key secret-abcdef1234 is disabled","RequestId":"req-echo"}`
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	fake.inject("AddDomainRecord", http.StatusBadRequest, echoBody, 5)
	provider := newFakeProvider(t, server.URL, 1)
	provider.accessKeyID = "id-abcdef1234"
	provider.accessKeySecret = "secret-abcdef1234"

	err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600)
	if err == nil {
		t.Fatal("AddDomainRecord 4xx 必须报错")
	}
	if strings.Contains(err.Error(), "secret-abcdef1234") {
		t.Fatalf("错误文案泄露凭据: %v", err)
	}
	if !strings.Contains(err.Error(), "InvalidAccessKeyId") {
		t.Fatalf("错误文案应保留错误码便于排障: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ACS3-HMAC-SHA256 签名固定向量（阿里云官方《原生 HTTP 调用》文档固定参数示例，
// RFC 8032 式：输入与期望输出全部钉死，实现漂移即红灯）。
// ---------------------------------------------------------------------------

const (
	vectorAK                 = "YourAccessKeyId"
	vectorSK                 = "YourAccessKeySecret"
	vectorNonce              = "3156853299f313e23d1673dc12e1703d"
	vectorDate               = "2023-10-26T10:22:32Z"
	vectorHost               = "ecs.cn-shanghai.aliyuncs.com"
	vectorAction             = "RunInstances"
	vectorVersion            = "2014-05-26"
	vectorQuery              = "ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai"
	vectorStringToSignDigest = "7ea06492da5221eba5297e897ce16e55f964061054b7695beedaac1145b1e259"
	vectorSignature          = "06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0"
)

func vectorSigningInput() signingInput {
	return signingInput{
		method:  http.MethodPost,
		host:    vectorHost,
		path:    "/",
		query:   vectorQuery,
		action:  vectorAction,
		version: vectorVersion,
		date:    vectorDate,
		nonce:   vectorNonce,
	}
}

func TestSigning_officialFixedVector(t *testing.T) {
	input := vectorSigningInput()

	stringToSign := input.stringToSign()
	wantStringToSign := signAlgorithm + "\n" + vectorStringToSignDigest
	if stringToSign != wantStringToSign {
		t.Fatalf("stringToSign=%q, want %q", stringToSign, wantStringToSign)
	}

	wantAuthorization := fmt.Sprintf(
		"%s Credential=%s,SignedHeaders=%s,Signature=%s",
		signAlgorithm, vectorAK,
		"host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version",
		vectorSignature)
	if got := input.authorization(vectorAK, vectorSK); got != wantAuthorization {
		t.Fatalf("authorization=\n%q\nwant\n%q", got, wantAuthorization)
	}
}

// 规范化请求串逐段钉死（含 CanonicalHeaders 尾随换行与空行分隔形态）。
func TestSigning_canonicalRequestBody(t *testing.T) {
	input := vectorSigningInput()
	want := strings.Join([]string{
		"POST",
		"/",
		vectorQuery,
		"host:" + vectorHost + "\n" +
			"x-acs-action:" + vectorAction + "\n" +
			"x-acs-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
			"x-acs-date:" + vectorDate + "\n" +
			"x-acs-signature-nonce:" + vectorNonce + "\n" +
			"x-acs-version:" + vectorVersion + "\n",
		"host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}, "\n")
	if got := input.canonicalRequest(); got != want {
		t.Fatalf("canonicalRequest=\n%q\nwant\n%q", got, want)
	}
}

// RFC3986 编码表：保留字符不编码、其余 %XX 大写（空格 %20、+ %2B、* %2A、
// 波浪号原样、多字节 UTF-8 逐字节编码）。
func TestAcsURIEncode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain", "plain"},
		{"a-b_c.d~e", "a-b_c.d~e"},
		{"hello world", "hello%20world"},
		{"a+b", "a%2Bb"},
		{"a*b", "a%2Ab"},
		{"a/b", "a%2Fb"},
		{"a=b&c", "a%3Db%26c"},
		{"值", "%E5%80%BC"},
		{"", ""},
	} {
		if got := acsURIEncode(tc.in); got != tc.want {
			t.Errorf("acsURIEncode(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

// 规范化查询串按参数名升序排列（乱序入参 → 有序输出）。
func TestCanonicalQueryString_sortsAndEncodes(t *testing.T) {
	got := canonicalQueryString(map[string]string{
		"RegionId": "cn-shanghai",
		"ImageId":  "win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd",
		"Value":    "a b+c",
	})
	want := "ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai&Value=a%20b%2Bc"
	if got != want {
		t.Fatalf("canonicalQueryString=%q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// 重试映射：Throttling 400 → 429 语义（重试）；AddDomainRecord 5xx 不重放
// （幽灵 TXT）；其他 4xx 不重试。
// ---------------------------------------------------------------------------

// Alidns 限流走 HTTP 400 + Code=Throttling：throttlingTransport 改写为 429
// 后由共享 retry.Transport 重试，body 原样保留（错误解析仍读到真实 Code）。
func TestProvider_Present_throttlingIsRetriedThrough429Rewrite(t *testing.T) {
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	fake.inject("AddDomainRecord", http.StatusBadRequest,
		`{"Code":"Throttling","Message":"Request throttled.","RequestId":"req-throttle"}`, 1)
	provider := newFakeProvider(t, server.URL, 3)

	if err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600); err != nil {
		t.Fatalf("present after throttle retry: %v", err)
	}
	if got := fake.attempts("AddDomainRecord"); got != 2 {
		t.Fatalf("AddDomainRecord attempts=%d, want 2（限流必须重试一次后成功）", got)
	}
}

// 限流重试耗尽：错误可读（点名限流），不是裸 4xx。
func TestProvider_Present_throttlingExhaustionReportsThrottle(t *testing.T) {
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	fake.inject("AddDomainRecord", http.StatusBadRequest,
		`{"Code":"Throttling","Message":"Request throttled.","RequestId":"req-throttle"}`, 9)
	provider := newFakeProvider(t, server.URL, 2)

	err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600)
	if err == nil {
		t.Fatal("限流耗尽必须报错")
	}
	if !strings.Contains(err.Error(), "Throttling") {
		t.Fatalf("error=%v, want 保留 Throttling 错误码", err)
	}
}

// 创建类动作 5xx 不重放（重试会在 DNS 侧产生无 ID 幽灵 TXT）：
// 只打一发即返回错误。
func TestProvider_Present_addRecord5xxNotReplayed(t *testing.T) {
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	fake.inject("AddDomainRecord", http.StatusInternalServerError,
		`{"Code":"InternalError","Message":"boom","RequestId":"req-500"}`, 9)
	provider := newFakeProvider(t, server.URL, 3)

	if err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600); err == nil {
		t.Fatal("AddDomainRecord 5xx 必须报错")
	}
	if got := fake.attempts("AddDomainRecord"); got != 1 {
		t.Fatalf("AddDomainRecord attempts=%d, want 1（创建类 5xx 不重放）", got)
	}
}

// 删除类动作 5xx 重试（非创建类动作维持重试语义）：耗尽后报错，
// 且所有权条目留存（记录可能仍存在，删除失败不得移除账本）。
func TestProvider_CleanUp_delete5xxRetriedThenFailsKeepsOwnership(t *testing.T) {
	fake := newFakeAlidns()
	server := newFakeServer(t, fake)
	dataDir := t.TempDir()
	provider, err := NewPersistent("test-access-key-id", "test-access-key-secret", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.endpoint = server.URL
	provider.httpClient = newFakeProvider(t, server.URL, 3).httpClient
	if err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600); err != nil {
		t.Fatalf("present: %v", err)
	}
	fake.inject("DeleteDomainRecord", http.StatusInternalServerError,
		`{"Code":"InternalError","Message":"boom","RequestId":"req-500"}`, 9)

	if err := provider.CleanUpValue(t.Context(), testZone, testFQDN, testValue); err == nil {
		t.Fatal("DeleteDomainRecord 5xx 耗尽后必须报错")
	}
	if got := fake.attempts("DeleteDomainRecord"); got != 3 {
		t.Fatalf("DeleteDomainRecord attempts=%d, want 3（非创建类动作维持重试）", got)
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	left, err := store.Matching("aliyun", testZone, testFQDN)
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 1 {
		t.Fatalf("ownership left=%+v, want 删除失败条目留存（记录可能仍存在）", left)
	}
}

package dnspod

// provider 侧残余排空（与 aliyun 侧同构，见 aliyun.go cleanUp 注释）：
// 「创建超时但服务端已建记录」「ownership.Add 失败且回滚删除失败后兜底表丢失」
// 「账本条目退役/丢失」三类账本脱追踪形态下，TXT 会在 provider 侧永久残留。
// 修复=cleanUp 尾部枚举（Record.List 按 domain+sub_domain 过滤）+ RR 精确
// 匹配 + 按值删除；触发口径=账本与内存双空且零删除尝试（保住他账户
// 「不删除」语义：有任一候选即不做网络枚举）。
//
// 假 transport 在 dnsPodRecordTransport 之上补 RR 名与 Record.List 服务端
// 过滤，注入「清理时记录已存在但本地无任何追踪」形态。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// dnsPodListRequest 是 Record.List 请求参数留档：服务端过滤口径
// （domain_id+sub_domain+record_type）错了，枚举要么查空、要么越名误删。
type dnsPodListRequest struct {
	DomainID   string
	SubDomain  string
	RecordType string
	Offset     string
	Length     string
}

// drainAwareTransport 在 dnsPodRecordTransport 之上补 Record.List 端点：
// names 映射 recordID → RR（主机记录），按 sub_domain/record_type 服务端
// 过滤语义返回匹配记录；其余端点委托基础 transport。
type drainAwareTransport struct {
	dnsPodRecordTransport
	// names 记录 recordID → RR；缺省（nil）视为无 RR 信息，Record.List 回空。
	names map[string]string
	lists []dnsPodListRequest
	// listEmptyStatusCode 是「无匹配记录」时返回的 status.code：默认 "1" +
	// 空 records；可注入 "10"（空结果）钉住该响应形态。
	listEmptyStatusCode string
	// failListTimes 让 Record.List 先失败 N 次（HTTP 500）。
	failListTimes    int
	failListAttempts int
	// failRemoveTimes 让 Record.Remove 先失败 N 次（HTTP 500）——枚举删除
	// 失败必须回填兜底表供下次重试。
	failRemoveTimes    int
	failRemoveAttempts int
}

func (transport *drainAwareTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, "Record.List") {
		return transport.roundTripRecordList(request)
	}
	if strings.HasSuffix(request.URL.Path, "Record.Remove") {
		transport.mu.Lock()
		transport.failRemoveAttempts++
		failing := transport.failRemoveAttempts <= transport.failRemoveTimes
		transport.mu.Unlock()
		if failing {
			if _, err := io.ReadAll(request.Body); err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"-1","message":"simulated outage"}}`)),
				Request:    request,
			}, nil
		}
	}
	return transport.dnsPodRecordTransport.RoundTrip(request)
}

func (transport *drainAwareTransport) roundTripRecordList(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.lists = append(transport.lists, dnsPodListRequest{
		DomainID:   params.Get("domain_id"),
		SubDomain:  params.Get("sub_domain"),
		RecordType: params.Get("record_type"),
		Offset:     params.Get("offset"),
		Length:     params.Get("length"),
	})
	transport.failListAttempts++
	if transport.failListAttempts <= transport.failListTimes {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"-1","message":"simulated outage"}}`)),
			Request:    request,
		}, nil
	}
	subDomain := params.Get("sub_domain")
	type listedRecord struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	records := make([]listedRecord, 0)
	for id, value := range transport.records {
		if transport.names[id] != subDomain {
			continue
		}
		records = append(records, listedRecord{ID: id, Name: subDomain, Type: "TXT", Value: value})
	}
	statusCode := transport.listEmptyStatusCode
	if len(records) > 0 || statusCode == "" {
		statusCode = "1"
	}
	responseBody, err := json.Marshal(map[string]any{
		"status":  map[string]string{"code": statusCode, "message": "ok"},
		"records": records,
		"info":    map[string]string{"record_total": strconv.Itoa(len(records))},
	})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(responseBody))),
		Request:    request,
	}, nil
}

func (transport *drainAwareTransport) listAttempts() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return len(transport.lists)
}

// 创建超时但服务端已建记录：全新 sweeper 实例（账本/内存均无条目）执行
// CleanUpValue 时，Record.List 兜底枚举必须按值删除同值幽灵记录，且另一值
// 记录（并发签发）不得被误删。
func TestProvider_CleanUpValue_sweepsUntrackedRecordByValue(t *testing.T) {
	transport := &drainAwareTransport{
		dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{
			"500": "stale-value",
			"501": "other-value",
		}},
		names: map[string]string{
			"500": "_acme-challenge",
			"501": "_acme-challenge",
		},
	}
	provider := New("id,token")
	provider.client.Transport = transport

	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "stale-value"); err != nil {
		t.Fatalf("clean up with empty ledger: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.records) != 1 || transport.records["501"] != "other-value" {
		t.Fatalf("remaining records=%v, want 仅另一值记录（并发签发）幸存", transport.records)
	}
	for _, removed := range transport.removes {
		if removed == "501" {
			t.Fatal("另一值记录被调用删除（并发签发 TXT 不得误删）")
		}
	}
	if len(transport.lists) == 0 {
		t.Fatal("账本未命中必须触发 Record.List 兜底枚举")
	}
	// 服务端过滤口径：sub_domain 精确名 + TXT 类型，错则枚举查空或越名。
	for _, list := range transport.lists {
		if list.SubDomain != "_acme-challenge" {
			t.Fatalf("Record.List sub_domain=%q, want 精确主机记录名", list.SubDomain)
		}
		if list.RecordType != "TXT" {
			t.Fatalf("Record.List record_type=%q, want TXT", list.RecordType)
		}
	}
}

// RR 精确匹配：按名清理（CleanUp）只清空精确主机记录名下的全部 TXT 幽灵，
// 其他名字（_acme-challenge.www、无关 RR）不得波及。
func TestProvider_CleanUp_sweepsAllGhostRecordsUnderExactRR(t *testing.T) {
	transport := &drainAwareTransport{
		dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{
			"500": "ghost-alpha",
			"501": "ghost-beta",
			"502": "www-ghost",
			"503": "dev-record",
		}},
		names: map[string]string{
			"500": "_acme-challenge",
			"501": "_acme-challenge",
			"502": "_acme-challenge.www",
			"503": "dev",
		},
	}
	provider := New("id,token")
	provider.client.Transport = transport

	if err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("clean up with empty ledger: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if _, alive := transport.records["500"]; alive {
		t.Fatal("幽灵记录 500（同 RR）必须被排空删除")
	}
	if _, alive := transport.records["501"]; alive {
		t.Fatal("幽灵记录 501（同 RR）必须被排空删除")
	}
	if _, alive := transport.records["502"]; !alive {
		t.Fatal("另一主机记录名（_acme-challenge.www）的记录被误删")
	}
	if _, alive := transport.records["503"]; !alive {
		t.Fatal("无关 RR（dev）的记录被误删")
	}
}

// 触发口径：账本有候选（他账户遗留条目，按值会被选中）时不得做网络枚举
// ——枚举只见当前账户记录，而候选链路仍在，兜底排空只会平添往返且可能
// 越权删除；他账户条目照旧只丢弃不删除。
func TestProvider_CleanUpValue_doesNotEnumerateWhenLedgerHasCandidates(t *testing.T) {
	dataDir := t.TempDir()
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	if err := store.Add(ownership.Record{
		Provider:  "dnspod",
		Zone:      "example.com",
		FQDN:      "_acme-challenge.example.com.",
		Value:     "alpha",
		RecordID:  "500",
		Account:   "ffffffff",
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("seed ownership record: %v", err)
	}
	transport := &drainAwareTransport{
		dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{"500": "alpha"}},
		names:                 map[string]string{"500": "_acme-challenge"},
	}
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport

	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "alpha"); err != nil {
		t.Fatalf("clean up: %v（他账户条目只丢弃，不该报错）", err)
	}
	if transport.listAttempts() != 0 {
		t.Fatal("账本有候选时不得做 Record.List 兜底枚举")
	}
	transport.mu.Lock()
	_, alive := transport.records["500"]
	transport.mu.Unlock()
	if !alive {
		t.Fatal("他账户条目的 record_id 被调用删除（Record.Remove 不应被调用）")
	}
}

// 兜底枚举失败（provider 5xx）必须上抛，不得静默。
func TestProvider_CleanUpValue_sweepFailureSurfacesError(t *testing.T) {
	transport := &drainAwareTransport{
		dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{}},
		failListTimes:         5,
	}
	provider := New("id,token")
	provider.client.Transport = transport

	err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "value")
	if err == nil {
		t.Fatal("Record.List 5xx 必须上抛")
	}
	if !strings.Contains(err.Error(), "Record.List") {
		t.Fatalf("error=%v, want 点名 Record.List", err)
	}
}

// Record.List 的「空结果」响应形态（code 10，无 records）：按空结果处理，
// 不报错、不删除——空结果不是故障。
func TestProvider_CleanUpValue_sweepEmptyResultCode10IsSuccess(t *testing.T) {
	transport := &drainAwareTransport{
		dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{}},
		listEmptyStatusCode:   "10",
	}
	provider := New("id,token")
	provider.client.Transport = transport

	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "value"); err != nil {
		t.Fatalf("clean up with empty-result list: %v（code 10 是空结果，不是故障）", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.removes) != 0 {
		t.Fatalf("Record.Remove calls=%v, want 零删除", transport.removes)
	}
}

// 枚举删除失败：错误上抛 + 幽灵记录回填内存兜底表；恢复后下一次清理经兜底
// 表重试删除成功，且不再做网络枚举（有候选即不枚举）。
func TestProvider_CleanUpValue_sweepDeleteFailureRefillsFallbackForRetry(t *testing.T) {
	transport := &drainAwareTransport{
		dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{
			"500": "stale-value",
		}},
		names:           map[string]string{"500": "_acme-challenge"},
		failRemoveTimes: 1,
	}
	provider := New("id,token")
	provider.client.Transport = transport

	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "stale-value"); err == nil {
		t.Fatal("枚举命中的删除失败必须上抛")
	}
	transport.mu.Lock()
	if _, alive := transport.records["500"]; !alive {
		transport.mu.Unlock()
		t.Fatal("删除失败的幽灵记录不应从 fake 消失")
	}
	transport.mu.Unlock()

	// 恢复后重试：兜底表条目直接命中删除，不再枚举。
	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "stale-value"); err != nil {
		t.Fatalf("retry clean up: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if _, alive := transport.records["500"]; alive {
		t.Fatal("兜底表重试必须删除幽灵记录")
	}
	if len(transport.lists) != 1 {
		t.Fatalf("Record.List attempts=%d, want 1（重试走兜底表，不做第二次枚举）", len(transport.lists))
	}
}

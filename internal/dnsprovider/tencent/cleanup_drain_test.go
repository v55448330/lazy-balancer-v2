package tencent

// provider 侧残余排空（与 aliyun 侧同构，见 aliyun.go cleanUp 注释）：
// 「创建超时但服务端已建记录」「ownership.Add 失败且回滚删除失败后兜底表丢失」
// 「账本条目退役/丢失」三类账本脱追踪形态下，TXT 会在 provider 侧永久残留。
// 修复=cleanUp 尾部枚举（DescribeRecordList 按 Domain+SubDomain 过滤）+
// RR 精确匹配 + 按值删除；触发口径=账本与内存双空且零删除尝试（保住他账户
// 「不删除」语义：有任一候选即不做网络枚举）。
//
// 假 transport 在 recordTransport 之上补 RR 名与 DescribeRecordList 端点，
// 注入「清理时记录已存在但本地无任何追踪」形态。

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// describeRecordListRequest 是 DescribeRecordList 请求体留档：服务端过滤
// 口径（Domain+SubDomain+RecordType）错了，枚举要么查空、要么越名误删。
type describeRecordListRequest struct {
	Domain     string `json:"Domain"`
	SubDomain  string `json:"SubDomain"`
	RecordType string `json:"RecordType"`
	Offset     uint64 `json:"Offset"`
	Limit      uint64 `json:"Limit"`
}

// drainAwareTransport 在 recordTransport 之上补 DescribeRecordList 端点：
// names 映射 recordID → RR（主机记录），按 SubDomain/RecordType 服务端
// 过滤语义返回匹配记录；其余动作委托基础 transport。
type drainAwareTransport struct {
	recordTransport
	// names 记录 recordID → RR；缺省（nil）视为无 RR 信息，枚举回空。
	names map[uint64]string
	lists []describeRecordListRequest
	// noDataOfRecord 让枚举返回 ResourceNotFound.NoDataOfRecord（查询不到
	// 数据的既有错误形态，ErrorOnEmpty=yes 的服务端默认行为）。
	noDataOfRecord bool
	// failListTimes 让 DescribeRecordList 先失败 N 次（HTTP 500）。
	failListTimes    int
	failListAttempts int
	// failDeleteTimes 让 DeleteRecord 先失败 N 次（HTTP 500）——枚举删除
	// 失败必须回填兜底表供下次重试。
	failDeleteTimes    int
	failDeleteAttempts int
}

func (transport *drainAwareTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Header.Get("X-TC-Action") == "DescribeRecordList" {
		return transport.roundTripDescribeRecordList(request)
	}
	if request.Header.Get("X-TC-Action") == "DeleteRecord" {
		transport.mu.Lock()
		transport.failDeleteAttempts++
		failing := transport.failDeleteAttempts <= transport.failDeleteTimes
		transport.mu.Unlock()
		if failing {
			if _, err := io.ReadAll(request.Body); err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"Response":{"Error":{"Code":"InternalError","Message":"simulated outage"},"RequestId":"test"}}`)),
				Request:    request,
			}, nil
		}
	}
	return transport.recordTransport.RoundTrip(request)
}

func (transport *drainAwareTransport) roundTripDescribeRecordList(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	var payload describeRecordListRequest
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.lists = append(transport.lists, payload)
	transport.failListAttempts++
	if transport.failListAttempts <= transport.failListTimes {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"Response":{"Error":{"Code":"InternalError","Message":"simulated outage"},"RequestId":"test"}}`)),
			Request:    request,
		}, nil
	}
	if transport.noDataOfRecord {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"Response":{"Error":{"Code":"ResourceNotFound.NoDataOfRecord","Message":"记录不存在"},"RequestId":"test"}}`)),
			Request:    request,
		}, nil
	}
	type listedRecord struct {
		RecordID uint64 `json:"RecordId"`
		Name     string `json:"Name"`
		Type     string `json:"Type"`
		Value    string `json:"Value"`
	}
	records := make([]listedRecord, 0)
	for id, value := range transport.records {
		if transport.names[id] != payload.SubDomain {
			continue
		}
		records = append(records, listedRecord{RecordID: id, Name: payload.SubDomain, Type: "TXT", Value: value})
	}
	responseBody, err := json.Marshal(map[string]any{
		"Response": map[string]any{
			"RecordCountInfo": map[string]uint64{"TotalCount": uint64(len(records)), "ListCount": uint64(len(records))},
			"RecordList":      records,
			"RequestId":       "test",
		},
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
// CleanUpValue 时，DescribeRecordList 兜底枚举必须按值删除同值幽灵记录，
// 且另一值记录（并发签发）不得被误删。
func TestProvider_CleanUpValue_sweepsUntrackedRecordByValue(t *testing.T) {
	transport := &drainAwareTransport{
		recordTransport: recordTransport{records: map[uint64]string{
			200: "stale-value",
			201: "other-value",
		}},
		names: map[uint64]string{
			200: "_acme-challenge",
			201: "_acme-challenge",
		},
	}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)

	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "stale-value"); err != nil {
		t.Fatalf("clean up with empty ledger: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.records) != 1 || transport.records[201] != "other-value" {
		t.Fatalf("remaining records=%v, want 仅另一值记录（并发签发）幸存", transport.records)
	}
	for _, removed := range transport.deletes {
		if removed == 201 {
			t.Fatal("另一值记录被调用删除（并发签发 TXT 不得误删）")
		}
	}
	if len(transport.lists) == 0 {
		t.Fatal("账本未命中必须触发 DescribeRecordList 兜底枚举")
	}
	// 服务端过滤口径：SubDomain 精确名 + TXT 类型，错则枚举查空或越名。
	for _, list := range transport.lists {
		if list.SubDomain != "_acme-challenge" {
			t.Fatalf("DescribeRecordList SubDomain=%q, want 精确主机记录名", list.SubDomain)
		}
		if list.RecordType != "TXT" {
			t.Fatalf("DescribeRecordList RecordType=%q, want TXT", list.RecordType)
		}
		if list.Domain != "example.com" {
			t.Fatalf("DescribeRecordList Domain=%q, want example.com", list.Domain)
		}
	}
}

// RR 精确匹配：按名清理（CleanUp）只清空精确主机记录名下的全部 TXT 幽灵，
// 其他名字（_acme-challenge.www、无关 RR）不得波及。
func TestProvider_CleanUp_sweepsAllGhostRecordsUnderExactRR(t *testing.T) {
	transport := &drainAwareTransport{
		recordTransport: recordTransport{records: map[uint64]string{
			200: "ghost-alpha",
			201: "ghost-beta",
			202: "www-ghost",
			203: "dev-record",
		}},
		names: map[uint64]string{
			200: "_acme-challenge",
			201: "_acme-challenge",
			202: "_acme-challenge.www",
			203: "dev",
		},
	}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)

	if err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("clean up with empty ledger: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if _, alive := transport.records[200]; alive {
		t.Fatal("幽灵记录 200（同 RR）必须被排空删除")
	}
	if _, alive := transport.records[201]; alive {
		t.Fatal("幽灵记录 201（同 RR）必须被排空删除")
	}
	if _, alive := transport.records[202]; !alive {
		t.Fatal("另一主机记录名（_acme-challenge.www）的记录被误删")
	}
	if _, alive := transport.records[203]; !alive {
		t.Fatal("无关 RR（dev）的记录被误删")
	}
}

// 触发口径：账本有候选（他账户遗留条目，按值会被选中）时不得做网络枚举
// ——枚举只见当前账户记录，而候选链路仍在，兜底排空只会平添往返且可能
// 越权删除；他账户条目照旧只丢弃不删除。
func TestProvider_CleanUpValue_doesNotEnumerateWhenLedgerHasCandidates(t *testing.T) {
	dataDir := t.TempDir()
	seedAccountRecord(t, dataDir, ownership.Record{
		Provider:  "tencent",
		Zone:      "example.com",
		FQDN:      "_acme-challenge.example.com.",
		Value:     "alpha",
		RecordID:  "200",
		Account:   foreignAccountID,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})
	transport := &drainAwareTransport{
		recordTransport: recordTransport{records: map[uint64]string{200: "alpha"}},
		names:           map[uint64]string{200: "_acme-challenge"},
	}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)

	if err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "alpha"); err != nil {
		t.Fatalf("clean up: %v（他账户条目只丢弃，不该报错）", err)
	}
	if transport.listAttempts() != 0 {
		t.Fatal("账本有候选时不得做 DescribeRecordList 兜底枚举")
	}
	transport.mu.Lock()
	_, alive := transport.records[200]
	transport.mu.Unlock()
	if !alive {
		t.Fatal("他账户条目的 record_id 被调用删除（DeleteRecord 不应被调用）")
	}
}

// 兜底枚举失败（provider 5xx）必须上抛，不得静默。
func TestProvider_CleanUpValue_sweepFailureSurfacesError(t *testing.T) {
	transport := &drainAwareTransport{
		recordTransport: recordTransport{records: map[uint64]string{}},
		failListTimes:   5,
	}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)

	cleanErr := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "value")
	if cleanErr == nil {
		t.Fatal("DescribeRecordList 5xx 必须上抛")
	}
	if !strings.Contains(cleanErr.Error(), "DescribeRecordList") {
		t.Fatalf("error=%v, want 点名 DescribeRecordList", cleanErr)
	}
}

// DescribeRecordList 的「查询不到数据」响应形态
// （ResourceNotFound.NoDataOfRecord，ErrorOnEmpty=yes 的服务端默认行为）：
// 按空结果处理，不报错、不删除——空结果不是故障。
func TestProvider_CleanUpValue_sweepNoDataOfRecordIsEmptyResult(t *testing.T) {
	transport := &drainAwareTransport{
		recordTransport: recordTransport{records: map[uint64]string{}},
		noDataOfRecord:  true,
	}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)

	if cleanErr := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "value"); cleanErr != nil {
		t.Fatalf("clean up with no-data list: %v（ResourceNotFound.NoDataOfRecord 是空结果，不是故障）", cleanErr)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.deletes) != 0 {
		t.Fatalf("DeleteRecord calls=%v, want 零删除", transport.deletes)
	}
}

// 枚举删除失败：错误上抛 + 幽灵记录回填内存兜底表；恢复后下一次清理经兜底
// 表重试删除成功，且不再做网络枚举（有候选即不枚举）。
func TestProvider_CleanUpValue_sweepDeleteFailureRefillsFallbackForRetry(t *testing.T) {
	transport := &drainAwareTransport{
		recordTransport: recordTransport{records: map[uint64]string{
			200: "stale-value",
		}},
		names:           map[uint64]string{200: "_acme-challenge"},
		failDeleteTimes: 1,
	}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)

	if cleanErr := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "stale-value"); cleanErr == nil {
		t.Fatal("枚举命中的删除失败必须上抛")
	}
	transport.mu.Lock()
	if _, alive := transport.records[200]; !alive {
		transport.mu.Unlock()
		t.Fatal("删除失败的幽灵记录不应从 fake 消失")
	}
	transport.mu.Unlock()

	// 恢复后重试：兜底表条目直接命中删除，不再枚举。
	if cleanErr := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "stale-value"); cleanErr != nil {
		t.Fatalf("retry clean up: %v", cleanErr)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if _, alive := transport.records[200]; alive {
		t.Fatal("兜底表重试必须删除幽灵记录")
	}
	if len(transport.lists) != 1 {
		t.Fatalf("DescribeRecordList attempts=%d, want 1（重试走兜底表，不做第二次枚举）", len(transport.lists))
	}
}

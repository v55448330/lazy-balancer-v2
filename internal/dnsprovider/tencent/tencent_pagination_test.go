package tencent

// 翻页 offset 推进语义钉测（对齐 dnspod 侧 dnspod_pagination_test.go）。
//
// DescribeRecordList 的 Offset 为绝对偏移——服务端短页（请求 Limit=100 只
// 返回 30 条）时按实际取到数推进（offset=30）不重不漏。按页对齐推进
// （offset=100）会跳过 30-99 区间的记录，此测试转红。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// shortPageListTransport 按 offset 切片下发 DescribeRecordList 短页（请求
// Limit=100、实际页容量 30），记录每次请求的 offset。
type shortPageListTransport struct {
	mu      sync.Mutex
	total   int
	pageCap int
	offsets []uint64
}

func (tr *shortPageListTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Offset uint64 `json:"Offset"`
		Limit  uint64 `json:"Limit"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.offsets = append(tr.offsets, payload.Offset)

	type listedRecord struct {
		RecordID uint64 `json:"RecordId"`
		Name     string `json:"Name"`
		Type     string `json:"Type"`
		Value    string `json:"Value"`
	}
	records := make([]listedRecord, 0)
	start := int(payload.Offset)
	end := start + tr.pageCap
	if end > tr.total {
		end = tr.total
	}
	for i := start; i < end; i++ {
		records = append(records, listedRecord{
			RecordID: uint64(1000 + i),
			Name:     "_acme-challenge",
			Type:     "TXT",
			Value:    fmt.Sprintf("value-%d", i),
		})
	}
	responseBody, err := json.Marshal(map[string]any{
		"Response": map[string]any{
			"RecordCountInfo": map[string]uint64{"TotalCount": uint64(tr.total), "ListCount": uint64(len(records))},
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

// 50 条记录、页容量 30：页 1（offset=0）返回 30 条，页 2 的 offset 必须按
// 实际取到数推进为 30（绝对偏移语义），取尽 50 条且 ID 不重不漏。
func TestListChallengeRecords_advancesOffsetByFetchedCount(t *testing.T) {
	tr := &shortPageListTransport{total: 50, pageCap: 30}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(tr)

	records, err := provider.listChallengeRecords(context.Background(), "example.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	if len(records) != 50 {
		t.Fatalf("collected=%d, want 50（短页按实际数推进不得漏扫）", len(records))
	}
	seen := make(map[uint64]bool, len(records))
	for _, r := range records {
		if seen[r.recordID] {
			t.Fatalf("recordID=%d 重复（offset 推进重叠）", r.recordID)
		}
		seen[r.recordID] = true
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.offsets) < 2 || tr.offsets[0] != 0 || tr.offsets[1] != 30 {
		t.Fatalf("offsets=%v, want [0 30 ...]（页 2 按实际取到数 30 推进，非页对齐 100）", tr.offsets)
	}
}

// shortPageStopListTransport 按模式下发 DescribeRecordList 短页形态
// （请求 Limit=100）：
//   - "inflated"：每页重复同一条记录，TotalCount 失真偏大（1000）——
//     「total 显示仍有后续、实际已取尽」，旧口径空转到页数上限并重复收集；
//   - "missingTotal"：TotalCount 缺失（0），150 条按整页 100 下发——
//     第 1 页整页继续，第 2 页 50 条短页即末页（total 不可信时短页兜底）；
//   - "middleShort"：TotalCount 可信（50），中途短页（第 2 页 10 条）后
//     仍有后续——total 优先，短页不得提前收手（既有契约，回归形状）。
//
// 记录 DescribeRecordList 调用次数。
type shortPageStopListTransport struct {
	mu    sync.Mutex
	mode  string
	calls int
}

func (tr *shortPageStopListTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Offset uint64 `json:"Offset"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.calls++
	type listedRecord struct {
		RecordID uint64 `json:"RecordId"`
		Name     string `json:"Name"`
		Type     string `json:"Type"`
		Value    string `json:"Value"`
	}
	records := make([]listedRecord, 0)
	var total uint64
	switch tr.mode {
	case "inflated":
		records = append(records, listedRecord{RecordID: 1001, Name: "_acme-challenge", Type: "TXT", Value: "v"})
		total = 1000
	case "missingTotal":
		for i := int(payload.Offset); i < min(int(payload.Offset)+100, 150); i++ {
			records = append(records, listedRecord{RecordID: uint64(1000 + i), Name: "_acme-challenge", Type: "TXT", Value: fmt.Sprintf("value-%d", i)})
		}
	case "middleShort":
		end := int(payload.Offset) + 30
		if payload.Offset == 30 {
			end = int(payload.Offset) + 10
		}
		for i := int(payload.Offset); i < min(end, 50); i++ {
			records = append(records, listedRecord{RecordID: uint64(1000 + i), Name: "_acme-challenge", Type: "TXT", Value: fmt.Sprintf("value-%d", i)})
		}
		total = 50
	}
	responseBody, err := json.Marshal(map[string]any{
		"Response": map[string]any{
			"RecordCountInfo": map[string]uint64{"TotalCount": total, "ListCount": uint64(len(records))},
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

// TotalCount 失真偏大（1000）且每页重复同一条记录：无进展兜底必须终止——
// 重复取到已见记录说明 offset 推进没有换来新数据，继续翻页只是空转+重复收集。
// 旧口径只看「空页或累计≥total」，在失真总数下空转到页数上限（20 次调用、
// 20 条重复记录）；新口径第二次取到重复记录即收手（2 次调用、1 条记录）。
func TestListChallengeRecords_stopsWhenPagesRepeatWithInflatedTotal(t *testing.T) {
	tr := &shortPageStopListTransport{mode: "inflated"}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(tr)

	records, err := provider.listChallengeRecords(context.Background(), "example.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(records) != 1 || tr.calls != 2 {
		t.Fatalf("records=%d calls=%d, want 1/2（重复页无进展即收手，不空转页数上限）", len(records), tr.calls)
	}
}

// TotalCount 缺失（0）时短页兜底（与 cloudflare 同口径）：不足请求页大小
// 即末页。150 条记录——第 1 页整页 100 条（继续），第 2 页 50 条（短页收手），
// 取尽 150 条且不重不漏。
func TestListChallengeRecords_shortPageFallbackWithoutTotal(t *testing.T) {
	tr := &shortPageStopListTransport{mode: "missingTotal"}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(tr)

	records, err := provider.listChallengeRecords(context.Background(), "example.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(records) != 150 || tr.calls != 2 {
		t.Fatalf("records=%d calls=%d, want 150/2（total 缺失时短页兜底，整页不漏扫）", len(records), tr.calls)
	}
	seen := make(map[uint64]bool, len(records))
	for _, r := range records {
		if seen[r.recordID] {
			t.Fatalf("recordID=%d 重复取到", r.recordID)
		}
		seen[r.recordID] = true
	}
}

// 回归形状：TotalCount 可信（50）时中途短页（第 2 页 10 条）不得提前收手——
// total 优先，按累计取到数继续翻页取尽 50 条（既有 advancesOffsetByFetchedCount
// 契约的短页兜底兼容钉：兜底只在 total 缺失/无进展时生效）。
func TestListChallengeRecords_continuesPastShortMiddlePageWithTrustedTotal(t *testing.T) {
	tr := &shortPageStopListTransport{mode: "middleShort"}
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider.client.WithHttpTransport(tr)

	records, err := provider.listChallengeRecords(context.Background(), "example.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(records) != 50 || tr.calls != 3 {
		t.Fatalf("records=%d calls=%d, want 50/3（可信 total 下中途短页继续翻页）", len(records), tr.calls)
	}
}

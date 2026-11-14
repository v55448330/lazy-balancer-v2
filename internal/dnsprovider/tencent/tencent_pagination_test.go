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

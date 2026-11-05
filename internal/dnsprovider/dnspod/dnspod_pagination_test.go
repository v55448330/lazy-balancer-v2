package dnspod

// 翻页 offset 推进语义钉测。
//
// offset 为绝对偏移（官方文档 docs.dnspod.cn/api/record-list：「记录开始的
// 偏移，第一条记录为 0，依次类推」）——服务端短页（请求 length=100 只返回
// 30 条）时按实际取到数推进（offset=30）不重不漏，无需按 length 整数倍
// 对齐。现状即正确（按 length 对齐的假设与官方码表相悖），本钉测把
// 该判定锁死：若未来改成「按页对齐推进」（offset=100），短页场景会跳过
// 30-99 区间的记录，此测试转红。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// shortPageTransport 按 offset 切片下发 Record.List 短页（请求 length=100、
// 实际页容量 30），记录每次请求的 offset。
type shortPageTransport struct {
	mu      sync.Mutex
	total   int
	pageCap int
	offsets []string
}

func (transport *shortPageTransport) RoundTrip(request *http.Request) (*http.Response, error) {
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
	if strings.HasSuffix(request.URL.Path, "Record.List") {
		transport.offsets = append(transport.offsets, params.Get("offset"))
		offset := 0
		if params.Get("offset") != "" {
			offset, err = strconv.Atoi(params.Get("offset"))
			if err != nil {
				return nil, err
			}
		}
		start, end := offset, min(offset+transport.pageCap, transport.total)
		type listed struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		records := []listed{}
		for i := start; i < end; i++ {
			records = append(records, listed{ID: strconv.Itoa(i), Name: "_acme-challenge", Type: "TXT", Value: "v"})
		}
		payload, err := json.Marshal(map[string]any{
			"status":  map[string]string{"code": "1", "message": "ok"},
			"records": records,
			"info":    map[string]string{"record_total": strconv.Itoa(transport.total)},
		})
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(string(payload))),
			Request:    request,
		}, nil
	}
	if strings.HasSuffix(request.URL.Path, "Domain.List") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"1","message":"ok"},"domains":[{"id":"1","name":"example.com"}],"info":{"domain_total":1}}`)),
			Request:    request,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"1","message":"ok"}}`)),
		Request:    request,
	}, nil
}

// 50 条记录、页容量 30：页 1（offset=0）返回 30 条，页 2 的 offset 必须按
// 实际取到数推进为 30（绝对偏移语义），取尽 50 条且 ID 不重不漏。
func TestListChallengeRecords_advancesOffsetByFetchedCount(t *testing.T) {
	transport := &shortPageTransport{total: 50, pageCap: 30}
	provider := New("id,token")
	provider.client.Transport = transport

	collected, err := provider.listChallengeRecords(t.Context(), "example.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("list challenge records: %v", err)
	}
	if len(collected) != 50 {
		t.Fatalf("collected=%d, want 50（短页推进不漏扫）", len(collected))
	}
	seen := map[string]bool{}
	for _, record := range collected {
		if seen[record.recordID] {
			t.Fatalf("recordID %s 重复取到（offset 推进语义错误）", record.recordID)
		}
		seen[record.recordID] = true
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.offsets) != 2 || transport.offsets[0] != "0" || transport.offsets[1] != "30" {
		t.Fatalf("offsets=%v, want [0 30]（短页按实际取到数推进，非按 length 对齐）", transport.offsets)
	}
}

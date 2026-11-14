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

// shortPageStopTransport 按模式下发 Record.List 短页形态（请求 length=100）：
//   - "inflated"：每页重复同一条记录，record_total 失真偏大（1000）——
//     「total 显示仍有后续、实际已取尽」，旧口径空转到页数上限并重复收集；
//   - "missingTotal"：record_total 缺失（0），150 条按整页 100 下发——
//     第 1 页整页继续，第 2 页 50 条短页即末页（total 不可信时短页兜底）；
//   - "middleShort"：record_total 可信（50），中途短页（第 2 页 10 条）后
//     仍有后续——total 优先，短页不得提前收手（既有契约，回归形状）。
//
// 记录 Record.List 调用次数。
type shortPageStopTransport struct {
	mu        sync.Mutex
	mode      string
	listCalls int
}

func (transport *shortPageStopTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	_ = request.Body.Close()
	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if strings.HasSuffix(request.URL.Path, "Domain.List") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"1","message":"ok"},"domains":[{"id":"1","name":"example.com"}],"info":{"domain_total":1}}`)),
			Request:    request,
		}, nil
	}
	transport.listCalls++
	offset, _ := strconv.Atoi(params.Get("offset"))
	type listed struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	records := []listed{}
	total := "0"
	switch transport.mode {
	case "inflated":
		records = append(records, listed{ID: "1", Name: "_acme-challenge", Type: "TXT", Value: "v"})
		total = "1000"
	case "missingTotal":
		for i := offset; i < min(offset+100, 150); i++ {
			records = append(records, listed{ID: strconv.Itoa(i), Name: "_acme-challenge", Type: "TXT", Value: "v"})
		}
	case "middleShort":
		end := offset + 30
		if offset == 30 {
			end = offset + 10
		}
		for i := offset; i < min(end, 50); i++ {
			records = append(records, listed{ID: strconv.Itoa(i), Name: "_acme-challenge", Type: "TXT", Value: "v"})
		}
		total = "50"
	}
	payload, err := json.Marshal(map[string]any{
		"status":  map[string]string{"code": "1", "message": "ok"},
		"records": records,
		"info":    map[string]string{"record_total": total},
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

func (transport *shortPageStopTransport) calls() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.listCalls
}

// record_total 失真偏大（1000）且每页重复同一条记录：无进展兜底必须终止——
// 重复取到已见记录说明 offset 推进没有换来新数据，继续翻页只是空转+重复收集。
// 旧口径只看「空页或累计≥total」，在失真总数下空转到页数上限（20 次调用、
// 20 条重复记录）；新口径第二次取到重复记录即收手（2 次调用、1 条记录）。
func TestListChallengeRecords_stopsWhenPagesRepeatWithInflatedTotal(t *testing.T) {
	seedDomainIDCache(t, "id,token", map[string]string{"example.com": "1"})
	transport := &shortPageStopTransport{mode: "inflated"}
	provider := New("id,token")
	provider.client.Transport = transport

	collected, err := provider.listChallengeRecords(t.Context(), "example.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("list challenge records: %v", err)
	}
	if len(collected) != 1 || transport.calls() != 2 {
		t.Fatalf("records=%d calls=%d, want 1/2（重复页无进展即收手，不空转页数上限）", len(collected), transport.calls())
	}
}

// record_total 缺失（0）时短页兜底（与 cloudflare 同口径）：不足请求页大小
// 即末页。150 条记录——第 1 页整页 100 条（继续），第 2 页 50 条（短页收手），
// 取尽 150 条且不重不漏。
func TestListChallengeRecords_shortPageFallbackWithoutTotal(t *testing.T) {
	seedDomainIDCache(t, "id,token", map[string]string{"example.com": "1"})
	transport := &shortPageStopTransport{mode: "missingTotal"}
	provider := New("id,token")
	provider.client.Transport = transport

	collected, err := provider.listChallengeRecords(t.Context(), "example.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("list challenge records: %v", err)
	}
	if len(collected) != 150 || transport.calls() != 2 {
		t.Fatalf("records=%d calls=%d, want 150/2（total 缺失时短页兜底，整页不漏扫）", len(collected), transport.calls())
	}
	seen := map[string]bool{}
	for _, record := range collected {
		if seen[record.recordID] {
			t.Fatalf("recordID %s 重复取到", record.recordID)
		}
		seen[record.recordID] = true
	}
}

// 回归形状：record_total 可信（50）时中途短页（第 2 页 10 条）不得提前收手——
// total 优先，按累计取到数继续翻页取尽 50 条（既有 advancesOffsetByFetchedCount
// 契约的短页兜底兼容钉：兜底只在 total 缺失/无进展时生效）。
func TestListChallengeRecords_continuesPastShortMiddlePageWithTrustedTotal(t *testing.T) {
	seedDomainIDCache(t, "id,token", map[string]string{"example.com": "1"})
	transport := &shortPageStopTransport{mode: "middleShort"}
	provider := New("id,token")
	provider.client.Transport = transport

	collected, err := provider.listChallengeRecords(t.Context(), "example.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("list challenge records: %v", err)
	}
	if len(collected) != 50 || transport.calls() != 3 {
		t.Fatalf("records=%d calls=%d, want 50/3（可信 total 下中途短页继续翻页）", len(collected), transport.calls())
	}
}

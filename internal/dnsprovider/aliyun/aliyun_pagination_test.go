package aliyun

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// 翻页终止口径必须按累计实际取到数（与 dnspod/tencent/cloudflare 同口径）：
// TotalCount=150、PageSize=100，服务端按请求 PageSize 切片下发——第 1 页
// 100 条、第 2 页 50 条。旧口径 "页号×请求页大小" 在第 2 页 2×100≥150 收手
// 看似正确，但它把请求页大小当实际取到数：服务端按更小页容量返回时即提前
// 终止漏扫。累计口径按实际取到数推进，150 条取尽才收手（不重不漏）。
func TestListChallengeRecords_terminationByFetchedTotalNotPageArithmetic(t *testing.T) {
	const total = 150
	var pages []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("Action") != "DescribeDomainRecords" && r.Header.Get("x-acs-action") != "DescribeDomainRecords" {
			writeFakeJSON(w, http.StatusBadRequest, map[string]any{"Code": "InvalidAction"})
			return
		}
		page, _ := strconv.Atoi(query.Get("PageNumber"))
		pageSize, _ := strconv.Atoi(query.Get("PageSize"))
		pages = append(pages, page)
		type listed struct {
			RecordId string `json:"RecordId"`
			RR       string `json:"RR"`
			Type     string `json:"Type"`
			Value    string `json:"Value"`
		}
		start := (page - 1) * pageSize
		end := start + pageSize
		if end > total {
			end = total
		}
		records := make([]listed, 0)
		for i := start; i < end; i++ {
			records = append(records, listed{
				RecordId: strconv.Itoa(1000 + i),
				RR:       "_acme-challenge.www",
				Type:     "TXT",
				Value:    "challenge-value",
			})
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"TotalCount": total, "DomainRecords": map[string]any{"Record": records}, "RequestId": "req-list",
		})
	}))
	t.Cleanup(server.Close)
	provider := newFakeProvider(t, server.URL, 1)

	records, err := provider.listChallengeRecords(context.Background(), testZone, "_acme-challenge.www")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	if len(records) != total {
		t.Fatalf("collected=%d, want %d（累计实际取到数取尽才收手）", len(records), total)
	}
	seen := make(map[string]bool, len(records))
	for _, r := range records {
		if seen[r.recordID] {
			t.Fatalf("recordID=%s 重复", r.recordID)
		}
		seen[r.recordID] = true
	}
	if len(pages) != 2 || pages[0] != 1 || pages[1] != 2 {
		t.Fatalf("pages=%v, want [1 2]（整页续取到累计取尽）", pages)
	}
}

// TotalCount 失真偏大（1000）而实际只有 1 条（短页）时，短页兜底必须终止
// （与 cloudflare 同口径）：不足请求页大小即末页。旧口径 "页号×请求页大小
// ≥TotalCount" 在 1000 的失真总数下永不成立，空转到页数上限（20 次调用）；
// 新口径短页即收手（1 次调用），记录不漏收。
func TestListChallengeRecords_shortPageStopsWithInflatedTotal(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"TotalCount": 1000,
			"DomainRecords": map[string]any{"Record": []map[string]any{{
				"RecordId": "1001", "RR": "_acme-challenge.www", "Type": "TXT", "Value": "challenge-value",
			}}},
			"RequestId": "req-list",
		})
	}))
	t.Cleanup(server.Close)
	provider := newFakeProvider(t, server.URL, 1)

	records, err := provider.listChallengeRecords(context.Background(), testZone, "_acme-challenge.www")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	if len(records) != 1 || calls != 1 {
		t.Fatalf("records=%d calls=%d, want 1/1（短页兜底终止，不空转页数上限）", len(records), calls)
	}
}

// TotalCount 缺失（0）且整页返回时按空页收尾（与 dnspod/tencent 同口径）：
// 两页满页、第三页空——旧口径 "页号×请求页大小≥TotalCount(0)" 第 1 页即
// 收手漏扫后续整页；新口径按空页收尾，200 条取尽（短页兜底只在不满足请求
// 页大小时触发，整页形态不受影响）。
func TestListChallengeRecords_missingTotalStopsOnEmptyPage(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		query := r.URL.Query()
		pageSize, _ := strconv.Atoi(query.Get("PageSize"))
		records := make([]map[string]any, 0, pageSize)
		if calls <= 2 {
			for i := range pageSize {
				records = append(records, map[string]any{
					"RecordId": strconv.Itoa(1000 + (calls-1)*pageSize + i), "RR": "_acme-challenge.www", "Type": "TXT", "Value": "challenge-value",
				})
			}
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"TotalCount": 0, "DomainRecords": map[string]any{"Record": records}, "RequestId": "req-list",
		})
	}))
	t.Cleanup(server.Close)
	provider := newFakeProvider(t, server.URL, 1)

	records, err := provider.listChallengeRecords(context.Background(), testZone, "_acme-challenge.www")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	if len(records) != 2*challengeListPageSize || calls != 3 {
		t.Fatalf("records=%d calls=%d, want %d/3（空页收尾，整页不漏收）", len(records), calls, 2*challengeListPageSize)
	}
}

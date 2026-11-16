package aliyun

// 畸形空记录 ID 的去重折叠回归：RecordId 缺失/空串的畸形条目不得参与 seen
// 去重——整页空 ID 会被折叠成「已见」误判无进展提前收手（后续页的真实记录
// 漏扫），且空 ID 进 collected 会污染复用/清理路径（清理侧按空 ID 删除永久
// 失败）。与 createRecord 的「空/无法解析 ID 不参与复用」同口径：空 ID 条目
// 整条跳过（不进 seen、不进 collected），真实 ID 照常判定进展。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// 第 1 页整页空 RecordId（畸形）+ 第 2 页目标记录：不得误判无进展收手，
// 第 2 页必须扫到；空 ID 条目不得进 collected。
func TestListChallengeRecords_emptyIDPageDoesNotFoldProgress(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		records := make([]map[string]any, 0, challengeListPageSize)
		if calls == 1 {
			for range challengeListPageSize {
				records = append(records, map[string]any{
					"RecordId": "", "RR": "_acme-challenge.www", "Type": "TXT", "Value": "challenge-value",
				})
			}
		} else {
			records = append(records, map[string]any{
				"RecordId": "3000", "RR": "_acme-challenge.www", "Type": "TXT", "Value": "target-value",
			})
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"TotalCount": 1000, "DomainRecords": map[string]any{"Record": records}, "RequestId": "req-list",
		})
	}))
	t.Cleanup(server.Close)
	provider := newFakeProvider(t, server.URL, 1)

	records, err := provider.listChallengeRecords(context.Background(), testZone, "_acme-challenge.www")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	if calls < 2 {
		t.Fatalf("calls=%d, want ≥2（整页空 ID 不得折叠成无进展提前收手）", calls)
	}
	if len(records) != 1 || records[0].recordID != "3000" || records[0].value != "target-value" {
		t.Fatalf("records=%+v, want 仅第 2 页目标记录（空 ID 条目不得进 collected）", records)
	}
}

// 畸形页与真实页交替（空 ID 页不占 seen）：真实记录跨页重复仍须按无进展
// 收手——空 ID 豁免不得把真正的重复页守卫拆掉。
func TestListChallengeRecords_emptyIDsDoNotDisableRepeatGuard(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		records := []map[string]any{
			{"RecordId": "1001", "RR": "_acme-challenge.www", "Type": "TXT", "Value": "challenge-value"},
		}
		// 每页追加一条空 ID 畸形条目：seen 只按真实 ID 判定，第 2 页起重复。
		records = append(records, map[string]any{
			"RecordId": "", "RR": "_acme-challenge.www", "Type": "TXT", "Value": "challenge-value",
		})
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"TotalCount": 1000, "DomainRecords": map[string]any{"Record": records}, "RequestId": "req-list",
		})
	}))
	t.Cleanup(server.Close)
	provider := newFakeProvider(t, server.URL, 1)

	records, err := provider.listChallengeRecords(context.Background(), testZone, "_acme-challenge.www")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	if len(records) != 1 || calls != 2 {
		t.Fatalf("records=%d calls=%d, want 1/2（真实 ID 重复页仍须收手，空 ID 不豁免重复守卫）", len(records), calls)
	}
}

// TotalCount 可信（150）时中途短页（第 2 页 10 条，服务端页容量波动）不得
// 提前收手——total 优先（与 dnspod/tencent/cloudflare 同构，函数头注释明示
// 的统一契约）：短页兜底仅在 total≤0 时生效。旧口径「短页无条件收手」在
// 第 2 页即终止，漏扫第 3 页的 40 条。
func TestListChallengeRecords_continuesPastShortMiddlePageWithTrustedTotal(t *testing.T) {
	var calls int
	var pages []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		query := r.URL.Query()
		page, _ := strconv.Atoi(query.Get("PageNumber"))
		pages = append(pages, page)
		// 服务端按更小页容量切片：第 1 页 100、第 2 页 10、第 3 页 40。
		start, count := 0, challengeListPageSize
		switch page {
		case 2:
			start, count = 100, 10
		case 3:
			start, count = 110, 40
		}
		records := make([]map[string]any, 0, count)
		for i := range count {
			records = append(records, map[string]any{
				"RecordId": strconv.Itoa(1000 + start + i), "RR": "_acme-challenge.www", "Type": "TXT", "Value": "challenge-value",
			})
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"TotalCount": 150, "DomainRecords": map[string]any{"Record": records}, "RequestId": "req-list",
		})
	}))
	t.Cleanup(server.Close)
	provider := newFakeProvider(t, server.URL, 1)

	records, err := provider.listChallengeRecords(context.Background(), testZone, "_acme-challenge.www")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	if len(records) != 150 {
		t.Fatalf("records=%d, want 150（可信 total 下中途短页继续翻页取尽）", len(records))
	}
	if len(pages) != 3 || pages[0] != 1 || pages[1] != 2 || pages[2] != 3 {
		t.Fatalf("pages=%v, want [1 2 3]（短页不提前收手，按累计取到数判定）", pages)
	}
}

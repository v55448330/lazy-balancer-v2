package cloudflare

// 翻页终止判定与 dnspod/tencent/aliyun 侧统一（total 优先、短页兜底、
// 按「实际取到条数」推进游标）。
//
// 历史形态是「短页即终止」：per_page=100 已是 Cloudflare 单页上限，稳定快照
// 下成立；但厂商页间漂移/服务端单页容量波动会产生「中途短页 + total 显示
// 仍有后续」的观测形态——短页提前收手会漏扫后续页：复用扫描漏看既有同值
// 记录（重复创建）、残余排空漏删幽灵 TXT。统一后的判定形状（与 dnspod 侧
// 同构）：fetched==0 即终止；result_info.total_count>0 时按累计取到数 ≥
// total 终止（中途短页继续翻）；total 缺失（非标准网关兜底体）退回短页终止。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func scriptedPage(t *testing.T, page, total int, ids []string) string {
	t.Helper()
	type record struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	records := make([]record, 0, len(ids))
	for _, id := range ids {
		records = append(records, record{ID: id, Name: "_acme-challenge.example.com", Type: "TXT", Content: "v-" + id})
	}
	result, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal records: %v", err)
	}
	info, err := json.Marshal(map[string]int{"page": page, "per_page": 100, "count": len(ids), "total_count": total})
	if err != nil {
		t.Fatalf("marshal result_info: %v", err)
	}
	return fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":%s,"result_info":%s}`, result, info)
}

func rangeIDs(prefix string, from, to int) []string {
	ids := make([]string, 0, to-from)
	for i := from; i < to; i++ {
		ids = append(ids, fmt.Sprintf("%s%d", prefix, i))
	}
	return ids
}

// 中途短页（第 2 页 30 条）+ total 显示仍有后续：必须按累计取到数继续翻页，
// 取尽 249 条为止——「短页即终止」只取到 130 条。
func TestListRecordsByName_continuesPastShortMiddlePage(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.zones["example.com"] = "z1"
	s.scriptedRecordPages = []string{
		scriptedPage(t, 1, 249, rangeIDs("r", 0, 100)),
		scriptedPage(t, 2, 249, rangeIDs("r", 100, 130)), // 中途短页
		scriptedPage(t, 3, 249, rangeIDs("r", 130, 230)),
		scriptedPage(t, 4, 249, rangeIDs("r", 230, 249)),
	}
	p := newCloudflareTestProvider(t, "cf-token", s)

	collected, err := p.listRecordsByName(t.Context(), "z1", "_acme-challenge.example.com")
	if err != nil {
		t.Fatalf("list records: %v", err)
	}
	if len(collected) != 249 {
		t.Fatalf("collected=%d, want 249（中途短页必须继续翻页，不得提前终止）", len(collected))
	}
}

// result_info 缺失（非标准网关兜底体）时退回短页终止：短页取尽即停，不失控
// 翻页。
func TestListRecordsByName_shortPageFallbackWithoutResultInfo(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.zones["example.com"] = "z1"
	body := `{"success":true,"errors":[],"messages":[],"result":[`
	for i := range 40 {
		if i > 0 {
			body += ","
		}
		body += `{"id":"r` + recordIDFor(i) + `","name":"_acme-challenge.example.com","type":"TXT","content":"v"}`
	}
	body += `]}`
	s.overrides["GET /zones/z1/dns_records"] = cfResponse{status: http.StatusOK, body: body}
	p := newCloudflareTestProvider(t, "cf-token", s)

	collected, err := p.listRecordsByName(t.Context(), "z1", "_acme-challenge.example.com")
	if err != nil {
		t.Fatalf("list records: %v", err)
	}
	if len(collected) != 40 {
		t.Fatalf("collected=%d, want 40（无 result_info 时短页终止仍生效）", len(collected))
	}
}

func recordIDFor(i int) string {
	return fmt.Sprintf("r%d", i)
}

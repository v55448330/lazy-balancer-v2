package services

// REST API 调用采集钉测（API 接入页接入统计 REST 列数据源）：
//   - 占位 200→按请求 token 回写状态码（IsError 补记当日错误计数；
//     并发/交错完成时不得把状态码写到别的请求记录上）
//   - 当日聚合 today_calls/error_rate
//   - 趋势按内存窗口按日聚合（7 天升序）
//   - 最近调用倒序上限 50、环形裁剪丢弃最旧
//   - 当日聚合日期键按天清理（保留今日+昨日）

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRESTCallOverview_todayAndErrorRate(t *testing.T) {
	tok := RecordRESTAPICallStart("probe-key", "GET", "/api/v1/config", "10.0.0.1")
	RecordRESTAPICallStatus(tok, 403) // 在途占位回写为 403
	tok = RecordRESTAPICallStart("probe-key", "GET", "/api/v1/notifications", "10.0.0.1")
	RecordRESTAPICallStatus(tok, 200)

	ov := GetRESTCallOverview()
	today := ov.TodayCalls
	if today < 2 {
		t.Fatalf("today_calls=%d, want ≥2（含本测试两笔）", today)
	}
	if ov.ErrorRate <= 0 || ov.ErrorRate > 1 {
		t.Fatalf("error_rate=%v, want (0,1]（含 403 回写）", ov.ErrorRate)
	}
	if len(ov.RecentCalls) == 0 {
		t.Fatal("recent_calls 空")
	}
	last := ov.RecentCalls[0]
	if last.Status != 200 || last.Path != "/api/v1/notifications" {
		t.Fatalf("最近调用尾记录=%+v", last)
	}
	if !strings.Contains(ov.RecentCalls[1].Path, "/api/v1/config") {
		t.Fatalf("第二新记录 path=%q", ov.RecentCalls[1].Path)
	}
}

// 交错完成：先入环的请求后完成，状态码必须写回自己的记录——按环形尾回写
// 会把 500 记到后入环（未完成）的请求上。
func TestRESTCallOverview_statusWritebackFollowsRequestToken(t *testing.T) {
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	pathA := "/api/v1/probe-token-a-" + suffix
	pathB := "/api/v1/probe-token-b-" + suffix
	tokA := RecordRESTAPICallStart("probe-key", "GET", pathA, "10.0.0.9")
	tokB := RecordRESTAPICallStart("probe-key", "GET", pathB, "10.0.0.9")
	// A 先完成（B 仍在途）。
	RecordRESTAPICallStatus(tokA, 500)

	statuses := recentStatusByPath(GetRESTCallOverview())
	if got := statuses[pathA]; got != 500 {
		t.Fatalf("pathA status=%d, want 500（回写落到别的请求记录）", got)
	}
	if got := statuses[pathB]; got != 200 {
		t.Fatalf("pathB status=%d, want 200（未完成请求的占位状态被改写）", got)
	}
	RecordRESTAPICallStatus(tokB, 204)
}

// 并发完成：每个请求的 token 各自定位，互不覆盖。
func TestRESTCallOverview_concurrentWritebackIsolated(t *testing.T) {
	const n = 40
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	paths := make([]string, n)
	tokens := make([]APICallToken, n)
	for i := range n {
		paths[i] = fmt.Sprintf("/api/v1/probe-conc-%s-%d", suffix, i)
		tokens[i] = RecordRESTAPICallStart("probe-key", "GET", paths[i], "10.0.0.9")
	}
	want := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		want[i] = 200
		if i%2 == 0 {
			want[i] = 500
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			RecordRESTAPICallStatus(tokens[i], want[i])
		}(i)
	}
	wg.Wait()

	statuses := recentStatusByPath(GetRESTCallOverview())
	for i := range n {
		if got := statuses[paths[i]]; got != want[i] {
			t.Fatalf("request %d (%s) status=%d, want %d", i, paths[i], got, want[i])
		}
	}
}

func recentStatusByPath(ov RESTCallOverview) map[string]int {
	out := make(map[string]int, len(ov.RecentCalls))
	for _, r := range ov.RecentCalls {
		out[r.Path] = r.Status
	}
	return out
}

func TestRESTCallOverview_trendSevenDays(t *testing.T) {
	ov := GetRESTCallOverview()
	if len(ov.Trend) != 7 {
		t.Fatalf("trend=%d 天, want 7", len(ov.Trend))
	}
	// 升序日期
	for i := 1; i < len(ov.Trend); i++ {
		if ov.Trend[i].Date <= ov.Trend[i-1].Date {
			t.Fatalf("trend 日期非升序: %v", ov.Trend)
		}
	}
	if ov.Trend[6].Calls < 2 {
		t.Fatalf("今日趋势点=%d, want ≥2", ov.Trend[6].Calls)
	}
}

// 当日聚合日期键只保留今日+昨日（长期运行下日期键按天累积，无界增长）。
func TestAPICallDay_prunesBeyondYesterday(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	today := now.Format("2006-01-02")
	yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")
	twoDaysAgo := now.AddDate(0, 0, -2).Format("2006-01-02")
	monthAgo := now.AddDate(0, 0, -30).Format("2006-01-02")

	apiCallMu.Lock()
	saved := apiCallDay
	apiCallDay = map[string][2]int64{
		today:      {5, 1},
		yesterday:  {3, 0},
		twoDaysAgo: {9, 9},
		monthAgo:   {100, 50},
	}
	apiCallMu.Unlock()
	t.Cleanup(func() {
		apiCallMu.Lock()
		apiCallDay = saved
		apiCallMu.Unlock()
	})

	pruneAPICallDayLocked(now)

	apiCallMu.Lock()
	defer apiCallMu.Unlock()
	if len(apiCallDay) != 2 {
		t.Fatalf("保留日期数=%d, want 2（今日+昨日）: %v", len(apiCallDay), apiCallDay)
	}
	if _, ok := apiCallDay[today]; !ok {
		t.Fatalf("今日键被清: %v", apiCallDay)
	}
	if _, ok := apiCallDay[yesterday]; !ok {
		t.Fatalf("昨日键被清: %v", apiCallDay)
	}
}

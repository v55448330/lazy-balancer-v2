package services

// REST API 调用采集钉测（API 接入页接入统计 REST 列数据源）：
//   - 占位 200→状态回写修正（IsError 补记当日错误计数）
//   - 当日聚合 today_calls/error_rate
//   - 趋势按内存窗口按日聚合（7 天升序）
//   - 最近调用倒序上限 50、环形裁剪丢弃最旧

import (
	"strings"
	"testing"
)

func TestRESTCallOverview_todayAndErrorRate(t *testing.T) {
	RecordRESTAPICall("probe-key", "GET", "/api/v1/config", "10.0.0.1", 200)
	RecordRESTAPICallStatus(403) // 在途占位回写为 403
	RecordRESTAPICall("probe-key", "GET", "/api/v1/notifications", "10.0.0.1", 200)
	RecordRESTAPICallStatus(200)

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

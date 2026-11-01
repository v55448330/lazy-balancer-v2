package handlers

// 检测放行拆分（logged）总览公式 RED→GREEN 用例：
// 三列严格互斥——HTTP normal = 总量差分 − 被拦差分 − 检测差分；
// TCP normal = allowed 日窗口和 − logged 日窗口和。
// 对账恒等式：blocked + logged + normal == 总量差分。
// logged 缺失/旧行=0 → 公式退化为既有口径（兼容，不回溯历史）。

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// seedRuleCounters 按 生产行形状播种（storePerRuleMetrics 每规则每周期一条
// 行，blocked/logged 同行落列）——分列独立播种会让锚点 MAX(id) 查到错误行
// （blocked 与 logged 互为 0），与生产语义不符。
func seedRuleCounters(t *testing.T, ruleID string, ts time.Time, blocked, logged int) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp, requests_blocked, requests_logged)
		VALUES (?, ?, ?, ?)`, ruleID, ts.UTC().Format("2006-01-02 15:04:05"), blocked, logged); err != nil {
		t.Fatalf("seed rule counters: %v", err)
	}
}

func seedL4Logged(t *testing.T, ruleID string, ts time.Time, logged int) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO lb_l4_conn_history (timestamp, rule_id, allowed, denied, logged)
		VALUES (?, ?, 0, 0, ?)`, ts.UTC().Format("2006-01-02 15:04:05"), ruleID, logged); err != nil {
		t.Fatalf("seed l4 logged: %v", err)
	}
}

// HTTP：normal = 总量差分 − 被拦差分 − 检测差分；blocked+logged+normal == 总量差分。
func TestGetSecurityOverview_normalSubtractsLoggedHTTP(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	ydayStart := todayStart.AddDate(0, 0, -1)
	anchorYday := ydayStart.Add(-time.Hour)
	anchorToday := todayStart.Add(-time.Hour)
	latest := now.UTC().Truncate(time.Second)

	seedGlobalSample(t, anchorYday, 100)
	seedGlobalSample(t, anchorToday, 250)
	seedGlobalSample(t, latest, 400)
	// 同行落列（生产行形状）：blocked 昨日 +15、今日 +15；logged lb_a 昨日 +5、
	// 今日 +10，lb_b 今日 +3。
	seedRuleCounters(t, "lb_a", anchorYday, 10, 5)
	seedRuleCounters(t, "lb_a", anchorToday, 25, 10)
	seedRuleCounters(t, "lb_a", latest, 40, 20)
	seedRuleCounters(t, "lb_b", latest, 0, 3)

	resp := fetchOverviewNewFields(t)
	// 昨日 = (250−100) − (25−10) − (10−5) = 130；今日 = (400−250) − (40−25) − ((20−10)+3) = 122。
	if got := *resp.Data.NormalYesterday; got != 130 {
		t.Fatalf("normal_yesterday=%d, want 130（150−blocked15−logged5）", got)
	}
	if got := *resp.Data.NormalToday; got != 122 {
		t.Fatalf("normal_today=%d, want 122（150−blocked15−logged13）", got)
	}
	// 对账恒等式：blocked + logged + normal == 总量差分。
	blockedYday, loggedYday := 15, 5
	if got := blockedYday + loggedYday + *resp.Data.NormalYesterday; got != 150 {
		t.Fatalf("昨日恒等式 broken: blocked+logged+normal=%d, want 150", got)
	}
	blockedToday, loggedToday := 15, 13
	if got := blockedToday + loggedToday + *resp.Data.NormalToday; got != 150 {
		t.Fatalf("今日恒等式 broken: blocked+logged+normal=%d, want 150", got)
	}
}

// TCP：normal = allowed 日窗口和 − logged 日窗口和；旧形态（logged=0）退化原口径。
func TestGetSecurityOverview_normalTCPSubtractsLogged(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	ydayStart := todayStart.AddDate(0, 0, -1)

	// 今日：全局行 allowed 12 + logged 5 → normal_tcp=7；昨日：allowed 34 + logged 9 → 25。
	seedL4Allowed(t, "", todayStart.Add(time.Hour), 12)
	seedL4Logged(t, "", todayStart.Add(2*time.Hour), 5)
	seedL4Allowed(t, "", ydayStart.Add(time.Hour), 34)
	seedL4Logged(t, "", ydayStart.Add(2*time.Hour), 9)
	// per-rule 行不参与全局求和（既有口径）。
	seedL4Allowed(t, "lb_tcp_1", todayStart.Add(time.Hour), 999)
	seedL4Logged(t, "lb_tcp_1", todayStart.Add(time.Hour), 42)

	resp := fetchOverviewNewFields(t)
	if got := *resp.Data.NormalTodayTCP; got != 7 {
		t.Fatalf("normal_today_tcp=%d, want 7（allowed12−logged5）", got)
	}
	if got := *resp.Data.NormalYesterdayTCP; got != 25 {
		t.Fatalf("normal_yesterday_tcp=%d, want 25（allowed34−logged9）", got)
	}
}

// 旧数据兼容：logged 列全 0（历史行/旧镜像快照）→ 公式与既有口径等值。
func TestGetSecurityOverview_loggedZeroBackwardCompatible(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	ydayStart := todayStart.AddDate(0, 0, -1)
	anchorYday := ydayStart.Add(-time.Hour)
	anchorToday := todayStart.Add(-time.Hour)
	latest := now.UTC().Truncate(time.Second)

	seedGlobalSample(t, anchorYday, 100)
	seedGlobalSample(t, anchorToday, 250)
	seedGlobalSample(t, latest, 400)
	seedRuleBlocked(t, "lb_a", anchorYday, 10)
	seedRuleBlocked(t, "lb_a", anchorToday, 25)
	seedRuleBlocked(t, "lb_a", latest, 40)
	// 无 logged 种子（=0）。

	resp := fetchOverviewNewFields(t)
	if got := *resp.Data.NormalYesterday; got != 135 {
		t.Fatalf("normal_yesterday=%d, want 135（logged 缺席时退化为原公式）", got)
	}
	if got := *resp.Data.NormalToday; got != 135 {
		t.Fatalf("normal_today=%d, want 135（logged 缺席时退化为原公式）", got)
	}
}

// apidocs 披露：三列互斥与历史不回溯进描述。
func TestAPIDocs_overviewDisclosesLoggedSplit(t *testing.T) {
	description := operationDescription(routesEntry(t, "GET /security/overview"))
	for _, phrase := range []string{
		"检测放行",
		"互斥",
		"不回溯",
	} {
		if !strings.Contains(description, phrase) {
			t.Fatalf("apidocs 描述缺口径披露 %q", phrase)
		}
	}
}

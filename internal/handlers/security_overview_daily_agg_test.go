package handlers

// 正常请求读路径切换（日聚合持久化，2026-11）RED→GREEN 用例：
//   - metrics_daily_agg 有窗口行（功能已激活）→ 读日聚合：重载零丢失、
//     不受 metrics_history 行帽/保留期裁剪影响；
//   - 窗口内无聚合行（历史日/功能上线前/新装）→ 回落既有锚点差分；
//   - 回退判定按窗口独立（今日有聚合行、昨日无 → 两窗口各走各通道）；
//   - 对账恒等式：同数据集（无重置）日聚合 SUM == 锚点差分，逐字段相等。

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// seedDailyAgg 播种日聚合行（采集侧 UPSERT 的落库形状）。
func seedDailyAgg(t *testing.T, ruleID, localDate string, total, blocked, logged int) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_daily_agg (rule_id, local_date, requests_delta, blocked_delta, logged_delta)
		VALUES (?, ?, ?, ?, ?)`, ruleID, localDate, total, blocked, logged); err != nil {
		t.Fatalf("seed metrics_daily_agg(%s,%s): %v", ruleID, localDate, err)
	}
}

func overviewTestWindows(t *testing.T) (ydayStart, todayStart time.Time, todayDate, ydayDate string) {
	t.Helper()
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	ydayStart = todayStart.AddDate(0, 0, -1)
	return ydayStart, todayStart, todayStart.Format("2006-01-02"), ydayStart.Format("2006-01-02")
}

// 聚合通道激活：今日有聚合行 → 今日读聚合（锚点种子的不同数值不得泄漏进结果）。
func TestSecurityOverviewNormalHTTPDiff_dailyAggChannelActive(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ydayStart, todayStart, todayDate, _ := overviewTestWindows(t)

	// 聚合行：lb_a 今日 +80/-3/-2、lb_b 今日 +20/-1/0 → 今日=80-3-2+20-1=94。
	seedDailyAgg(t, "lb_a", todayDate, 80, 3, 2)
	seedDailyAgg(t, "lb_b", todayDate, 20, 1, 0)
	// 锚点种子刻意给不同值：若误走锚点通道会得到 200-150=50。
	latest := time.Now().UTC()
	seedRuleCounters(t, "lb_a", latest, 200, 10, 5)

	today, yesterday, err := securityOverviewNormalHTTPDiff(db.MetricsDB, ydayStart, todayStart)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if today != 94 {
		t.Fatalf("normal_today=%d, want 94（今日必须读日聚合通道）", today)
	}
	if yesterday != 0 {
		t.Fatalf("normal_yesterday=%d, want 0（昨日无聚合行且无锚点样本）", yesterday)
	}
}

// 回退路径：聚合表空（新装/未激活）→ 两窗口均回落锚点差分（与既有实现逐字一致）。
func TestSecurityOverviewNormalHTTPDiff_fallbackWhenNoAggRows(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ydayStart, todayStart, _, _ := overviewTestWindows(t)
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	anchorYday := ydayStart.Add(-time.Hour)
	anchorToday := todayStart.Add(-time.Hour)
	latest := now.UTC()

	seedRuleCounters(t, "lb_a", anchorYday, 100, 10, 5)
	seedRuleCounters(t, "lb_a", anchorToday, 250, 25, 10)
	seedRuleCounters(t, "lb_a", latest, 400, 40, 20)

	today, yesterday, err := securityOverviewNormalHTTPDiff(db.MetricsDB, ydayStart, todayStart)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	// 与锚点差分逐字一致（125/130，同 security_overview_logged_test 期望）。
	if today != 125 || yesterday != 130 {
		t.Fatalf("回退通道 broken: today=%d yesterday=%d, want 125/130", today, yesterday)
	}
}

// 按窗口独立回退：今日有聚合行、昨日无 → 今日读聚合、昨日回落锚点差分
// （功能升级当日激活的历史日兼容形态）。
func TestSecurityOverviewNormalHTTPDiff_perWindowFallback(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ydayStart, todayStart, todayDate, _ := overviewTestWindows(t)
	anchorYday := ydayStart.Add(-time.Hour)
	anchorToday := todayStart.Add(-time.Hour)
	latest := time.Now().UTC()

	// 锚点：昨日 150→250（+100/-10/-5 → 昨日 85），今日 250→400（+150/-15/-10 → 今日 125）。
	seedRuleCounters(t, "lb_a", anchorYday, 150, 10, 5)
	seedRuleCounters(t, "lb_a", anchorToday, 250, 20, 10)
	seedRuleCounters(t, "lb_a", latest, 400, 35, 20)
	// 今日聚合行给不同值：若今日误走锚点通道会得到 125 而非 77。
	seedDailyAgg(t, "lb_a", todayDate, 90, 8, 5)

	today, yesterday, err := securityOverviewNormalHTTPDiff(db.MetricsDB, ydayStart, todayStart)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if today != 77 {
		t.Fatalf("normal_today=%d, want 77（今日读聚合 90−8−5）", today)
	}
	if yesterday != 85 {
		t.Fatalf("normal_yesterday=%d, want 85（昨日回落锚点 100−10−5）", yesterday)
	}
}

// 对账恒等式（对账钉测）：同数据集（无重置）日聚合 SUM == 锚点差分，
// 今日/昨日逐字段相等；含 per-rule 负值钳零（blockedΔ > totalΔ 规则记 0）。
func TestSecurityOverviewNormalHTTPDiff_reconciliationAggEqualsAnchorDiff(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ydayStart, todayStart, todayDate, ydayDate := overviewTestWindows(t)
	anchorYday := ydayStart.Add(-time.Hour)
	anchorToday := todayStart.Add(-time.Hour)
	latest := time.Now().UTC()

	// 三规则时间线（累计快照，无重置；各规则在两窗口起点前均有样本——
	// 恒等式定义域：冷启动规则的「首样本=基线」与锚点「零基线」天然不同，
	// 不在对账域内）：
	//   lb_a: 100/10/5 → 250/25/10 → 400/40/20（正常单调）
	//   lb_b: 50/0/0   → 60/12/0   → 70/27/0（blockedΔ 12>totalΔ10、15>10——钳零形态）
	//   lb_c: 30/3/0   → 30/3/0   → 90/9/0（昨日零增量、今日 +60/+6）
	seedRuleCounters(t, "lb_a", anchorYday, 100, 10, 5)
	seedRuleCounters(t, "lb_a", anchorToday, 250, 25, 10)
	seedRuleCounters(t, "lb_a", latest, 400, 40, 20)
	seedRuleCounters(t, "lb_b", anchorYday, 50, 0, 0)
	seedRuleCounters(t, "lb_b", anchorToday, 60, 12, 0)
	seedRuleCounters(t, "lb_b", latest, 70, 27, 0)
	seedRuleCounters(t, "lb_c", anchorYday.Add(-time.Hour), 30, 3, 0)
	seedRuleCounters(t, "lb_c", anchorToday, 30, 3, 0)
	seedRuleCounters(t, "lb_c", latest, 90, 9, 0)

	// 同一时间线推导日聚合行（采集侧每轮 delta = cur − checkpoint 的等价产物）：
	//   昨日窗口 [anchorYday → anchorToday]，今日窗口 [anchorToday → latest]。
	//   lb_a 昨日 +150/+15/+5；今日 +150/+15/+10。
	//   lb_b 昨日 +10/+12/0（钳零）；今日 +10/+15/0（钳零）。
	//   lb_c 昨日 +0/+0/0（零增量不落行）；今日 +60/+6/0。
	seedDailyAgg(t, "lb_a", ydayDate, 150, 15, 5)
	seedDailyAgg(t, "lb_a", todayDate, 150, 15, 10)
	seedDailyAgg(t, "lb_b", ydayDate, 10, 12, 0)
	seedDailyAgg(t, "lb_b", todayDate, 10, 15, 0)
	seedDailyAgg(t, "lb_c", todayDate, 60, 6, 0)

	// 锚点差分基准（同库同数据，回退实现）。
	wantToday, err := securityOverviewNormalRuleSumRange(db.MetricsDB, todayStart, time.Time{})
	if err != nil {
		t.Fatalf("anchor today: %v", err)
	}
	wantYesterday, err := securityOverviewNormalRuleSumRange(db.MetricsDB, ydayStart, todayStart)
	if err != nil {
		t.Fatalf("anchor yesterday: %v", err)
	}

	today, yesterday, err := securityOverviewNormalHTTPDiff(db.MetricsDB, ydayStart, todayStart)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	// lb_a 昨日 150-15-5=130、今日 150-15-10=125；lb_b 两窗口钳零 0；
	// lb_c 今日 60-6=54 → 期望 130/179。
	if wantYesterday != 130 || wantToday != 179 {
		t.Fatalf("锚点基准漂移: yesterday=%d today=%d, want 130/179（种子或公式回归）", wantYesterday, wantToday)
	}
	if today != wantToday {
		t.Fatalf("对账恒等式 broken（今日）: 聚合通道=%d, 锚点差分=%d", today, wantToday)
	}
	if yesterday != wantYesterday {
		t.Fatalf("对账恒等式 broken（昨日）: 聚合通道=%d, 锚点差分=%d", yesterday, wantYesterday)
	}
}

// 重置改进形态（非恒等、聚合通道更准确）：计数器归零前增量在聚合行中已入账，
// 锚点差分在归零形态下丢失该段——聚合值 ≥ 锚点值（当日聚合行含归零钳制增量）。
func TestSecurityOverviewNormalHTTPDiff_dailyAggSurvivesCounterReset(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ydayStart, todayStart, todayDate, _ := overviewTestWindows(t)

	// 重载前 30 请求入账 + /load 归零后重累 12——同日同主键走采集侧 UPSERT
	// 形状（增量相加），单行 (42,0,0)。
	seedDailyAgg(t, "lb_a", todayDate, 42, 0, 0)
	// 归零后的累计快照（锚点差分只见 0→12）。
	seedRuleCounters(t, "lb_a", time.Now().UTC(), 12, 0, 0)

	today, _, err := securityOverviewNormalHTTPDiff(db.MetricsDB, ydayStart, todayStart)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if today != 42 {
		t.Fatalf("normal_today=%d, want 42（重载前 30+归零后 12；锚点通道只能给 12）", today)
	}
}

// apidocs 口径披露（R-15）：日聚合承载、重载零丢失、历史日回落锚点差分。
func TestAPIDocs_overviewDisclosesDailyAgg(t *testing.T) {
	description := operationDescription(routesEntry(t, "GET /security/overview"))
	for _, phrase := range []string{
		"日聚合",
		"重载零丢失",
		"锚点差分",
	} {
		if !strings.Contains(description, phrase) {
			t.Fatalf("apidocs 描述缺日聚合披露 %q", phrase)
		}
	}
}

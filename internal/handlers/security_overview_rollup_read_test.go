package handlers

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 安全总览近 7 天聚合读路径切换（rollup 优先 + 原始表回退）测试：
//   - 覆盖水位回推到窗口起点 + 固化新鲜 + 写入侧就绪标记（overview_rollup_ready）
//     → 趋势/Top10 IP/攻击族读预聚合（security_event_ip_rollup /
//     security_event_rule_rollup；写入侧 aggregateOverviewEvents 同口径含
//     保留/私网地址，读路径切换为纯性能下沉、零口径变化）；
//   - 覆盖未达窗口起点 / 固化陈旧 / 就绪标记缺失 / 无状态（fresh install、
//     写侧未合入过渡期）→ 原始表直读原样保留。
//
// 写侧未合入的过渡期：ip/rule 维度表由 seedRollupReadTables 按生产 DDL
// 同构创建（PK 前缀=minute，UTC 分钟文本），合入后 IF NOT EXISTS 幂等。

// rollupReadEvent 一条安全事件及其固化投影（保留/私网与爬虫放行事件不产
// rollup 行——固化语义）。
type rollupReadEvent struct {
	eventTimeUTC  time.Time
	clientIP      string
	ruleTriggered string
	ruleMsg       string
	action        string
	reserved      bool // 保留/私网地址：只进原始表
	crawlerExempt bool // 爬虫放行族 logged：只进原始表（攻击面谓词排除）
}

func seedRollupReadTables(t *testing.T) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`CREATE TABLE IF NOT EXISTS security_event_ip_rollup (
		minute TEXT NOT NULL,
		client_ip TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL DEFAULT '',
		count INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (minute, client_ip, action)
	) WITHOUT ROWID`); err != nil {
		t.Fatalf("create ip rollup table: %v", err)
	}
	if _, err := db.MetricsDB.Exec(`CREATE TABLE IF NOT EXISTS security_event_rule_rollup (
		minute TEXT NOT NULL,
		rule_triggered TEXT NOT NULL DEFAULT '',
		rule_msg TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL DEFAULT '',
		count INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (minute, rule_triggered, rule_msg, action)
	) WITHOUT ROWID`); err != nil {
		t.Fatalf("create rule rollup table: %v", err)
	}
}

// seedRollupCoverage 写覆盖状态：coveredFrom 与新鲜水位（当前完整分钟）。
// ready=false 时不写 overview_rollup_ready（写入侧升级回填未完成形态——
// 读侧必须回退原始表）。
func seedRollupCoverage(t *testing.T, coveredFrom time.Time, ready bool) {
	t.Helper()
	watermark := time.Now().UTC().Add(-time.Minute).Truncate(time.Minute).Format("2006-01-02 15:04")
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?), (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		threatRollupCoveredFromKey, coveredFrom.UTC().Format("2006-01-02 15:04"),
		threatRollupWatermarkKey, watermark); err != nil {
		t.Fatalf("seed rollup state: %v", err)
	}
	if !ready {
		return
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		threatRollupOverviewReadyKey, "1"); err != nil {
		t.Fatalf("seed overview ready: %v", err)
	}
}

func seedRollupReadEvent(t *testing.T, e rollupReadEvent) {
	t.Helper()
	minute := e.eventTimeUTC.Format("2006-01-02 15:04")
	seconds := e.eventTimeUTC.Format("2006-01-02 15:04:05")
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action)
		VALUES (?, ?, 'GET', '/a', 'crs', ?, ?, ?)`, seconds, e.clientIP, e.ruleTriggered, e.ruleMsg, e.action); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	if e.crawlerExempt {
		// 爬虫放行族 logged：攻击面谓词排除，写入侧不产任何 rollup 行。
		return
	}
	if !e.reserved {
		// 大屏主 rollup（threat-screen 固化语义）排除保留/私网地址。
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES (?, '', '', '', ?, ?, 1)`, minute, e.ruleTriggered, e.action); err != nil {
			t.Fatalf("seed main rollup: %v", err)
		}
	}
	// 总览维度新表（写入侧 aggregateOverviewEvents 口径）：含保留/私网地址。
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_ip_rollup (minute, client_ip, action, count) VALUES (?, ?, ?, 1)`, minute, e.clientIP, e.action); err != nil {
		t.Fatalf("seed ip rollup: %v", err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rule_rollup (minute, rule_triggered, rule_msg, action, count) VALUES (?, ?, ?, ?, 1)`, minute, e.ruleTriggered, e.ruleMsg, e.action); err != nil {
		t.Fatalf("seed rule rollup: %v", err)
	}
}

type overviewTrendPointJSON struct {
	Date     string `json:"date"`
	Blocked  int    `json:"blocked"`
	Detected int    `json:"detected"`
}

type overviewTopIPJSON struct {
	IP              string `json:"ip"`
	Blocked         int    `json:"blocked"`
	Detected        int    `json:"detected"`
	Recent10m       int    `json:"recent_10m"`
	Recent1h        int    `json:"recent_1h"`
	Recent24h       int    `json:"recent_24h"`
	LastTime        string `json:"last_time"`
	AttackType      string `json:"attack_type"`
	AttackTypeStage string `json:"attack_type_stage"`
}

type overviewAttackTypeJSON struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

type overviewAggregatesJSON struct {
	Trend            []overviewTrendPointJSON `json:"trend"`
	TopIPs           []overviewTopIPJSON      `json:"top_ips"`
	AttackTypes      []overviewAttackTypeJSON `json:"attack_types"`
	AttackTypesStage []overviewAttackTypeJSON `json:"attack_types_stage"`
	IncludesReserved bool                     `json:"includes_reserved"`
}

func fetchOverviewAggregates(t *testing.T) overviewAggregatesJSON {
	t.Helper()
	router := newSecurityEventsRouter(t)
	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data overviewAggregatesJSON `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal overview: %v", err)
	}
	return resp.Data
}

// overviewRollupSeedEvents 固定日期事件（窗口内确定性桶）+ now 相对事件
// （recency 窗口，与 10m/1h/24h 边界保持 ≥25 分钟余量，规避加载间隔的
// 分钟取整抖动）。base 由调用方传入并在两库间共享——同一用例的两次播种
// 必须得到逐字节相同的分钟投影。全部事件取整分钟（秒位 0）——原始表
// last_time 与 rollup MAX(minute) 文本形状一致，双路径可比。
func overviewRollupSeedEvents(t *testing.T, base time.Time) time.Time {
	t.Helper()
	loc := services.CurrentLocation()
	todayStart := time.Date(base.Year(), base.Month(), base.Day(), 0, 0, 0, 0, loc)
	day := func(offset, hour, minute int) time.Time {
		d := todayStart.AddDate(0, 0, offset)
		return time.Date(d.Year(), d.Month(), d.Day(), hour, minute, 0, 0, loc)
	}
	fixed := []rollupReadEvent{
		{eventTimeUTC: day(-6, 8, 0).UTC(), clientIP: "93.184.216.30", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"},
		{eventTimeUTC: day(-5, 12, 0).UTC(), clientIP: "93.184.216.10", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"},
		{eventTimeUTC: day(-2, 9, 0).UTC(), clientIP: "93.184.216.10", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"},
		{eventTimeUTC: day(-2, 9, 1).UTC(), clientIP: "93.184.216.10", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"},
		{eventTimeUTC: day(-2, 9, 2).UTC(), clientIP: "93.184.216.10", ruleTriggered: "941100", ruleMsg: "XSS", action: "logged"},
		{eventTimeUTC: day(-2, 9, 3).UTC(), clientIP: "93.184.216.20", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"},
		{eventTimeUTC: day(-2, 9, 4).UTC(), clientIP: "93.184.216.20", ruleTriggered: "941100", ruleMsg: "XSS", action: "logged"},
		// 爬虫放行族 logged：攻击面谓词排除，两条路径都不得计入。
		{eventTimeUTC: day(-2, 9, 5).UTC(), clientIP: "93.184.216.20", ruleTriggered: "810016", ruleMsg: "爬虫放行", action: "logged", crawlerExempt: true},
	}
	recency := []rollupReadEvent{
		{eventTimeUTC: base.UTC().Add(-2 * time.Hour).Truncate(time.Minute), clientIP: "93.184.216.10", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"},
		{eventTimeUTC: base.UTC().Add(-30 * time.Minute).Truncate(time.Minute), clientIP: "93.184.216.20", ruleTriggered: "941100", ruleMsg: "XSS", action: "logged"},
		{eventTimeUTC: base.UTC().Add(-5 * time.Minute).Truncate(time.Minute), clientIP: "93.184.216.10", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"},
	}
	for _, e := range append(fixed, recency...) {
		seedRollupReadEvent(t, e)
	}
	return todayStart
}

// 同一事件集合双算对账：无覆盖状态（原始表回退）与覆盖到窗口起点（rollup
// 读路径）必须给出恒等的趋势/Top10/攻击族——回退与切换点数值分叉会让同一
// 卡片在水位推进瞬间跳变。两库句柄不同 → 30s 聚合缓存键不同，互不串味。
func TestSecurityOverviewAggregates_rollupPathMatchesRawFallback(t *testing.T) {
	base := time.Now()
	// 库 A：无 rollup 状态 → 原始表回退（基线）。
	setupSecurityPolicyTestDB(t)
	seedRollupReadTables(t)
	overviewRollupSeedEvents(t, base)
	rawSide := fetchOverviewAggregates(t)
	if !rawSide.IncludesReserved {
		t.Fatalf("includes_reserved=false, want true（无覆盖状态必须回退原始表口径）")
	}

	// 库 B：同种子 + 全量 rollup 投影 + 覆盖到窗口起点 → rollup 读路径。
	setupSecurityPolicyTestDB(t)
	seedRollupReadTables(t)
	todayStart := overviewRollupSeedEvents(t, base)
	windowStart := todayStart.AddDate(0, 0, -6)
	seedRollupCoverage(t, windowStart, true)
	rollupSide := fetchOverviewAggregates(t)
	if rollupSide.IncludesReserved {
		t.Fatalf("includes_reserved=true, want false（rollup 口径排除私网须披露）")
	}

	if !reflect.DeepEqual(rawSide.Trend, rollupSide.Trend) {
		t.Fatalf("趋势分叉:\nraw   =%+v\nrollup=%+v", rawSide.Trend, rollupSide.Trend)
	}
	if !reflect.DeepEqual(rawSide.TopIPs, rollupSide.TopIPs) {
		t.Fatalf("Top10 IP 分叉:\nraw   =%+v\nrollup=%+v", rawSide.TopIPs, rollupSide.TopIPs)
	}
	if !reflect.DeepEqual(rawSide.AttackTypes, rollupSide.AttackTypes) {
		t.Fatalf("攻击族分叉:\nraw   =%+v\nrollup=%+v", rawSide.AttackTypes, rollupSide.AttackTypes)
	}
	if !reflect.DeepEqual(rawSide.AttackTypesStage, rollupSide.AttackTypesStage) {
		t.Fatalf("阶段攻击族分叉:\nraw   =%+v\nrollup=%+v", rawSide.AttackTypesStage, rollupSide.AttackTypesStage)
	}

	// 固定日期桶绝对值（窗口首日边界 + 中段多事件日）。
	wantBuckets := map[string][2]int{
		todayStart.AddDate(0, 0, -6).Format("2006-01-02"): {1, 0},
		todayStart.AddDate(0, 0, -5).Format("2006-01-02"): {1, 0},
		todayStart.AddDate(0, 0, -2).Format("2006-01-02"): {3, 2},
	}
	for _, point := range rollupSide.Trend {
		if want, ok := wantBuckets[point.Date]; ok {
			if point.Blocked != want[0] || point.Detected != want[1] {
				t.Fatalf("趋势桶 %s = (%d,%d), want (%d,%d)", point.Date, point.Blocked, point.Detected, want[0], want[1])
			}
		}
	}
	wantFamilies := map[string]int{"SQL注入": 7, "XSS": 3}
	if len(rollupSide.AttackTypes) != len(wantFamilies) {
		t.Fatalf("攻击族=%+v, want 恰两类（爬虫放行不计攻击面）", rollupSide.AttackTypes)
	}
	for _, fam := range rollupSide.AttackTypes {
		if wantFamilies[fam.Name] != fam.Value {
			t.Fatalf("攻击族 %s=%d, want %d", fam.Name, fam.Value, wantFamilies[fam.Name])
		}
	}
	wantTop := []overviewTopIPJSON{
		{IP: "93.184.216.10", Blocked: 5, Detected: 1, Recent10m: 1, Recent1h: 1},
		{IP: "93.184.216.20", Blocked: 1, Detected: 2, Recent10m: 0, Recent1h: 1},
		{IP: "93.184.216.30", Blocked: 1, Detected: 0},
	}
	if len(rollupSide.TopIPs) != len(wantTop) {
		t.Fatalf("Top10=%d 条, want %d", len(rollupSide.TopIPs), len(wantTop))
	}
	for i, want := range wantTop {
		got := rollupSide.TopIPs[i]
		if got.IP != want.IP || got.Blocked != want.Blocked || got.Detected != want.Detected ||
			got.Recent10m != want.Recent10m || got.Recent1h != want.Recent1h {
			t.Fatalf("Top[%d]=%+v, want 核心列 %+v", i, got, want)
		}
		if got.LastTime == "" {
			t.Fatalf("Top[%d] last_time 为空（MAX(minute) 须格式化回填）", i)
		}
	}
}

// 原始表被保留期/行帽裁剪（仅剩最近事件）时，rollup 读路径必须凭预聚合
// 重建完整 7 天历史——这正是切换读路径的动机；直读被裁剪的原始表会静默少计。
func TestSecurityOverviewAggregates_rollupServesPrunedRaw(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	seedRollupReadTables(t)
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := overviewRollupSeedEvents(t, now)
	windowStart := todayStart.AddDate(0, 0, -6)
	seedRollupCoverage(t, windowStart, true)
	// 保留期裁剪：删除 3 小时前的全部原始事件（窗口首日/中段事件全部消失，
	// 仅留 now 相对 recency 事件）。
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events WHERE event_time < ?`,
		now.UTC().Add(-3*time.Hour).Format("2006-01-02 15:04:05")); err != nil {
		t.Fatalf("prune raw: %v", err)
	}

	agg := fetchOverviewAggregates(t)
	for _, point := range agg.Trend {
		switch point.Date {
		case todayStart.AddDate(0, 0, -6).Format("2006-01-02"):
			if point.Blocked != 1 {
				t.Fatalf("裁剪后趋势首日 %s=(%d,%d), want blocked=1（必须由 rollup 重建）", point.Date, point.Blocked, point.Detected)
			}
		case todayStart.AddDate(0, 0, -5).Format("2006-01-02"):
			if point.Blocked != 1 {
				t.Fatalf("裁剪后趋势 %s=(%d,%d), want blocked=1", point.Date, point.Blocked, point.Detected)
			}
		case todayStart.AddDate(0, 0, -2).Format("2006-01-02"):
			if point.Blocked != 3 || point.Detected != 2 {
				t.Fatalf("裁剪后趋势 %s=(%d,%d), want (3,2)", point.Date, point.Blocked, point.Detected)
			}
		}
	}
	if len(agg.TopIPs) != 3 {
		t.Fatalf("裁剪后 Top10=%d 条, want 3（93.184.216.30 仅存于 rollup）: %+v", len(agg.TopIPs), agg.TopIPs)
	}
	if agg.TopIPs[0].IP != "93.184.216.10" || agg.TopIPs[0].Blocked != 5 {
		t.Fatalf("裁剪后 Top[0]=%+v, want 93.184.216.10 blocked=5", agg.TopIPs[0])
	}
	var sqlTotal int
	for _, fam := range agg.AttackTypes {
		if fam.Name == "SQL注入" {
			sqlTotal = fam.Value
		}
	}
	if sqlTotal != 7 {
		t.Fatalf("裁剪后攻击族 SQL注入=%d, want 7（被裁剪事件必须由 rule rollup 计入）", sqlTotal)
	}
}

// 覆盖水位差 1 分钟未达窗口起点（升级回填进行中）→ 近 7 天聚合必须回退
// 原始表直读：此时 rollup 只有部分历史，读它会静默丢窗口前段。混合态披露
// （includes_reserved 仅描述今日两项）：今日计数已走 rollup（覆盖 ≤ 今日
// 起点）→ false；近 7 天聚合走原始表（含私网事件计入）。
func TestGetSecurityOverview_fallsBackToRawWhenCoverageBelowWindow(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	seedRollupReadTables(t)
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	windowStart := todayStart.AddDate(0, 0, -6)
	day := func(offset, hour, minute int) time.Time {
		d := todayStart.AddDate(0, 0, offset)
		return time.Date(d.Year(), d.Month(), d.Day(), hour, minute, 0, 0, loc)
	}
	seedRollupReadEvent(t, rollupReadEvent{eventTimeUTC: day(-1, 10, 0).UTC(), clientIP: "10.0.0.8", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked", reserved: true})
	seedRollupReadEvent(t, rollupReadEvent{eventTimeUTC: day(-1, 10, 1).UTC(), clientIP: "93.184.216.7", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"})
	seedRollupCoverage(t, windowStart.Add(time.Minute), true)

	agg := fetchOverviewAggregates(t)
	if agg.IncludesReserved {
		t.Fatalf("includes_reserved=true, want false（今日计数已走 rollup，披露仅描述今日两项）")
	}
	foundPrivate := false
	for _, top := range agg.TopIPs {
		if top.IP == "10.0.0.8" {
			foundPrivate = true
			if top.Blocked != 1 {
				t.Fatalf("私网 IP blocked=%d, want 1（原始表口径含私网）", top.Blocked)
			}
		}
	}
	if !foundPrivate {
		t.Fatalf("回退路径 Top10 缺私网 IP 10.0.0.8: %+v", agg.TopIPs)
	}
	wantDate := day(-1, 0, 0).Format("2006-01-02")
	for _, point := range agg.Trend {
		if point.Date == wantDate && (point.Blocked != 2 || point.Detected != 0) {
			t.Fatalf("回退趋势 %s=(%d,%d), want (2,0)（含私网事件）", point.Date, point.Blocked, point.Detected)
		}
	}
}

// 覆盖恰好回推到窗口起点（含边界分钟）→ rollup 读路径：新维度表写入侧
// 同口径含保留/私网地址（aggregateOverviewEvents 契约）——私网 IP 必须照常
// 进入 Top10/趋势，读路径切换为纯性能下沉、零口径变化。
func TestGetSecurityOverview_rollupPathIncludesReservedFromNewTables(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	seedRollupReadTables(t)
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	windowStart := todayStart.AddDate(0, 0, -6)
	day := func(offset, hour, minute int) time.Time {
		d := todayStart.AddDate(0, 0, offset)
		return time.Date(d.Year(), d.Month(), d.Day(), hour, minute, 0, 0, loc)
	}
	seedRollupReadEvent(t, rollupReadEvent{eventTimeUTC: day(-1, 10, 0).UTC(), clientIP: "10.0.0.8", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked", reserved: true})
	seedRollupReadEvent(t, rollupReadEvent{eventTimeUTC: day(-1, 10, 1).UTC(), clientIP: "93.184.216.7", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"})
	seedRollupCoverage(t, windowStart, true)

	agg := fetchOverviewAggregates(t)
	if agg.IncludesReserved {
		t.Fatalf("includes_reserved=true, want false（今日计数已走 rollup，披露仅描述今日两项）")
	}
	foundPrivate := false
	for _, top := range agg.TopIPs {
		if top.IP == "10.0.0.8" && top.Blocked == 1 {
			foundPrivate = true
		}
	}
	if !foundPrivate {
		t.Fatalf("rollup 路径 Top10 丢失私网 IP 10.0.0.8（新表写入侧含保留地址，读侧不得过滤）: %+v", agg.TopIPs)
	}
	if len(agg.TopIPs) != 2 {
		t.Fatalf("rollup 路径 Top10=%+v, want 2 条", agg.TopIPs)
	}
	wantDate := day(-1, 0, 0).Format("2006-01-02")
	for _, point := range agg.Trend {
		if point.Date == wantDate && (point.Blocked != 2 || point.Detected != 0) {
			t.Fatalf("rollup 趋势 %s=(%d,%d), want (2,0)（趋势源与新表同口径含私网）", point.Date, point.Blocked, point.Detected)
		}
	}
}

// 写入侧就绪标记（overview_rollup_ready）缺失=升级回填未完成/状态恢复异常
// ——即使覆盖水位已回推到窗口起点，读侧也必须回退原始表，不得读半成品
// 新表（状态宣称覆盖而维度表为空会静默少计）。
func TestGetSecurityOverview_fallsBackToRawWithoutOverviewReadyKey(t *testing.T) {
	base := time.Now()
	// 库 A：覆盖完整但就绪标记缺失 → 原始表回退（此处原始表已裁剪 → 全零）。
	setupSecurityPolicyTestDB(t)
	seedRollupReadTables(t)
	todayStart := overviewRollupSeedEvents(t, base)
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events`); err != nil {
		t.Fatalf("prune raw: %v", err)
	}
	seedRollupCoverage(t, todayStart.AddDate(0, 0, -6), false)
	noReady := fetchOverviewAggregates(t)
	for _, point := range noReady.Trend {
		if point.Blocked != 0 || point.Detected != 0 {
			t.Fatalf("无就绪标记时趋势 %s=(%d,%d), want (0,0)（必须回退已裁剪的原始表）", point.Date, point.Blocked, point.Detected)
		}
	}

	// 库 B：同一覆盖 + 就绪标记 → rollup 读路径重建完整历史。
	setupSecurityPolicyTestDB(t)
	seedRollupReadTables(t)
	todayStart = overviewRollupSeedEvents(t, base)
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events`); err != nil {
		t.Fatalf("prune raw: %v", err)
	}
	seedRollupCoverage(t, todayStart.AddDate(0, 0, -6), true)
	ready := fetchOverviewAggregates(t)
	var blockedTotal int
	for _, point := range ready.Trend {
		blockedTotal += point.Blocked
	}
	if blockedTotal != 7 {
		t.Fatalf("就绪标记缺失解除后趋势 blocked 合计=%d, want 7（固定日期 5 + 当日 2）", blockedTotal)
	}
}

// 时区口径：Asia/Shanghai（固定 +08）本地日界跨 UTC 日——本地 00:30 事件的
// rollup 分钟（UTC 前一日 16:30）必须落本地当日桶；本地日界整点事件取
// UTC 分钟恰好等于桶下界（前缀文本比较的边界分钟不得丢失）。
// 原始表事件全部裁剪，桶归属只能由 rollup 分钟重建。
func TestSecurityOverviewAggregates_rollupMinuteBucketsFollowLocalDay(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	seedRollupReadTables(t)
	cst := time.FixedZone("CST", 8*3600)
	today := time.Date(2026, 3, 8, 10, 0, 0, 0, cst)
	local := func(day int, hour, minute int) time.Time {
		return time.Date(2026, 3, day, hour, minute, 0, 0, cst).UTC()
	}
	for _, e := range []rollupReadEvent{
		// 本地 03-07 00:30 → UTC 03-06 16:30 → 本地桶 03-07。
		{eventTimeUTC: local(7, 0, 30), clientIP: "93.184.216.10", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"},
		// 本地 03-06 23:50 → UTC 03-06 15:50 → 本地桶 03-06。
		{eventTimeUTC: local(6, 23, 50), clientIP: "93.184.216.20", ruleTriggered: "941100", ruleMsg: "XSS", action: "logged"},
		// 本地 03-08 00:00 → UTC 03-07 16:00 = 桶下界分钟（边界含入）。
		{eventTimeUTC: local(8, 0, 0), clientIP: "93.184.216.30", ruleTriggered: "942100", ruleMsg: "SQL注入", action: "blocked"},
	} {
		seedRollupReadEvent(t, e)
	}
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events`); err != nil {
		t.Fatalf("prune raw: %v", err)
	}
	seedRollupCoverage(t, time.Date(2026, 3, 2, 0, 0, 0, 0, cst), true)

	agg, err := loadSecurityOverviewAggregates(db.MetricsDB, today, today.AddDate(0, 0, -6).UTC().Format("2006-01-02 15:04:05"), "Asia/Shanghai")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	want := map[string][2]int{
		"2026-03-06": {0, 1},
		"2026-03-07": {1, 0},
		"2026-03-08": {1, 0},
	}
	if len(agg.trend) != 7 {
		t.Fatalf("trend=%d 点, want 7", len(agg.trend))
	}
	for _, point := range agg.trend {
		if w, ok := want[point.Date]; ok {
			if point.Blocked != w[0] || point.Detected != w[1] {
				t.Fatalf("趋势桶 %s=(%d,%d), want (%d,%d)", point.Date, point.Blocked, point.Detected, w[0], w[1])
			}
			delete(want, point.Date)
		} else if point.Blocked != 0 || point.Detected != 0 {
			t.Fatalf("趋势桶 %s=(%d,%d), want (0,0)", point.Date, point.Blocked, point.Detected)
		}
	}
	if len(want) != 0 {
		t.Fatalf("趋势缺桶: %v", want)
	}
}

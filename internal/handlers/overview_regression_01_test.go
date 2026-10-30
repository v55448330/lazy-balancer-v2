package handlers

// 契约：特征口径（active_policies/总量披露）在模式归一为 off 后必须仍按
// 真实特征计数——旧 `mode!='off'` 口径使纯 stage1/2 部署显示 0。

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func TestGetSecurityOverview_activePoliciesCountsFeatureBearingStages(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	// Given：三条启用策略——stage1 纯 ACL、stage2 纯限流、stage3 WAF、
	// 另有一条无任何特征的 off 空策略（不应计入）
	seed := func(name string, acl int, aclList string, rl int, rps int, mode string, custom string) {
		if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, ip_acl_enabled, ip_acl_list, rate_limit_enabled, rate_limit_rps, custom_rules, policy_type)
			VALUES (?, ?, 1, ?, ?, ?, ?, ?, '')`,
			name, mode, acl, aclList, rl, rps, custom); err != nil {
			t.Fatal(err)
		}
	}
	seed("s1-纯ACL", 1, `["1.1.1.1"]`, 0, 0, "off", "[]")
	seed("s2-纯限流", 0, "[]", 1, 100, "off", "[]")
	seed("s3-纯WAF", 0, "[]", 0, 0, "blocking", "[]")
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type) VALUES ('空策略', 'off', 1, 'stage3')`); err != nil {
		t.Fatal(err)
	}

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int                     `json:"code"`
		Data models.SecurityOverview `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	// Then：三条特征策略全部计入（旧口径 mode!='off' 只数到 s3 一条）
	if resp.Data.ActivePolicies != 3 {
		t.Fatalf("active_policies=%d, want 3（特征口径：stage1/2/3 各 1，空策略不计）", resp.Data.ActivePolicies)
	}
}

// 总量口径披露：今日拦截/检测优先走分钟 rollup（与大屏同口径排除私网，
// includes_reserved=false）；rollup 覆盖水位未回推/固化陈旧时回退原始表
// 直算（含私网，includes_reserved=true）；7 天趋势/Top IP 恒为含私网口径
// （读路径下沉后新维度表写入侧同口径含保留地址，性能优化不改变统计口径）。
// nil metrics 零面板分支同键常驻。
// 本用例无 rollup 覆盖状态 → 回退路径（含私网，披露 true）。
func TestGetSecurityOverview_disclosesReservedInclusiveTotals(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			IncludesReserved bool `json:"includes_reserved"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Data.IncludesReserved {
		t.Fatalf("includes_reserved=false, want true（总量含私网/保留地址事件须披露）: %s", recorder.Body.String())
	}

	// nil metrics 分支同键（零面板也须披露口径）
	oldMetrics := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = oldMetrics })
	recorder = getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("nil-metrics overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"includes_reserved":true`) {
		t.Fatalf("nil-metrics body=%s, want includes_reserved:true 常驻", recorder.Body.String())
	}
}

// 今日计数与威胁大屏同源（分钟 rollup）：行帽触顶时原始表只剩最近若干
// 分钟，直算静默少计。rollup 覆盖到今日起点且固化新鲜时——计数=rollup
// SUM（排除私网/保留地址，含昨日分钟不计），includes_reserved=false；
// 原始表里的私网事件与昨日事件均不进入今日计数。
// （近 7 天聚合读路径下沉为纯性能优化——新维度表写入侧含保留地址，口径
// 不变；本用例无窗口级覆盖状态，聚合走原始表回退，与切换前行为一致。）
func TestGetSecurityOverview_todayCountsFromRollupExcludeReserved(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	lastComplete := now.UTC().Add(-time.Minute).Truncate(time.Minute)
	todayMinute := todayStart.UTC().Format("2006-01-02 15:04")

	// 原始表事件：今日公网拦截×2、今日私网拦截×1、今日公网检测×1、昨日拦截×1。
	//（rollup 行模拟固化结果——私网事件固化时被排除，故只播公网计数。）
	seedThreatScreenEventNamed(t, todayStart.UTC().Add(time.Hour).Format("2006-01-02 15:04:05"), "93.184.216.7", "942100", "SQL", "blocked", "r")
	seedThreatScreenEventNamed(t, todayStart.UTC().Add(2*time.Hour).Format("2006-01-02 15:04:05"), "93.184.216.8", "942100", "SQL", "blocked", "r")
	seedThreatScreenEventNamed(t, todayStart.UTC().Add(3*time.Hour).Format("2006-01-02 15:04:05"), "10.0.0.8", "942100", "SQL", "blocked", "r")
	seedThreatScreenEventNamed(t, todayStart.UTC().Add(4*time.Hour).Format("2006-01-02 15:04:05"), "93.184.216.9", "941100", "XSS", "logged", "r")
	seedThreatScreenEventNamed(t, todayStart.UTC().Add(-time.Hour).Format("2006-01-02 15:04:05"), "93.184.216.10", "942100", "SQL", "blocked", "r")
	// rollup：今日 blocked=2、logged=1；昨日分钟 blocked=5（不得计入）。
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES
		(?, '', '', 'WAF', '942100', 'blocked', 2),
		(?, '', '', 'WAF', '941100', 'logged', 1),
		(?, '', '', 'WAF', '942100', 'blocked', 5)`,
		todayMinute, todayMinute, todayStart.UTC().Add(-time.Hour).Format("2006-01-02 15:04")); err != nil {
		t.Fatalf("seed rollup: %v", err)
	}
	// 覆盖状态：覆盖起点=今日起点，水位=最新完整分钟（新鲜）。
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES
		('threat_rollup_covered_from', ?), ('threat_rollup_last_fixed_minute', ?)`,
		todayMinute, lastComplete.Format("2006-01-02 15:04")); err != nil {
		t.Fatalf("seed rollup state: %v", err)
	}

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			TodayBlocked     int  `json:"today_blocked"`
			TodayDetected    int  `json:"today_detected"`
			IncludesReserved bool `json:"includes_reserved"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.TodayBlocked != 2 || resp.Data.TodayDetected != 1 {
		t.Fatalf("today=(%d,%d), want (2,1)——rollup 同源（私网事件与昨日分钟不得计入）", resp.Data.TodayBlocked, resp.Data.TodayDetected)
	}
	if resp.Data.IncludesReserved {
		t.Fatalf("includes_reserved=true, want false（rollup 口径排除私网须披露）: %s", recorder.Body.String())
	}
}

// rollup 固化陈旧（水位落后超过阈值，warmer 停转形态）→ 回退原始表直算
// （含私网，includes_reserved=true），不得把陈旧 rollup 伪装成最新计数。
func TestGetSecurityOverview_todayCountsFallBackWhenRollupStale(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	todayMinute := todayStart.UTC().Format("2006-01-02 15:04")
	staleWatermark := now.UTC().Add(-10 * time.Minute).Truncate(time.Minute)

	seedThreatScreenEventNamed(t, todayStart.UTC().Add(time.Hour).Format("2006-01-02 15:04:05"), "93.184.216.7", "942100", "SQL", "blocked", "r")
	seedThreatScreenEventNamed(t, todayStart.UTC().Add(2*time.Hour).Format("2006-01-02 15:04:05"), "10.0.0.8", "942100", "SQL", "blocked", "r")
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES
		(?, '', '', 'WAF', '942100', 'blocked', 1)`, todayMinute); err != nil {
		t.Fatalf("seed rollup: %v", err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES
		('threat_rollup_covered_from', ?), ('threat_rollup_last_fixed_minute', ?)`,
		todayMinute, staleWatermark.Format("2006-01-02 15:04")); err != nil {
		t.Fatalf("seed rollup state: %v", err)
	}

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			TodayBlocked     int  `json:"today_blocked"`
			IncludesReserved bool `json:"includes_reserved"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.TodayBlocked != 2 {
		t.Fatalf("today_blocked=%d, want 2（陈旧 rollup 必须回退原始表直算，私网事件计入）", resp.Data.TodayBlocked)
	}
	if !resp.Data.IncludesReserved {
		t.Fatalf("includes_reserved=false, want true（回退口径含私网须披露）")
	}
}

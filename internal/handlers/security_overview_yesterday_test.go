package handlers

// 安全总览新增指标（昨日窗口计数 + 正常请求差分）RED→GREEN 用例：
//   - 昨日拦截/检测走原始表单日窗口（本地日界跨 UTC），攻击面谓词同今日直算；
//   - TCP 协议拆分（blocked）/检测 TCP 恒 0（契约披露，与数据无关）；
//   - 正常请求 HTTP=累计差分−被拦差分（跨日/重置钳制/样本不足/负值钳零）；
//   - 正常 TCP=lb_l4_conn_history 全局行 allowed 日差分；
//   - apidocs 口径披露与示例键。

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

type overviewNewFieldsResponse struct {
	Code int `json:"code"`
	Data struct {
		YesterdayBlocked     *int `json:"yesterday_blocked"`
		YesterdayBlockedTCP  *int `json:"yesterday_blocked_tcp"`
		YesterdayDetected    *int `json:"yesterday_detected"`
		YesterdayDetectedTCP *int `json:"yesterday_detected_tcp"`
		NormalToday          *int `json:"normal_today"`
		NormalTodayHTTP      *int `json:"normal_today_http"`
		NormalTodayTCP       *int `json:"normal_today_tcp"`
		NormalYesterday      *int `json:"normal_yesterday"`
		NormalYesterdayHTTP  *int `json:"normal_yesterday_http"`
		NormalYesterdayTCP   *int `json:"normal_yesterday_tcp"`
		TodayBlockedTCP      *int `json:"today_blocked_tcp"`
		TodayBlocked         *int `json:"today_blocked"`
		TodayDetected        *int `json:"today_detected"`
	} `json:"data"`
}

func fetchOverviewNewFields(t *testing.T) overviewNewFieldsResponse {
	t.Helper()
	router := newSecurityEventsRouter(t)
	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp overviewNewFieldsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal overview: %v", err)
	}
	pointers := map[string]*int{
		"yesterday_blocked":      resp.Data.YesterdayBlocked,
		"yesterday_blocked_tcp":  resp.Data.YesterdayBlockedTCP,
		"yesterday_detected":     resp.Data.YesterdayDetected,
		"yesterday_detected_tcp": resp.Data.YesterdayDetectedTCP,
		"normal_today":           resp.Data.NormalToday,
		"normal_today_http":      resp.Data.NormalTodayHTTP,
		"normal_today_tcp":       resp.Data.NormalTodayTCP,
		"normal_yesterday":       resp.Data.NormalYesterday,
		"normal_yesterday_http":  resp.Data.NormalYesterdayHTTP,
		"normal_yesterday_tcp":   resp.Data.NormalYesterdayTCP,
		"today_blocked_tcp":      resp.Data.TodayBlockedTCP,
		"today_blocked":          resp.Data.TodayBlocked,
		"today_detected":         resp.Data.TodayDetected,
	}
	for key, ptr := range pointers {
		if ptr == nil {
			t.Fatalf("响应缺 %s 键: %s", key, recorder.Body.String())
		}
	}
	return resp
}

// seedOverviewEvent 带协议类型的事件种子（event_type: crs/tcp）。
func seedOverviewEvent(t *testing.T, eventTime, clientIP, action, eventType string) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name)
		VALUES (?, ?, 'GET', '/a', ?, '942100', 'SQL', ?, '测试规则')`,
		eventTime, clientIP, eventType, action); err != nil {
		t.Fatalf("seed event: %v", err)
	}
}

// 昨日窗口按本地日界跨 UTC：昨日窗口=[昨日本地 0 点, 今日本地 0 点)（UTC 文本
// 比较），窗口外（前日/今日起点及以后）事件不得计入；TCP 拆分只认
// event_type='tcp' AND action='blocked'；yesterday_detected_tcp=tcp+logged
// （L4 信任检测 trust_detect 产该形态，与 HTTP stage0 DetectionOnly 对齐）。
func TestGetSecurityOverview_yesterdayWindowLocalBoundaryAndTCPSplit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	ydayStart := todayStart.AddDate(0, 0, -1)
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") }

	// 昨日窗口内：blocked crs ×1 + blocked tcp ×1 + logged crs ×1。
	seedOverviewEvent(t, ts(ydayStart.Add(time.Hour)), "93.184.216.7", "blocked", "crs")
	seedOverviewEvent(t, ts(ydayStart.Add(2*time.Hour)), "93.184.216.8", "blocked", "tcp")
	seedOverviewEvent(t, ts(ydayStart.Add(3*time.Hour)), "93.184.216.9", "logged", "crs")
	// 窗口外：昨日起点前 1 小时（前日）blocked——不得计入昨日。
	seedOverviewEvent(t, ts(ydayStart.Add(-time.Hour)), "93.184.216.10", "blocked", "crs")
	// 边界：恰为今日本地 0 点的事件属今日（今日 TCP 拆分=1）。
	seedOverviewEvent(t, ts(todayStart), "93.184.216.11", "blocked", "tcp")
	// 昨日窗口内 tcp+logged（L4 信任检测 trust_detect 形态）计入 yesterday_detected_tcp。
	seedOverviewEvent(t, ts(ydayStart.Add(4*time.Hour)), "93.184.216.12", "logged", "tcp")

	resp := fetchOverviewNewFields(t)
	if got := *resp.Data.YesterdayBlocked; got != 2 {
		t.Fatalf("yesterday_blocked=%d, want 2（窗口内 crs+tcp，前日事件不计）", got)
	}
	if got := *resp.Data.YesterdayBlockedTCP; got != 1 {
		t.Fatalf("yesterday_blocked_tcp=%d, want 1（仅 tcp+blocked）", got)
	}
	if got := *resp.Data.YesterdayDetected; got != 2 {
		t.Fatalf("yesterday_detected=%d, want 2（合计口径含窗口内全部 logged，含人工 tcp+logged 形态）", got)
	}
	if got := *resp.Data.YesterdayDetectedTCP; got != 1 {
		t.Fatalf("yesterday_detected_tcp=%d, want 1（窗口内 tcp+logged=信任检测形态）", got)
	}
	if got := *resp.Data.TodayBlockedTCP; got != 1 {
		t.Fatalf("today_blocked_tcp=%d, want 1（今日起点事件属今日）", got)
	}
	if got := *resp.Data.TodayBlocked; got != 1 {
		t.Fatalf("today_blocked=%d, want 1（回退直算口径，tcp 边界事件）", got)
	}
}

// seedGlobalSample / seedRuleBlocked metrics_history 种子（全局累计快照与
// per-rule 被拦累计快照，同 storeMetrics/storePerRuleMetrics 的存储语义）。
func seedGlobalSample(t *testing.T, ts time.Time, requestsTotal int) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp, requests_total)
		VALUES (NULL, ?, ?)`, ts.UTC().Format("2006-01-02 15:04:05"), requestsTotal); err != nil {
		t.Fatalf("seed global sample: %v", err)
	}
}

func seedRuleBlocked(t *testing.T, ruleID string, ts time.Time, blocked int) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp, requests_blocked)
		VALUES (?, ?, ?)`, ruleID, ts.UTC().Format("2006-01-02 15:04:05"), blocked); err != nil {
		t.Fatalf("seed rule blocked: %v", err)
	}
}

func seedL4Allowed(t *testing.T, ruleID string, ts time.Time, allowed int) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO lb_l4_conn_history (timestamp, rule_id, allowed, denied)
		VALUES (?, ?, ?, 0)`, ts.UTC().Format("2006-01-02 15:04:05"), ruleID, allowed); err != nil {
		t.Fatalf("seed l4 allowed: %v", err)
	}
}

// 正常请求差分跨日：今日=最新累计−今日起点前末样本−今日被拦差分；
// 昨日=今日起点前末样本−昨日起点前末样本−昨日被拦差分；
// 正常 TCP=lb_l4_conn_history 全局行 allowed 日窗口求和。
func TestGetSecurityOverview_normalRequestDiffCrossDay(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	ydayStart := todayStart.AddDate(0, 0, -1)
	anchorYday := ydayStart.Add(-time.Hour)   // 昨日起点前末样本
	anchorToday := todayStart.Add(-time.Hour) // 今日起点前末样本（昨日末尾）
	latest := now.UTC().Truncate(time.Second)

	seedGlobalSample(t, anchorYday, 100)
	seedGlobalSample(t, anchorToday, 250)
	seedGlobalSample(t, latest, 400)
	// per-rule 被拦累计：lb_a 昨日 +15、今日 +15；lb_b 今日 +5。
	seedRuleBlocked(t, "lb_a", anchorYday, 10)
	seedRuleBlocked(t, "lb_a", anchorToday, 25)
	seedRuleBlocked(t, "lb_a", latest, 40)
	seedRuleBlocked(t, "lb_b", anchorToday, 0)
	seedRuleBlocked(t, "lb_b", latest, 5)
	// TCP 正常连接：昨日窗 34、今日窗 12（全局行；per-rule 行不参与读侧求和）。
	seedL4Allowed(t, "", ydayStart.Add(time.Hour), 34)
	seedL4Allowed(t, "", todayStart.Add(time.Hour), 12)
	seedL4Allowed(t, "lb_tcp_1", todayStart.Add(time.Hour), 999)

	resp := fetchOverviewNewFields(t)
	// 昨日 = (250−100) − ((25−10)+(0−0)) = 135；今日 = (400−250) − ((40−25)+(5−0)) = 130。
	if got := *resp.Data.NormalYesterday; got != 135 {
		t.Fatalf("normal_yesterday=%d, want 135", got)
	}
	if got := *resp.Data.NormalYesterdayHTTP; got != 135 {
		t.Fatalf("normal_yesterday_http=%d, want 135（与 normal_yesterday 同值）", got)
	}
	if got := *resp.Data.NormalToday; got != 130 {
		t.Fatalf("normal_today=%d, want 130", got)
	}
	if got := *resp.Data.NormalTodayHTTP; got != 130 {
		t.Fatalf("normal_today_http=%d, want 130（与 normal_today 同值）", got)
	}
	if got := *resp.Data.NormalTodayTCP; got != 12 {
		t.Fatalf("normal_today_tcp=%d, want 12（仅全局行，per-rule 999 不得计入）", got)
	}
	if got := *resp.Data.NormalYesterdayTCP; got != 34 {
		t.Fatalf("normal_yesterday_tcp=%d, want 34", got)
	}
}

// 重置钳制：区间内样本值下降（计数器随 /load/重启归零）→ 该区间增量取后端
// 样本当前值（总请求与 per-rule 被拦同法），不出现负数。
func TestGetSecurityOverview_normalRequestDiffResetClamp(t *testing.T) {
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
	seedGlobalSample(t, latest, 200) // 今日内重置：< anchorToday
	seedRuleBlocked(t, "lb_a", anchorYday, 10)
	seedRuleBlocked(t, "lb_a", anchorToday, 25)
	seedRuleBlocked(t, "lb_a", latest, 5) // 重置：< 25

	resp := fetchOverviewNewFields(t)
	// 今日总请求差分=200（取 cur）、被拦差分=5（取 cur）→ 200−5=195；
	// 昨日不受影响 = (250−100) − 15 = 135。
	if got := *resp.Data.NormalToday; got != 195 {
		t.Fatalf("normal_today=%d, want 195（重置钳制：增量取 cur）", got)
	}
	if got := *resp.Data.NormalYesterday; got != 135 {
		t.Fatalf("normal_yesterday=%d, want 135（昨日窗口不受今日重置影响）", got)
	}
}

// 样本不足（锚不到昨日起点前样本=history 短于 2 天）：normal_* 全部返回 0
// （样本积累中，披露见 apidocs）。
func TestGetSecurityOverview_normalFieldsZeroWhenSamplesInsufficient(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	seedGlobalSample(t, todayStart.Add(time.Hour), 500)
	seedRuleBlocked(t, "lb_a", todayStart.Add(time.Hour), 3)

	resp := fetchOverviewNewFields(t)
	for name, got := range map[string]*int{
		"normal_today":          resp.Data.NormalToday,
		"normal_today_http":     resp.Data.NormalTodayHTTP,
		"normal_today_tcp":      resp.Data.NormalTodayTCP,
		"normal_yesterday":      resp.Data.NormalYesterday,
		"normal_yesterday_http": resp.Data.NormalYesterdayHTTP,
		"normal_yesterday_tcp":  resp.Data.NormalYesterdayTCP,
	} {
		if *got != 0 {
			t.Fatalf("%s=%d, want 0（样本积累中）", name, *got)
		}
	}
}

// 负值钳零：被拦差分 > 总请求差分（口径差异极端形态）时 normal 不出负数。
func TestGetSecurityOverview_negativeNormalClampsToZero(t *testing.T) {
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
	seedGlobalSample(t, latest, 251) // 今日总请求差分仅 1
	seedRuleBlocked(t, "lb_a", anchorYday, 10)
	seedRuleBlocked(t, "lb_a", anchorToday, 25)
	seedRuleBlocked(t, "lb_a", latest, 200) // 重置钳制取 200 > 1

	resp := fetchOverviewNewFields(t)
	if got := *resp.Data.NormalToday; got != 0 {
		t.Fatalf("normal_today=%d, want 0（差分口径不与事件表对账，负值钳零）", got)
	}
}

// apidocs 披露：新字段键进示例（通用键钉测之外显式断言），口径披露与
// 「样本积累中」进描述。
func TestAPIDocs_overviewDisclosesNewFieldSemantics(t *testing.T) {
	description := operationDescription(routesEntry(t, "GET /security/overview"))
	for _, phrase := range []string{
		"yesterday_detected_tcp",
		"样本积累中",
		"与安全事件表不逐一对账",
		"raw_coverage_from",
	} {
		if !strings.Contains(description, phrase) {
			t.Fatalf("apidocs 描述缺口径披露 %q: %q", phrase, description)
		}
	}
	example := docResponseExample(t, "GET /security/overview")
	for _, key := range []string{
		"yesterday_blocked", "yesterday_blocked_tcp", "yesterday_detected", "yesterday_detected_tcp",
		"normal_today", "normal_today_http", "normal_today_tcp",
		"normal_yesterday", "normal_yesterday_http", "normal_yesterday_tcp",
	} {
		if _, ok := example[key]; !ok {
			t.Fatalf("apidocs 示例缺键 %s", key)
		}
	}
}

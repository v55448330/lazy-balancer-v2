package handlers

// L4 消费面 RED 测试（B 前端契约）：事件列表 event_type 筛选 + 总览
// today_blocked_tcp（原始表口径，rollup 表无 event_type 维度）。
import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func newL4EventsRouter(t *testing.T) *gin.Engine {
	t.Helper()
	setupSecurityPolicyTestDB(t)
	h := newFakeCaddyHandlers(t)
	router := gin.New()
	router.GET("/security/events", h.ListSecurityEvents)
	router.GET("/security/overview", h.GetSecurityOverview)
	return router
}

func seedL4SecurityEvent(t *testing.T, eventType, action, ruleTriggered string) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events
		(event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, anomaly_score)
		VALUES (datetime('now'), 'lb_tcp_ev', 1, '203.0.113.50', '', '', ?, ?, 'IP 黑名单拒绝', ?, 12)`,
		eventType, ruleTriggered, action); err != nil {
		t.Fatalf("seed event: %v", err)
	}
}

func decodeEventsBody(t *testing.T, body []byte) (events []map[string]any, data map[string]any) {
	t.Helper()
	var resp struct {
		Code int            `json:"code"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, body)
	}
	rawEvents, _ := resp.Data["events"].([]any)
	for _, raw := range rawEvents {
		if m, ok := raw.(map[string]any); ok {
			events = append(events, m)
		}
	}
	return events, resp.Data
}

func TestListSecurityEvents_eventTypeFilter(t *testing.T) {
	router := newL4EventsRouter(t)
	seedL4SecurityEvent(t, "tcp", "blocked", "2")
	seedL4SecurityEvent(t, "tcp", "blocked", "800001")
	seedL4SecurityEvent(t, "waf", "blocked", "942100")

	get := func(query string) (events []map[string]any, data map[string]any) {
		t.Helper()
		rec := getRequest(t, router, "/security/events"+query)
		if rec.Code != http.StatusOK {
			t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
		}
		return decodeEventsBody(t, rec.Body.Bytes())
	}

	events, _ := get("?event_type=tcp")
	if len(events) != 2 {
		t.Fatalf("tcp 筛选=%d 行, want 2", len(events))
	}
	for _, e := range events {
		if e["event_type"] != "tcp" {
			t.Fatalf("event_type=%v 混入 tcp 筛选", e["event_type"])
		}
	}
	events, _ = get("?event_type=waf")
	if len(events) != 1 || events[0]["event_type"] != "waf" {
		t.Fatalf("waf 筛选=%v, want 1 行 waf", events)
	}
	events, _ = get("")
	if len(events) != 3 {
		t.Fatalf("无筛选=%d 行, want 3（回归形状）", len(events))
	}
}

// seedL4TrustDetectTCPEvent 经真实 IPC 入库管线写入一条 L4 信任检测事务
// （仅阶段 1 特征生产形态：stage1 策略 mode=off + ip_acl_enabled=1，信任名单保留
// 检测经独立最小引擎产 id:12 审计行，X-LB-Protocol: tcp 合成审计）——
// 动作升格（logged→trust）由摄取侧完成，禁止直 seed 终态绕过升格。
func seedL4TrustDetectTCPEvent(t *testing.T, txID string, ts time.Time) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_enabled, ip_acl_mode, ip_acl_list, policy_type, enabled)
		VALUES ('l4-g1-only', 'off', 1, 'deny', '[]', 'stage1', 1)`); err != nil {
		t.Fatalf("seed stage1-only policy: %v", err)
	}
	line := fmt.Sprintf(`{"transaction":{"unix_timestamp":%d,"id":%q,"client_ip":"203.0.113.50","server_id":"example.com","request":{"method":"","uri":"","headers":{"host":["example.com"],"x-lb-protocol":["tcp"]}},"is_interrupted":false},"messages":[{"message":"trust detection","data":{"id":"12","raw":"SecRule"}}]}`,
		ts.Unix(), txID)
	rec := postSecurityEventsBatch(t, &SecurityEventsIPCServer{}, line+"\n")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("ingest trust detect status=%d body=%s, want 204", rec.Code, rec.Body.String())
	}
}

func TestGetSecurityOverview_todayBlockedTCP(t *testing.T) {
	router := newL4EventsRouter(t)
	seedL4SecurityEvent(t, "tcp", "blocked", "2")
	seedL4TrustDetectTCPEvent(t, "tx-l4-trust-today", time.Now())
	seedL4SecurityEvent(t, "waf", "blocked", "942100")

	rec := getRequest(t, router, "/security/overview")
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			TodayBlocked     *int `json:"today_blocked"`
			TodayBlockedTCP  *int `json:"today_blocked_tcp"`
			TodayDetected    *int `json:"today_detected"`
			TodayDetectedTCP *int `json:"today_detected_tcp"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if resp.Data.TodayBlockedTCP == nil {
		t.Fatalf("响应缺 today_blocked_tcp 键: %s", rec.Body.String())
	}
	if *resp.Data.TodayBlockedTCP != 1 {
		t.Fatalf("today_blocked_tcp=%d, want 1（仅 tcp+blocked）", *resp.Data.TodayBlockedTCP)
	}
	if resp.Data.TodayBlocked == nil || *resp.Data.TodayBlocked != 2 {
		t.Fatalf("today_blocked 回归形状漂移: %s", rec.Body.String())
	}
	// 检测列 TCP 拆分：信任检测（trust_detect, id 12）经摄取升格产 tcp+trust——
	// 可能产生数据就必须如实统计与显示，不得隐藏（拆分列不经过攻击口径
	// 谓词）。全局 today_detected 属攻击口径（AttackEventSQLPredicate）：
	// trust 整类不计入攻击/检测 KPI——本种子仅一条 trust 且为信任检测，
	// 全局检测为 0；可见性由拆分列与事件列表承载。
	if resp.Data.TodayDetectedTCP == nil {
		t.Fatalf("响应缺 today_detected_tcp 键: %s", rec.Body.String())
	}
	if *resp.Data.TodayDetectedTCP != 1 {
		t.Fatalf("today_detected_tcp=%d, want 1（tcp+trust 信任检测拆分列如实统计）", *resp.Data.TodayDetectedTCP)
	}
	if resp.Data.TodayDetected == nil || *resp.Data.TodayDetected != 0 {
		t.Fatalf("today_detected=%v, want 0（trust 不计入攻击口径检测 KPI）", resp.Data.TodayDetected)
	}
}

// 昨日窗口同口径：信任检测 tcp+trust 计入 yesterday_detected_tcp，
// 攻击口径 yesterday_detected 不受影响（全量/增量双轨一致）。
func TestGetSecurityOverview_yesterdayDetectedTCPTrustShape(t *testing.T) {
	router := newL4EventsRouter(t)
	yesterday := time.Now().Add(-24 * time.Hour)
	seedL4TrustDetectTCPEvent(t, "tx-l4-trust-yday", yesterday)

	rec := getRequest(t, router, "/security/overview")
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			YesterdayDetected    *int `json:"yesterday_detected"`
			YesterdayDetectedTCP *int `json:"yesterday_detected_tcp"`
			TodayDetectedTCP     *int `json:"today_detected_tcp"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if resp.Data.YesterdayDetectedTCP == nil || *resp.Data.YesterdayDetectedTCP != 1 {
		t.Fatalf("yesterday_detected_tcp=%v, want 1（昨日 tcp+trust 如实统计）: %s", resp.Data.YesterdayDetectedTCP, rec.Body.String())
	}
	if resp.Data.YesterdayDetected == nil || *resp.Data.YesterdayDetected != 0 {
		t.Fatalf("yesterday_detected=%v, want 0（trust 不计入攻击口径）", resp.Data.YesterdayDetected)
	}
	if resp.Data.TodayDetectedTCP == nil || *resp.Data.TodayDetectedTCP != 0 {
		t.Fatalf("today_detected_tcp=%v, want 0（昨日事件不得跨日界计入今日）", resp.Data.TodayDetectedTCP)
	}
}

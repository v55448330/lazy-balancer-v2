package handlers

// L4 消费面 RED 测试（B 前端契约）：事件列表 event_type 筛选 + 总览
// today_blocked_tcp（原始表口径，rollup 表无 event_type 维度）。
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func newL4EventsRouter(t *testing.T) *gin.Engine {
	t.Helper()
	setupSecurityPolicyTestDB(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(srv.URL)}
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

func TestGetSecurityOverview_todayBlockedTCP(t *testing.T) {
	router := newL4EventsRouter(t)
	seedL4SecurityEvent(t, "tcp", "blocked", "2")
	seedL4SecurityEvent(t, "tcp", "logged", "12")
	seedL4SecurityEvent(t, "waf", "blocked", "942100")

	rec := getRequest(t, router, "/security/overview")
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			TodayBlocked    *int `json:"today_blocked"`
			TodayBlockedTCP *int `json:"today_blocked_tcp"`
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
}

package handlers

// MCP 会话可见性/强制断开/统计聚合 REST 钉测：JOIN 展示名与在线口径、
// mine=1 收敛、断开删行+显式审计留痕+未知会话 404、统计形状（今日调用/
// 在线会话/错误率/TOP 工具/7 天趋势含补零）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// withIsolatedMCPDatabase 三句柄隔离夹具（与 mcpserver 同形：只还原 db.DB
// 会把已关闭的 MetricsDB/AuditDB 留给后续用例，-shuffle 下顺序依赖假红）。
func withIsolatedMCPDatabase(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
}

// seedMCPSessionFixture 用户/Key/会话/统计种子。
//   - 用户：1=root(admin)、7=alice、8=bob；Key：42=ci-key(属主 7)。
//   - 会话：sid-alice-online（7，在线）、sid-alice-stale（7，过期）、
//     sid-bob-online（8，在线，用户行在）。
//   - 统计：今日 list_rules 10/1、今日 get_rule 2/2、3 天前 list_rules 5/0、
//     8 天前 audit_out 100/0（趋势窗外）。
func seedMCPSessionFixture(t *testing.T) {
	t.Helper()
	seeds := []string{
		`INSERT INTO users (id, username, password_hash, role) VALUES (1,'root','x','admin')`,
		`INSERT INTO users (id, username, password_hash, role) VALUES (7,'alice','x','user')`,
		`INSERT INTO users (id, username, password_hash, role) VALUES (8,'bob','x','user')`,
		`INSERT INTO api_keys (id, name, key_hash, key_prefix, created_by) VALUES (42,'ci-key','hash','lb_sk_ci',7)`,
		`INSERT INTO mcp_sessions (session_id, user_id, api_key_id, ip, user_agent, first_seen, last_seen)
			VALUES ('sid-alice-online', 7, 42, '10.0.0.1', 'agent/1', datetime('now'), datetime('now'))`,
		`INSERT INTO mcp_sessions (session_id, user_id, api_key_id, ip, user_agent, first_seen, last_seen)
			VALUES ('sid-alice-stale', 7, 42, '10.0.0.1', 'agent/1', '2020-01-01 00:00:00', '2020-01-01 00:00:00')`,
		`INSERT INTO mcp_sessions (session_id, user_id, api_key_id, ip, user_agent, first_seen, last_seen)
			VALUES ('sid-bob-online', 8, 0, '10.0.0.2', 'agent/2', datetime('now'), datetime('now'))`,
		"INSERT INTO mcp_tool_stats (date, tool, key_id, calls, errors) VALUES ('" + time.Now().Format("2006-01-02") + "', 'list_rules', 42, 10, 1)",
		"INSERT INTO mcp_tool_stats (date, tool, key_id, calls, errors) VALUES ('" + time.Now().Format("2006-01-02") + "', 'get_rule', 42, 2, 2)",
		"INSERT INTO mcp_tool_stats (date, tool, key_id, calls, errors) VALUES ('" + time.Now().AddDate(0, 0, -3).Format("2006-01-02") + "', 'list_rules', 42, 5, 0)",
		"INSERT INTO mcp_tool_stats (date, tool, key_id, calls, errors) VALUES ('" + time.Now().AddDate(0, 0, -8).Format("2006-01-02") + "', 'list_rules', 42, 100, 0)",
	}
	for _, seed := range seeds {
		if _, err := db.DB.Exec(seed); err != nil {
			t.Fatalf("seed %q: %v", seed, err)
		}
	}
}

// newMCPSessionRouter 装配被测路由并模拟认证注入（identity=uid/role）。
func newMCPSessionRouter(uid int64, role string) (*Handlers, *gin.Engine) {
	h := &Handlers{}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", uid)
		c.Set("username", "root")
		c.Set("role", role)
		c.Set("auth_type", "session")
		c.Next()
	})
	r.GET("/security/mcp-sessions", h.ListMCPSessions)
	r.POST("/security/mcp-sessions/:id/disconnect", h.DisconnectMCPSession)
	r.GET("/notification/mcp/stats", h.GetMCPStats)
	return h, r
}

func TestListMCPSessionsAdminSeesAllWithJoins(t *testing.T) {
	withIsolatedMCPDatabase(t)
	seedMCPSessionFixture(t)
	_, router := newMCPSessionRouter(1, "admin")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/security/mcp-sessions", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Code int `json:"code"`
		Data struct {
			Sessions []struct {
				SessionID string `json:"session_id"`
				UserID    int64  `json:"user_id"`
				Username  string `json:"username"`
				KeyID     int64  `json:"key_id"`
				KeyName   string `json:"key_name"`
				Online    bool   `json:"online"`
			} `json:"sessions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, response.Body.String())
	}
	byID := map[string]int{}
	for i, s := range payload.Data.Sessions {
		byID[s.SessionID] = i
	}
	if len(payload.Data.Sessions) != 3 {
		t.Fatalf("sessions=%d, want 3（管理员全量）", len(payload.Data.Sessions))
	}
	alice := payload.Data.Sessions[byID["sid-alice-online"]]
	if alice.Username != "alice" || alice.KeyID != 42 || alice.KeyName != "ci-key" {
		t.Errorf("JOIN 展示名不符: %+v", alice)
	}
	if !alice.Online {
		t.Errorf("在线会话 online=false")
	}
	if stale := payload.Data.Sessions[byID["sid-alice-stale"]]; stale.Online {
		t.Errorf("过期会话 online=true")
	}
	bob := payload.Data.Sessions[byID["sid-bob-online"]]
	if bob.Username != "bob" || bob.KeyName != "" {
		t.Errorf("无 Key 会话 JOIN 兜底不符: %+v", bob)
	}
}

func TestListMCPSessionsMineFiltersToOwner(t *testing.T) {
	withIsolatedMCPDatabase(t)
	seedMCPSessionFixture(t)
	_, router := newMCPSessionRouter(7, "user")

	request := httptest.NewRequest(http.MethodGet, "/security/mcp-sessions?mine=1", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	var payload struct {
		Data struct {
			Sessions []struct {
				SessionID string `json:"session_id"`
				UserID    int64  `json:"user_id"`
			} `json:"sessions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Data.Sessions) != 2 {
		t.Fatalf("mine=1 sessions=%d, want 2（仅本人）", len(payload.Data.Sessions))
	}
	for _, s := range payload.Data.Sessions {
		if s.UserID != 7 {
			t.Errorf("他人会话泄漏: %+v", s)
		}
	}
}

func TestDisconnectMCPSessionDeletesRowAndAudits(t *testing.T) {
	withIsolatedMCPDatabase(t)
	seedMCPSessionFixture(t)
	_, router := newMCPSessionRouter(1, "admin")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/security/mcp-sessions/sid-alice-online/disconnect", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM mcp_sessions WHERE session_id='sid-alice-online'`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("会话行未删")
	}
	var action, resource, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, resource, detail FROM audit_log ORDER BY id DESC LIMIT 1`).
		Scan(&action, &resource, &detail); err != nil {
		t.Fatalf("审计行缺失: %v", err)
	}
	if action != "断开" || resource != "MCP 会话" || !strings.Contains(detail, "sid-alice-online") {
		t.Errorf("审计留痕不符: action=%q resource=%q detail=%q", action, resource, detail)
	}

	// 未知会话 404。
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/security/mcp-sessions/sid-missing/disconnect", nil))
	if response.Code != http.StatusNotFound {
		t.Errorf("未知会话 status=%d, want 404", response.Code)
	}
}

func TestGetMCPStatsAggregatesShape(t *testing.T) {
	withIsolatedMCPDatabase(t)
	seedMCPSessionFixture(t)
	_, router := newMCPSessionRouter(1, "admin")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/notification/mcp/stats", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Code int `json:"code"`
		Data struct {
			TodayCalls     int64   `json:"today_calls"`
			ActiveSessions int64   `json:"active_sessions"`
			ErrorRate      float64 `json:"error_rate"`
			TopTools       []struct {
				Tool  string `json:"tool"`
				Calls int64  `json:"calls"`
			} `json:"top_tools"`
			Trend []struct {
				Date  string `json:"date"`
				Calls int64  `json:"calls"`
			} `json:"trend"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, response.Body.String())
	}
	if payload.Data.TodayCalls != 12 {
		t.Errorf("today_calls=%d, want 12", payload.Data.TodayCalls)
	}
	if payload.Data.ActiveSessions != 2 {
		t.Errorf("active_sessions=%d, want 2（过期会话不计）", payload.Data.ActiveSessions)
	}
	if payload.Data.ErrorRate != 0.25 {
		t.Errorf("error_rate=%v, want 0.25（3/12）", payload.Data.ErrorRate)
	}
	if len(payload.Data.TopTools) != 2 || payload.Data.TopTools[0].Tool != "list_rules" || payload.Data.TopTools[0].Calls != 10 {
		t.Errorf("top_tools=%+v, want list_rules=10 在首", payload.Data.TopTools)
	}
	if len(payload.Data.Trend) != 7 {
		t.Fatalf("trend=%d 点, want 7（含补零）", len(payload.Data.Trend))
	}
	var trendSum int64
	for _, point := range payload.Data.Trend {
		trendSum += point.Calls
	}
	if trendSum != 17 {
		t.Errorf("trend 合计=%d, want 17（12 今日+5 三天前；8 天前窗外不计）", trendSum)
	}
}

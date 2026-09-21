package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 安全测试事件生成/清除（R45 验证辅助，用户裁定）：curated 集覆盖阶段化
// 流水线各族的代表性事件形状，全部行 rule_caddy_id=lb_testevent 标记，
// 清除仅删标记行——用户真实事件（含同 IP 真实命中）永不受影响。

func newSecurityTestEventsContext(t *testing.T, method string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, "/api/v1/security/test-events", nil)
	c.Set("username", "admin")
	return c, rec
}

func countTestEvents(t *testing.T, where string, args ...any) int {
	t.Helper()
	var n int
	if err := db.MetricsDB.QueryRow("SELECT COUNT(*) FROM security_events WHERE rule_caddy_id='lb_testevent' AND "+where, args...).Scan(&n); err != nil {
		t.Fatalf("count security_events (%s): %v", where, err)
	}
	return n
}

// ①生成：插入行数与响应 inserted 一致，且 rule_triggered / action / 时间分布 /
// 来源 IP / rule_msg 多样性覆盖 curated 设计的每个形状（供 stage-stats、
// 总览族分类、事件列表筛选、IP 弹框四条消费链验证）。⑤生成操作落审计。
func TestCreateSecurityTestEvents_seedsCuratedSet(t *testing.T) {
	// Given a fresh metrics store and audit store
	setupSecurityPolicyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit database: %v", err)
	}
	c, rec := newSecurityTestEventsContext(t, http.MethodPost)

	// When the curated set is generated
	(&Handlers{}).CreateSecurityTestEvents(c)

	// Then the response reports the inserted count with a cleanup hint
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Code int `json:"code"`
		Data struct {
			Inserted int    `json:"inserted"`
			Hint     string `json:"hint"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Code != 0 || body.Data.Inserted != 12 {
		t.Fatalf("code=%d inserted=%d, want code=0 inserted=12; body=%s", body.Code, body.Data.Inserted, rec.Body.String())
	}
	if body.Data.Hint == "" {
		t.Fatalf("hint missing: 测试数据会污染总览/stage-stats 统计，响应必须提示清除方式")
	}

	// And the marked row count matches the reported insertions
	if got := countTestEvents(t, "1=1"); got != body.Data.Inserted {
		t.Fatalf("marked rows=%d, want %d", got, body.Data.Inserted)
	}

	// And every designed rule_triggered shape is present (942100 twice: one
	// blocked in stage-3 and one detection-logged)
	shapes := map[string]int{"2": 1, "4": 1, "7": 1, "8": 1, "800001": 1, "800499": 1, "942100": 2, "949110": 1, "10005": 1, "10006": 1, "11": 1}
	for shape, want := range shapes {
		if got := countTestEvents(t, "rule_triggered=?", shape); got != want {
			t.Fatalf("rule_triggered=%s rows=%d, want %d", shape, got, want)
		}
	}

	// And the action distribution is blocked-dominant with logged controls
	if got := countTestEvents(t, "action='blocked'"); got != 10 {
		t.Fatalf("blocked rows=%d, want 10", got)
	}
	if got := countTestEvents(t, "action='logged'"); got != 2 {
		t.Fatalf("logged rows=%d, want 2", got)
	}

	// And the event_time spread covers the 1h window, the 24h boundary band, and beyond
	if got := countTestEvents(t, "event_time >= datetime('now','-1 hour')"); got != 5 {
		t.Fatalf("rows within 1h=%d, want 5", got)
	}
	if got := countTestEvents(t, "event_time BETWEEN datetime('now','-21 hours') AND datetime('now','-19 hours')"); got != 1 {
		t.Fatalf("rows near -20h=%d, want 1", got)
	}
	if got := countTestEvents(t, "event_time < datetime('now','-24 hours')"); got != 1 {
		t.Fatalf("rows beyond 24h=%d, want 1", got)
	}

	// And the source IP set includes the IPv4 samples and the IPv6 sample
	for _, ip := range []string{"198.51.100.10", "198.51.100.23", "198.51.100.45", "203.0.113.77", "2001:db8::15"} {
		if got := countTestEvents(t, "client_ip=?", ip); got == 0 {
			t.Fatalf("client_ip=%s missing from curated set", ip)
		}
	}

	// And rule_msg diversity covers comma-bearing, CJK, and empty messages
	if got := countTestEvents(t, "rule_msg LIKE '%,%'"); got < 1 {
		t.Fatalf("no comma-bearing rule_msg in curated set")
	}
	if got := countTestEvents(t, "rule_msg LIKE '%拦截%'"); got < 1 {
		t.Fatalf("no CJK rule_msg in curated set")
	}
	if got := countTestEvents(t, "rule_msg=''"); got < 1 {
		t.Fatalf("no empty rule_msg in curated set")
	}

	// And the generation is explicitly audited
	var action, resource string
	if err := db.AuditDB.QueryRow(`SELECT action, resource FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&action, &resource); err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if action != "生成" || resource != "测试事件" {
		t.Fatalf("audit action=%q resource=%q, want 生成/测试事件", action, resource)
	}
}

// ②清除：仅删标记行——非标记对照行存活；③重复生成允许累积，一次清除全净。
// ⑤清除操作落审计。
func TestDeleteSecurityTestEvents_removesOnlyMarkedRows(t *testing.T) {
	// Given a seeded non-marked control row and two generated batches
	setupSecurityPolicyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit database: %v", err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, client_ip, action)
		VALUES (datetime('now'), 'lb_real_rule', '192.0.2.1', 'blocked')`); err != nil {
		t.Fatalf("seed control row: %v", err)
	}
	c1, _ := newSecurityTestEventsContext(t, http.MethodPost)
	(&Handlers{}).CreateSecurityTestEvents(c1)
	c2, _ := newSecurityTestEventsContext(t, http.MethodPost)
	(&Handlers{}).CreateSecurityTestEvents(c2)

	// When the test events are cleared
	c3, rec := newSecurityTestEventsContext(t, http.MethodDelete)
	(&Handlers{}).DeleteSecurityTestEvents(c3)

	// Then every marked row is gone regardless of batch count
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Code int `json:"code"`
		Data struct {
			Deleted int `json:"deleted"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Code != 0 || body.Data.Deleted != 24 {
		t.Fatalf("code=%d deleted=%d, want code=0 deleted=24; body=%s", body.Code, body.Data.Deleted, rec.Body.String())
	}
	if got := countTestEvents(t, "1=1"); got != 0 {
		t.Fatalf("marked rows after clear=%d, want 0", got)
	}

	// And the non-marked control row survives
	var control int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE rule_caddy_id='lb_real_rule'`).Scan(&control); err != nil {
		t.Fatalf("count control row: %v", err)
	}
	if control != 1 {
		t.Fatalf("control rows=%d, want 1（清除仅删标记行）", control)
	}

	// And the cleanup is explicitly audited
	var action, resource string
	if err := db.AuditDB.QueryRow(`SELECT action, resource FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&action, &resource); err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if action != "清除" || resource != "测试事件" {
		t.Fatalf("audit action=%q resource=%q, want 清除/测试事件", action, resource)
	}
}

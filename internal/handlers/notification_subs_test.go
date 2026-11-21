package handlers

// 通知中心订阅/投递/设置 REST 钉测：真实 SQLite（db.Initialize 临时库）+
// 真实 handler 经 httptest 请求。覆盖：目录导出形状、订阅 UPSERT/回读/默认
// 态、投递列表属主过滤与跨属主脱敏、重发状态机（409/403/404）、设置角色门
// 与 secret 不回显、日报触发角色门与审计留痕。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// newNotificationTestRouter 直连通知 REST handler 的测试路由：身份三键
// （user_id/role/username）由桩中间件注入——认证链本身不在本文件钉测范围。
func newNotificationTestRouter(h *Handlers, uid int64, role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", uid)
		c.Set("role", role)
		c.Set("username", "tester")
		c.Next()
	})
	r.GET("/notification/catalog", h.ListNotificationCatalog)
	r.GET("/notification/subscriptions", h.ListNotificationSubscriptions)
	r.PUT("/notification/subscriptions", h.UpdateNotificationSubscriptions)
	r.GET("/notification/deliveries", h.ListNotificationDeliveries)
	r.POST("/notification/deliveries/:id/resend", h.ResendNotificationDelivery)
	r.GET("/notification/settings", h.GetNotificationSettings)
	r.PUT("/notification/settings", h.UpdateNotificationSettings)
	r.POST("/notification/daily/trigger", h.TriggerNotificationDaily)
	r.POST("/notification/settings/smtp-test", h.TestSMTPSettings)
	return r
}

// doNotifyRequest 发请求并解析 APIResponse 信封。
func doNotifyRequest(t *testing.T, r *gin.Engine, method, path, body string) (int, map[string]any) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %s %s: %v; body=%s", method, path, err, rec.Body.String())
	}
	return rec.Code, out
}

func notifySeedDelivery(t *testing.T, userID int64, status, body string) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, error, created_at)
		VALUES (?,?,?,?,?,?,0,'',datetime('now'))`,
		userID, "cert.failed", "critical", "证书签发失败", body, status)
	if err != nil {
		t.Fatalf("seed delivery: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

// notifySubRow 取订阅矩阵响应中指定 event_type 的行。
func notifySubRow(t *testing.T, data map[string]any, eventType string) map[string]any {
	t.Helper()
	subs, _ := data["subscriptions"].([]any)
	for _, raw := range subs {
		row, _ := raw.(map[string]any)
		if row["event_type"] == eventType {
			return row
		}
	}
	t.Fatalf("subscriptions 缺少 %s 行", eventType)
	return nil
}

func TestNotificationCatalog_exportPins(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newNotificationTestRouter(h, 1, "user")
	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/catalog", "")
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("status=%d body=%v", status, out)
	}
	events, _ := out["data"].(map[string]any)["events"].([]any)
	if len(events) < 30 {
		t.Fatalf("目录导出行数=%d, want ≥30（全量目录）", len(events))
	}
	want := map[string][4]any{
		// event_type: title, level, default_subscribed, group
		"auth.login_success":    {"登录成功", "info", false, "认证"},
		"cert.failed":           {"证书签发失败", "critical", true, "证书"},
		"sec.blocked_aggregate": {"拦截聚合", "info", true, "安全"},
		"cluster.node_joined":   {"集群节点加入", "info", false, "集群"},
		"notify.channel_down":   {"通知通道离线", "warn", true, "系统"},
	}
	for _, raw := range events {
		row, _ := raw.(map[string]any)
		if w, ok := want[row["id"].(string)]; ok {
			if row["title"] != w[0] || row["level"] != w[1] || row["default_subscribed"] != w[2] || row["group"] != w[3] {
				t.Errorf("%s 导出=%v/%v/%v/%v, want %v", row["id"], row["title"], row["level"], row["default_subscribed"], row["group"], w)
			}
			delete(want, row["id"].(string))
		}
	}
	for id := range want {
		t.Errorf("目录导出缺少 %s", id)
	}
}

func TestNotificationSubscriptions_upsertReadbackAndDefaults(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newNotificationTestRouter(h, 7, "user")

	// 初始态：目录全量行，cert.failed 未显式订阅（默认开）。
	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/subscriptions", "")
	if status != http.StatusOK {
		t.Fatalf("initial GET status=%d", status)
	}
	row := notifySubRow(t, out["data"].(map[string]any), "cert.failed")
	if row["subscribed"] != false || row["default_subscribed"] != true || row["min_level"] != "" {
		t.Fatalf("cert.failed 初始行=%v", row)
	}

	// PUT：UPSERT 两行 + 空级别（=停用；无行用户补建 opt-out 行）。
	body := `{"items":[{"event_type":"cert.failed","min_level":"warn"},{"event_type":"notify.channel_down","min_level":"info"},{"event_type":"auth.login_success","min_level":""}]}`
	if status, out = doNotifyRequest(t, r, http.MethodPut, "/notification/subscriptions", body); status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("PUT status=%d body=%v", status, out)
	}
	var minLevel string
	if err := db.DB.QueryRow(`SELECT min_level FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&minLevel); err != nil || minLevel != "warn" {
		t.Fatalf("cert.failed 落库 min_level=%q err=%v, want warn", minLevel, err)
	}
	if err := db.DB.QueryRow(`SELECT min_level FROM notification_subscriptions WHERE user_id=7 AND event_type='notify.channel_down'`).Scan(&minLevel); err != nil || minLevel != "info" {
		t.Fatalf("notify.channel_down 落库 min_level=%q err=%v, want info", minLevel, err)
	}
	// 空级别=停用：无行用户必须补建 opt-out 行（enabled=0, min_level 空串）。
	// 若只 UPDATE，0 行影响=静默无操作，目录默认订阅兜底会让「关闭」在投递
	// 侧失效（EVTCERT153-01）。
	var count, enabled int
	if err := db.DB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(enabled),-1) FROM notification_subscriptions WHERE user_id=7 AND event_type='auth.login_success'`).Scan(&count, &enabled); err != nil || count != 1 || enabled != 0 {
		t.Fatalf("空级别应补建停用行: count=%d enabled=%d err=%v, want 1/0", count, enabled, err)
	}
	if err := db.DB.QueryRow(`SELECT min_level FROM notification_subscriptions WHERE user_id=7 AND event_type='auth.login_success'`).Scan(&minLevel); err != nil || minLevel != "" {
		t.Fatalf("停用行 min_level=%q err=%v, want 空串", minLevel, err)
	}

	// 回读：显式行 subscribed=true；未订阅行保持默认态。
	_, out = doNotifyRequest(t, r, http.MethodGet, "/notification/subscriptions", "")
	data := out["data"].(map[string]any)
	row = notifySubRow(t, data, "cert.failed")
	if row["subscribed"] != true || row["min_level"] != "warn" {
		t.Fatalf("cert.failed 回读=%v, want subscribed/min_level=warn", row)
	}
	row = notifySubRow(t, data, "auth.login_success")
	if row["subscribed"] != false || row["enabled"] != false || row["disabled"] != true || row["default_subscribed"] != false {
		t.Fatalf("auth.login_success 回读=%v, want 停用 opt-out 行（不得回默认可投递态）", row)
	}

	// 二次 UPSERT 同事件=更新而非重复行。
	if status, _ = doNotifyRequest(t, r, http.MethodPut, "/notification/subscriptions", `{"items":[{"event_type":"cert.failed","min_level":"critical"}]}`); status != http.StatusOK {
		t.Fatalf("second PUT status=%d", status)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("UPSERT 重复行: count=%d err=%v", count, err)
	}
	if err := db.DB.QueryRow(`SELECT min_level FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&minLevel); err != nil || minLevel != "critical" {
		t.Fatalf("UPSERT 后 min_level=%q, want critical", minLevel)
	}

	// 非法事件/级别 fail-loud。
	status, out = doNotifyRequest(t, r, http.MethodPut, "/notification/subscriptions", `{"items":[{"event_type":"nope.nope","min_level":"warn"}]}`)
	if status != http.StatusBadRequest || out["message_key"] != "k_74125a73" {
		t.Fatalf("非法事件 status=%d body=%v", status, out)
	}
	status, out = doNotifyRequest(t, r, http.MethodPut, "/notification/subscriptions", `{"items":[{"event_type":"cert.failed","min_level":"urgent"}]}`)
	if status != http.StatusBadRequest || out["message_key"] != "k_3ae60346" {
		t.Fatalf("非法级别 status=%d body=%v", status, out)
	}
}

func TestNotificationSettings_roleGateAndSecretNonEcho(t *testing.T) {
	h := newBackupTestHandlers(t)

	// 非管理员：GET/PUT/触发全部 403（handler 级角色门，与 adminOnly 中间件双保险）。
	userRouter := newNotificationTestRouter(h, 2, "user")
	for _, tc := range []struct{ method, path, body, wantKey string }{
		{http.MethodGet, "/notification/settings", "", "k_20b2245c"},
		{http.MethodPut, "/notification/settings", `{"mcp_enabled":true}`, "k_20b2245c"},
		// 日报触发端点独立文案键（TriggerNotificationDaily）。
		{http.MethodPost, "/notification/daily/trigger", "", "k_4b8e3591"},
	} {
		status, out := doNotifyRequest(t, userRouter, tc.method, tc.path, tc.body)
		if status != http.StatusForbidden || out["message_key"] != tc.wantKey {
			t.Fatalf("%s %s 非管理员 status=%d body=%v, want 403 %s", tc.method, tc.path, status, out, tc.wantKey)
		}
	}

	adminRouter := newNotificationTestRouter(h, 1, "admin")
	body := `{"smtp":{"port":"465"},"mcp_enabled":true,"attack_warn_at":80}`
	status, out := doNotifyRequest(t, adminRouter, http.MethodPut, "/notification/settings", body)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("admin PUT status=%d body=%v", status, out)
	}
	status, out = doNotifyRequest(t, adminRouter, http.MethodGet, "/notification/settings", "")
	if status != http.StatusOK {
		t.Fatalf("admin GET status=%d", status)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "s3cret") {
		t.Fatalf("GET 响应泄漏 secret 明文: %s", raw)
	}
	data := out["data"].(map[string]any)
	smtp := data["smtp"].(map[string]any)
	if smtp["port"] != "465" || smtp["pass_configured"] != false {
		t.Fatalf("smtp 形状=%v", smtp)
	}
	// QQ/微信凭据不回显（单源=扫码绑定；bot 登录态经 bind-state 查询），
	// GET 契约只剩 smtp/mcp_enabled/阈值。
	if _, hasQQ := data["qq"]; hasQQ {
		t.Fatalf("GET 响应不应含 qq 段（凭据不回显）: %v", data)
	}
	if _, hasWx := data["wx_bot_cred_configured"]; hasWx {
		t.Fatalf("GET 响应不应含 wx_bot_cred_configured: %v", data)
	}
	if data["mcp_enabled"] != true || data["attack_warn_at"].(float64) != 80 || data["attack_critical_at"].(float64) != 200 {
		t.Fatalf("开关/阈值形状=%v", data)
	}

	// 部分更新：只动 host，其余键保持。
	if status, _ = doNotifyRequest(t, adminRouter, http.MethodPut, "/notification/settings", `{"smtp":{"host":"smtp.example.com"}}`); status != http.StatusOK {
		t.Fatalf("partial PUT status=%d", status)
	}
	_, out = doNotifyRequest(t, adminRouter, http.MethodGet, "/notification/settings", "")
	data = out["data"].(map[string]any)
	smtp = data["smtp"].(map[string]any)
	if smtp["host"] != "smtp.example.com" || smtp["port"] != "465" {
		t.Fatalf("partial PUT 后 smtp=%v", smtp)
	}
	// partial PUT 不携带 qq/wx 段（凭据不回显）：notify_settings 里的扫码
	// 凭据键不受影响（GET 也不外泄）。
	if _, err := db.DB.Exec(`INSERT INTO notify_settings (key, value) VALUES ('notify.qq_secret','scanned')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatal(err)
	}
	if _, out = doNotifyRequest(t, adminRouter, http.MethodGet, "/notification/settings", ""); strings.Contains(func() string { b, _ := json.Marshal(out); return string(b) }(), "scanned") {
		t.Fatalf("partial PUT 后 GET 泄漏扫码凭据值")
	}
	if data["mcp_enabled"] != true {
		t.Fatalf("partial PUT 后 mcp_enabled 保持 true")
	}

	// 非法形态 fail-loud：端口/阈值序/空更新。
	status, out = doNotifyRequest(t, adminRouter, http.MethodPut, "/notification/settings", `{"smtp":{"port":"abc"}}`)
	if status != http.StatusBadRequest || out["message_key"] != "k_d37587be" {
		t.Fatalf("非法端口 status=%d body=%v", status, out)
	}
	status, out = doNotifyRequest(t, adminRouter, http.MethodPut, "/notification/settings", `{"attack_warn_at":300,"attack_critical_at":100}`)
	if status != http.StatusBadRequest || out["message_key"] != "k_04f0eea4" {
		t.Fatalf("阈值倒挂 status=%d body=%v", status, out)
	}
	status, _ = doNotifyRequest(t, adminRouter, http.MethodPut, "/notification/settings", `{}`)
	if status != http.StatusBadRequest {
		t.Fatalf("空更新 status=%d, want 400", status)
	}
}

func TestNotificationDeliveries_scopeFilterResendAndMasking(t *testing.T) {
	h := newBackupTestHandlers(t)
	longBody := strings.Repeat("机", 300)
	ownFailed := notifySeedDelivery(t, 7, "failed", longBody)
	notifySeedDelivery(t, 7, "sent", "正常投递正文")
	otherFailed := notifySeedDelivery(t, 8, "failed", "他人投递正文")

	userRouter := newNotificationTestRouter(h, 7, "user")
	adminRouter := newNotificationTestRouter(h, 1, "admin")

	// 恒全量（用户裁定：投递记录不区分用户视角）：普通用户也见全部行，
	// 跨属主正文截断脱敏；用户维度经 username 呈现。
	status, out := doNotifyRequest(t, userRouter, http.MethodGet, "/notification/deliveries", "")
	if status != http.StatusOK {
		t.Fatalf("GET status=%d", status)
	}
	deliveries, _ := out["data"].(map[string]any)["deliveries"].([]any)
	if len(deliveries) != 3 {
		t.Fatalf("全量行数=%d, want 3", len(deliveries))
	}
	for _, raw := range deliveries {
		row, _ := raw.(map[string]any)
		if row["user_id"].(float64) == 8 {
			// 短正文原样（≤200 rune 不截断）；长正文截断脱敏由下方 admin 段钉住
			if b := row["body"].(string); len([]rune(b)) > 210 {
				t.Fatalf("跨属主行未截断: %q", b)
			}
		}
	}

	// 状态过滤与分页（page_size 契约：默认 50 上限 200，<1 → 400）。
	status, out = doNotifyRequest(t, userRouter, http.MethodGet, "/notification/deliveries?status=failed", "")
	deliveries, _ = out["data"].(map[string]any)["deliveries"].([]any)
	if len(deliveries) != 2 {
		t.Fatalf("status=failed 行数=%d, want 2（全量含他人 failed）", len(deliveries))
	}
	status, out = doNotifyRequest(t, userRouter, http.MethodGet, "/notification/deliveries?page_size=1", "")
	deliveries, _ = out["data"].(map[string]any)["deliveries"].([]any)
	if len(deliveries) != 1 {
		t.Fatalf("page_size=1 行数=%d, want 1", len(deliveries))
	}
	if total, _ := out["data"].(map[string]any)["total"].(float64); total != 3 {
		t.Fatalf("page_size=1 total=%v, want 3（total 不受分页影响）", out["data"].(map[string]any)["total"])
	}
	status, out = doNotifyRequest(t, userRouter, http.MethodGet, "/notification/deliveries?status=bogus", "")
	if status != http.StatusBadRequest || out["message_key"] != "k_0d569dd0" {
		t.Fatalf("非法 status 过滤 status=%d body=%v", status, out)
	}
	status, _ = doNotifyRequest(t, userRouter, http.MethodGet, "/notification/deliveries?page_size=0", "")
	if status != http.StatusBadRequest {
		t.Fatalf("page_size=0 status=%d, want 400", status)
	}

	// 管理员 ?all=1 全平台：他人行正文截断脱敏，user_id 保留。
	status, out = doNotifyRequest(t, adminRouter, http.MethodGet, "/notification/deliveries?all=1", "")
	if status != http.StatusOK {
		t.Fatalf("admin GET status=%d", status)
	}
	deliveries, _ = out["data"].(map[string]any)["deliveries"].([]any)
	if len(deliveries) != 3 {
		t.Fatalf("全平台行数=%d, want 3", len(deliveries))
	}
	for _, raw := range deliveries {
		row, _ := raw.(map[string]any)
		if row["user_id"].(float64) == 8 {
			if b := row["body"].(string); strings.Contains(b, "他人投递正文") == false || len([]rune(b)) > 210 {
				t.Fatalf("跨属主行未脱敏/未截断: %q", b)
			}
		}
	}

	// 管理员默认视图同样恒全量（投递记录不区分用户视角）。
	status, out = doNotifyRequest(t, adminRouter, http.MethodGet, "/notification/deliveries", "")
	deliveries, _ = out["data"].(map[string]any)["deliveries"].([]any)
	if len(deliveries) != 3 {
		t.Fatalf("管理员默认视图行数=%d, want 3（恒全量）", len(deliveries))
	}

	// 重发：failed → pending；重复重发 409。
	status, out = doNotifyRequest(t, userRouter, http.MethodPost, fmt.Sprintf("/notification/deliveries/%d/resend", ownFailed), "")
	if status != http.StatusOK || out["message_key"] != "k_07b47533" {
		t.Fatalf("resend status=%d body=%v", status, out)
	}
	var dbStatus string
	var attempts int
	if err := db.DB.QueryRow(`SELECT status, attempts FROM notification_deliveries WHERE id=?`, ownFailed).Scan(&dbStatus, &attempts); err != nil || dbStatus != "pending" || attempts != 0 {
		t.Fatalf("重发后 status=%q attempts=%d err=%v, want pending/0", dbStatus, attempts, err)
	}
	status, out = doNotifyRequest(t, userRouter, http.MethodPost, fmt.Sprintf("/notification/deliveries/%d/resend", ownFailed), "")
	if status != http.StatusConflict || out["message_key"] != "k_c16c1667" {
		t.Fatalf("重复重发 status=%d body=%v, want 409", status, out)
	}

	// 越权重发 403；不存在 404。
	status, out = doNotifyRequest(t, userRouter, http.MethodPost, fmt.Sprintf("/notification/deliveries/%d/resend", otherFailed), "")
	if status != http.StatusForbidden || out["message_key"] != "k_e18b003b" {
		t.Fatalf("越权重发 status=%d body=%v, want 403", status, out)
	}
	status, out = doNotifyRequest(t, adminRouter, http.MethodPost, "/notification/deliveries/99999/resend", "")
	if status != http.StatusNotFound || out["message_key"] != "k_e742ee3f" {
		t.Fatalf("不存在行 status=%d body=%v, want 404", status, out)
	}
}

func TestNotificationDailyReportTrigger_adminOnlyAndAudit(t *testing.T) {
	h := newBackupTestHandlers(t)
	userRouter := newNotificationTestRouter(h, 2, "user")
	adminRouter := newNotificationTestRouter(h, 1, "admin")

	status, out := doNotifyRequest(t, adminRouter, http.MethodPost, "/notification/daily/trigger", "")
	if status != http.StatusOK {
		t.Fatalf("admin 触发 status=%d body=%v", status, out)
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='触发' AND resource='通知日报'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("日报触发审计留痕 count=%d err=%v", count, err)
	}

	status, out = doNotifyRequest(t, userRouter, http.MethodPost, "/notification/daily/trigger", "")
	if status != http.StatusForbidden || out["message_key"] != "k_4b8e3591" {
		t.Fatalf("非管理员触发 status=%d body=%v, want 403 k_4b8e3591", status, out)
	}
}

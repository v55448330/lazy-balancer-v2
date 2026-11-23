package handlers

// （回归） 通知 REST 回归：跨属主投递 error 脱敏、通道 headers 脱敏、
// 组规则保存保留逐事件 min_level、阈值下限拒绝、日报默认目标可见。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

func newAudit156NotifyRouter(h *Handlers, uid int64, role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", uid)
		c.Set("role", role)
		c.Set("username", "tester")
		c.Next()
	})
	r.GET("/notification/channels", h.ListNotificationChannels)
	r.GET("/notification/deliveries", h.ListNotificationDeliveries)
	r.POST("/notification/rules/:id", h.UpdateNotificationRule)
	r.GET("/notification/daily/targets", h.GetDailyTargets)
	r.PUT("/notification/settings", h.UpdateNotificationSettings)
	return r
}

func TestNotificationDeliveriesMasksCrossOwnerErrors(t *testing.T) {
	h := newBackupTestHandlers(t)
	secret := "https://hooks.example.com/T0K3N-SECRET"
	res, err := db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, error, created_at)
		VALUES (8, 'cert.failed', 'critical', '证书签发失败', '正文', 'failed', 1, ?, datetime('now'))`, "webhook 请求失败: "+secret)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO notification_delivery_channels
		(delivery_id, user_id, channel_id, channel_name, channel_type, event_type, status, error, created_at)
		VALUES (?, 8, 1, '运维群', 'webhook', 'cert.failed', 'failed', ?, datetime('now'))`, id, "webhook 返回非 2xx status=500 body=远端响应 "+secret); err != nil {
		t.Fatal(err)
	}

	r := newAudit156NotifyRouter(h, 7, "user")
	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/deliveries", "")
	if status != http.StatusOK {
		t.Fatalf("GET status=%d", status)
	}
	rows := out["data"].(map[string]any)["deliveries"].([]any)
	if len(rows) != 1 {
		t.Fatalf("deliveries 行数=%d", len(rows))
	}
	row := rows[0].(map[string]any)
	if msg, _ := row["error"].(string); strings.Contains(msg, "T0K3N-SECRET") || msg == "" {
		t.Fatalf("跨属主 error 泄漏/为空: %q", msg)
	}
	chs := row["channels"].([]any)
	if len(chs) != 1 {
		t.Fatalf("channels 行数=%d", len(chs))
	}
	if msg, _ := chs[0].(map[string]any)["error"].(string); strings.Contains(msg, "T0K3N-SECRET") || msg == "" {
		t.Fatalf("跨属主通道 error 泄漏/为空: %q", msg)
	}

	// 属主本人仍可看到完整错误（排障面不回退）。
	own := newAudit156NotifyRouter(h, 8, "user")
	_, out = doNotifyRequest(t, own, http.MethodGet, "/notification/deliveries", "")
	row = out["data"].(map[string]any)["deliveries"].([]any)[0].(map[string]any)
	if msg, _ := row["error"].(string); !strings.Contains(msg, "T0K3N-SECRET") {
		t.Fatalf("属主 error 被误脱敏: %q", msg)
	}
}

func TestListNotificationChannelsMasksStyleHeadersForNonOwner(t *testing.T) {
	h := newBackupTestHandlers(t)
	const secret = "Bearer top-secret-token"
	style := `{"headers":{"Authorization":"` + secret + `","Content-Type":"application/json"}}`
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, style_config, enabled)
		VALUES (11, 8, 'webhook', '他人钩子', '{"url":"https://hooks.example.com/x"}', ?, 1)`, style); err != nil {
		t.Fatal(err)
	}

	r := newAudit156NotifyRouter(h, 1, "admin")
	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/channels", "")
	if status != http.StatusOK {
		t.Fatalf("GET status=%d", status)
	}
	rows := out["data"].(map[string]any)["channels"].([]any)
	if len(rows) != 1 {
		t.Fatalf("channels 行数=%d", len(rows))
	}
	raw, _ := rows[0].(map[string]any)["style_config"].(string)
	if strings.Contains(raw, secret) {
		t.Fatalf("非属主 style_config.headers 泄漏: %s", raw)
	}
	var parsed struct {
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("masked style_config 非法 JSON: %v (%s)", err, raw)
	}
	if parsed.Headers["Authorization"] != "***" {
		t.Fatalf("Authorization 掩码=%q，want ***", parsed.Headers["Authorization"])
	}
	if parsed.Headers["Content-Type"] != "application/json" {
		t.Fatalf("非敏感头不应被掩码: %+v", parsed.Headers)
	}

	// 属主自看保留原值。
	own := newAudit156NotifyRouter(h, 8, "user")
	_, out = doNotifyRequest(t, own, http.MethodGet, "/notification/channels", "")
	raw, _ = out["data"].(map[string]any)["channels"].([]any)[0].(map[string]any)["style_config"].(string)
	if !strings.Contains(raw, secret) {
		t.Fatalf("属主 style_config 被误掩码: %s", raw)
	}
}

func TestUpdateNotificationRuleGroupPreservesPerEventMinLevel(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newAudit156NotifyRouter(h, 7, "user")
	gid := certGroupID(t)
	group := strings.TrimPrefix(gid, "group:")
	var events []string
	for _, e := range notify.CatalogExport() {
		if e.Group == group {
			events = append(events, e.ID)
		}
	}
	if len(events) < 2 {
		t.Fatalf("证书组事件不足: %v", events)
	}
	for i, ev := range events[:2] {
		level := "info"
		if i == 1 {
			level = "critical"
		}
		if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, enabled)
			VALUES (7, ?, ?, 1)`, ev, level); err != nil {
			t.Fatal(err)
		}
	}

	status, out := doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid, `{"min_level":"warn"}`)
	if status != http.StatusOK {
		t.Fatalf("组保存 status=%d body=%v", status, out)
	}
	for i, ev := range events[:2] {
		want := "info"
		if i == 1 {
			want = "critical"
		}
		var got string
		if err := db.DB.QueryRow(`SELECT min_level FROM notification_subscriptions WHERE user_id=7 AND event_type=?`, ev).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("事件 %s 的逐事件 min_level 被组级 %q 覆盖：got %q want %q", ev, "warn", got, want)
		}
	}
}

func TestNotificationSettingsRejectsWarnBelowInfoThreshold(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newAudit156NotifyRouter(h, 1, "admin")
	status, out := doNotifyRequest(t, r, http.MethodPut, "/notification/settings",
		fmt.Sprintf(`{"attack_warn_at":%d,"attack_critical_at":20}`, notify.MinBlockedWarnAt-1))
	if status != http.StatusBadRequest {
		t.Fatalf("warn 低于 info 起点 status=%d body=%v，want 400", status, out)
	}
}

func TestGetDailyTargetsIncludesUsersWithoutConfigRow(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id, username, password_hash, role, is_enabled)
		VALUES (9, 'default-daily', 'x', 'user', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled)
		VALUES (21, 9, 'email', '默认日报邮件', '{"email":"u9@example.com"}', 1)`); err != nil {
		t.Fatal(err)
	}
	r := newAudit156NotifyRouter(h, 1, "admin")
	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/daily/targets", "")
	if status != http.StatusOK {
		t.Fatalf("GET targets status=%d body=%v", status, out)
	}
	raw, _ := json.Marshal(out["data"])
	if !strings.Contains(string(raw), "default-daily") {
		t.Fatalf("无 notification_daily 行（默认启用）的用户未出现在日报目标: %s", raw)
	}
}

package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// 规则级「事件×通道模板」保存门（与派发渲染同门）：webhook 模板必须是占位符
// 替换后可解析的 JSON 载荷——否则投递期接收端拿到非法 JSON；机器人/邮件模板
// 长度受限。校验失败 400（语义键）且不触碰任何订阅行。
func TestUpdateNotificationRule_ruleChannelTemplateSaveGate(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newNotificationChannelsRouter(h, 7, "user")
	r.POST("/notification/rules/:id", h.UpdateNotificationRule)
	catalog := notify.CatalogExport()
	path := "/notification/rules/group:" + catalog[0].Group

	hookID := seedScopeChannel(t, `{}`)
	res, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, style_config, enabled, created_at, updated_at)
		VALUES (7, 'qq', 'bot', '{"openid":"o1"}', '{}', 1, datetime('now'), datetime('now'))`)
	if err != nil {
		t.Fatalf("seed qq channel: %v", err)
	}
	qqID, _ := res.LastInsertId()
	hookKey, qqKey := strconv.FormatInt(hookID, 10), strconv.FormatInt(qqID, 10)
	subscriptions := func() map[string]string {
		t.Helper()
		var stored string
		if err := db.DB.QueryRow(`SELECT COALESCE(channel_templates,'') FROM notification_subscriptions WHERE user_id=7 AND event_type=?`, catalog[0].ID).Scan(&stored); err != nil {
			t.Fatalf("read subscription templates: %v", err)
		}
		out := map[string]string{}
		_ = json.Unmarshal([]byte(stored), &out)
		return out
	}

	// 目标形状：webhook 模板不是 JSON → 400，且这一组事件一行都不落。
	status, out := doNotifyRequest(t, r, http.MethodPost, path, `{"enabled":true,"channel_templates":{"`+hookKey+`":"probe-ev not json"}}`)
	if status != http.StatusBadRequest || out["message_key"] != "k_00c1f3e8" {
		t.Fatalf("webhook 非法模板 status=%d out=%v, want 400 k_00c1f3e8", status, out)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_subscriptions WHERE user_id=7`).Scan(&rows); err != nil {
		t.Fatalf("count subscriptions: %v", err)
	}
	if rows != 0 {
		t.Fatalf("校验失败不得落任何订阅行，got %d 行", rows)
	}

	// 畸形形状：机器人模板超长 → 400。
	status, out = doNotifyRequest(t, r, http.MethodPost, path, `{"enabled":true,"channel_templates":{"`+qqKey+`":"`+strings.Repeat("x", 2001)+`"}}`)
	if status != http.StatusBadRequest || out["message_key"] != "k_0d9a61a4" {
		t.Fatalf("机器人模板超长 status=%d out=%v, want 400 k_0d9a61a4", status, out)
	}

	// 畸形形状：通道键的非规范数字写法（前导零）与规范键指向同一通道——派发
	// 侧按数值解析键，保存门必须同样归一后校验，不得借写法绕过。无法解析的键
	// 在派发侧永不命中，不拦（见下方回归形状里的 "abc"）。
	status, out = doNotifyRequest(t, r, http.MethodPost, path, `{"enabled":true,"channel_templates":{"0`+hookKey+`":"probe-ev not json"}}`)
	if status != http.StatusBadRequest || out["message_key"] != "k_00c1f3e8" {
		t.Fatalf("前导零通道键必须同样过保存门 status=%d out=%v, want 400 k_00c1f3e8", status, out)
	}

	// 回归形状：合法 JSON（裸占位符与裹引号占位符皆可）放行并落库；已删除通道
	// 的历史键不阻止规则保存。
	const tpl = `{"ev": {{event}}, "title": "{{title}}"}`
	status, out = doNotifyRequest(t, r, http.MethodPost, path,
		`{"enabled":true,"channel_templates":{"`+hookKey+`":`+strconv.Quote(tpl)+`,"999999":"legacy","abc":"whatever"}}`)
	if status != http.StatusOK {
		t.Fatalf("合法模板 status=%d out=%v, want 200", status, out)
	}
	if got := subscriptions()[hookKey]; got != tpl {
		t.Fatalf("合法 webhook 模板必须原样落库: %q", got)
	}
}

package handlers

// 通知规则部分更新语义钉测（2026-11-19 重构）：POST /notification/rules/:id
// 缺省键=不动既有值。此前全量覆盖语义下「保存模板」会强制 enabled=true、
// 「调级别」会清空模板——用户可见的状态破坏。真实 SQLite + httptest。

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

func newRulesTestRouter(h *Handlers, uid int64, role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", uid)
		c.Set("role", role)
		c.Set("username", "tester")
		c.Next()
	})
	r.GET("/notification/rules", h.GetNotificationRules)
	r.POST("/notification/rules/:id", h.UpdateNotificationRule)
	r.GET("/notification/admin/overview", h.GetAdminNotificationOverview)
	return r
}

// certGroupID 从目录取「证书」组的规则 ID（group:证书）。
func certGroupID(t *testing.T) string {
	t.Helper()
	for _, e := range notify.CatalogExport() {
		if e.ID == "cert.failed" {
			return "group:" + e.Group
		}
	}
	t.Fatal("目录缺少 cert.failed")
	return ""
}

func TestUpdateNotificationRule_partialUpdatePreservesState(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newRulesTestRouter(h, 7, "user")
	gid := certGroupID(t)

	// 启用订阅（显式 enabled=true 建行）
	status, out := doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid, `{"enabled":true,"min_level":"warn"}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("启用订阅 status=%d body=%v", status, out)
	}

	// 只写模板：不得改动 min_level，不得要求 enabled 键
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid, `{"body_template":"{{title}} custom"}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("模板保存 status=%d body=%v", status, out)
	}
	var level, tpl string
	if err := db.DB.QueryRow(`SELECT min_level, body_template FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&level, &tpl); err != nil {
		t.Fatalf("回读订阅: %v", err)
	}
	if level != "warn" {
		t.Fatalf("模板保存后 min_level=%q, want warn（缺省键不得覆盖）", level)
	}
	if tpl != "{{title}} custom" {
		t.Fatalf("body_template=%q, want 模板落库", tpl)
	}

	// 只调级别：不得清空模板
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid, `{"min_level":"critical"}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("级别保存 status=%d body=%v", status, out)
	}
	if err := db.DB.QueryRow(`SELECT min_level, body_template FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&level, &tpl); err != nil {
		t.Fatalf("回读订阅: %v", err)
	}
	if level != "critical" || tpl != "{{title}} custom" {
		t.Fatalf("级别保存后 level=%q tpl=%q, want critical+模板保留", level, tpl)
	}

	// 显式停用=停用行（保留更新用户/时间；投递侧按 enabled=0 过滤）
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid, `{"enabled":false}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("停用 status=%d body=%v", status, out)
	}
	var n, en int
	_ = db.DB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(enabled),-1) FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&n, &en)
	if n != 1 || en != 0 {
		t.Fatalf("停用后行数=%d enabled=%d, want 1/0（保留行+停用）", n, en)
	}

	// 未订阅组只写模板：不得静默建行（无 enabled=true 不激活）
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid, `{"body_template":"x"}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("未订阅写模板 status=%d body=%v", status, out)
	}
	_ = db.DB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(enabled),-1) FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&n, &en)
	if n != 1 || en != 0 {
		t.Fatalf("停用后写模板行数=%d enabled=%d, want 1/0（不得静默启用）", n, en)
	}
}

func TestAdminNotificationOverview_userScopeAndTypeDist(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 两个用户各建通道（类型不同）
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, enabled) VALUES (7,'qq','u7','{"openid":"x"}',1),(8,'email','u8','{"email":"a@b.c"}',1),(8,'webhook','u8w','{"url":"https://x"}',0)`); err != nil {
		t.Fatalf("seed channels: %v", err)
	}
	r := newRulesTestRouter(h, 1, "admin")

	// 全平台：启用通道 2（qq+email），停用不计
	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/admin/overview", "")
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("overview status=%d body=%v", status, out)
	}
	data := out["data"].(map[string]any)
	stats := data["stats"].(map[string]any)
	if stats["channels"].(float64) != 2 {
		t.Fatalf("全平台 channels=%v, want 2（停用不计）", stats["channels"])
	}
	byType, _ := data["channel_by_type"].([]any)
	if len(byType) != 2 {
		t.Fatalf("channel_by_type 行数=%d, want 2", len(byType))
	}

	// user_id=8 收窄：仅该用户的启用通道（email×1）
	status, out = doNotifyRequest(t, r, http.MethodGet, "/notification/admin/overview?user_id=8", "")
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("scoped overview status=%d body=%v", status, out)
	}
	data = out["data"].(map[string]any)
	stats = data["stats"].(map[string]any)
	if stats["channels"].(float64) != 1 {
		t.Fatalf("user 8 channels=%v, want 1", stats["channels"])
	}
	byType, _ = data["channel_by_type"].([]any)
	if len(byType) != 1 || byType[0].(map[string]any)["type"] != "email" {
		t.Fatalf("user 8 channel_by_type=%v, want [email]", byType)
	}

	// 非管理员 403
	rUser := newRulesTestRouter(h, 7, "user")
	status, _ = doNotifyRequest(t, rUser, http.MethodGet, "/notification/admin/overview", "")
	if status != http.StatusForbidden {
		t.Fatalf("非管理员 overview status=%d, want 403", status)
	}
}

func TestUpdateNotificationRule_adminWriteOwnership(t *testing.T) {
	h := newBackupTestHandlers(t)
	gid := certGroupID(t)
	// 管理员（uid=1）在 user 7 视角保存：必须写 user 7，不得写管理员自己
	rAdmin := newRulesTestRouter(h, 1, "admin")
	status, out := doNotifyRequest(t, rAdmin, http.MethodPost, "/notification/rules/"+gid+"?user_id=7", `{"enabled":true,"channel_ids":[42]}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("代管保存 status=%d body=%v", status, out)
	}
	var ids string
	if err := db.DB.QueryRow(`SELECT channel_ids FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&ids); err != nil {
		t.Fatalf("user 7 订阅未落库: %v", err)
	}
	if ids != "[42]" {
		t.Fatalf("user 7 channel_ids=%q, want [42]", ids)
	}
	var adminRows int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_subscriptions WHERE user_id=1`).Scan(&adminRows)
	if adminRows != 0 {
		t.Fatalf("管理员名下订阅行数=%d, want 0（代管不得写自己）", adminRows)
	}
	// 非管理员带 user_id 参数：忽略，恒写本人
	rUser := newRulesTestRouter(h, 9, "user")
	status, out = doNotifyRequest(t, rUser, http.MethodPost, "/notification/rules/"+gid+"?user_id=7", `{"enabled":true}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("非管理员保存 status=%d body=%v", status, out)
	}
	var ownRows int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_subscriptions WHERE user_id=9 AND event_type='cert.failed'`).Scan(&ownRows)
	if ownRows != 1 {
		t.Fatalf("非管理员本人订阅行数=%d, want 1（user_id 参数不得越权）", ownRows)
	}
}

func TestGetNotificationRules_stableOrder(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newRulesTestRouter(h, 7, "user")
	var prev string
	for i := 0; i < 5; i++ {
		status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/rules", "")
		if status != http.StatusOK || out["code"].(float64) != 0 {
			t.Fatalf("rules status=%d body=%v", status, out)
		}
		data := out["data"].(map[string]any)
		raw := data["rules"].([]any)
		ids := make([]string, 0, len(raw))
		for _, it := range raw {
			ids = append(ids, it.(map[string]any)["id"].(string))
		}
		cur := strings.Join(ids, ",")
		if prev != "" && cur != prev {
			t.Fatalf("规则顺序不稳定：prev=%s cur=%s", prev, cur)
		}
		prev = cur
		if len(ids) == 0 || ids[len(ids)-1] != "daily" {
			t.Fatalf("日报必须末位：%v", ids)
		}
	}
}

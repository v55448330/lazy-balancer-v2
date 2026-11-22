package handlers

// 通道列表脱敏契约（管理员跨属主视角）：非属主行 target 保持脱敏，
// 并显式标记 target_masked=true——前端据此禁止把展示值回写 target
// （此前前端无法区分「真值」与「掩码串」，管理员保存即损坏目标）。

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func newNotificationChannelsRouter(h *Handlers, uid int64, role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", uid)
		c.Set("role", role)
		c.Set("username", "tester")
		c.Next()
	})
	r.GET("/notification/channels", h.ListNotificationChannels)
	return r
}

func channelByID(t *testing.T, out map[string]any, id float64) map[string]any {
	t.Helper()
	data, _ := out["data"].(map[string]any)
	channels, _ := data["channels"].([]any)
	for _, raw := range channels {
		row, _ := raw.(map[string]any)
		if row["id"] == id {
			return row
		}
	}
	t.Fatalf("通道 id=%v 未出现在列表 %v", id, channels)
	return nil
}

func TestListNotificationChannels_marksMaskedTargetsForNonOwner(t *testing.T) {
	h := newBackupTestHandlers(t)
	// id=1 属 user 7（管理员视角=非属主，必须脱敏）；id=2 属管理员 1（原值）。
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled) VALUES
		(1, 7, 'webhook', '运维群', '{"url":"https://hooks.example.com/secret-token"}', 1),
		(2, 1, 'webhook', '我的', '{"url":"https://mine.example.com/plain"}', 1)`); err != nil {
		t.Fatalf("seed channels: %v", err)
	}

	admin := newNotificationChannelsRouter(h, 1, "admin")
	status, out := doNotifyRequest(t, admin, http.MethodGet, "/notification/channels", "")
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("admin list status=%d body=%v", status, out)
	}
	other := channelByID(t, out, 1)
	if masked, _ := other["target_masked"].(bool); !masked {
		t.Fatalf("非属主通道 target_masked=%v, want true（%v）", other["target_masked"], other)
	}
	maskedTarget, _ := other["target"].(string)
	if maskedTarget == `{"url":"https://hooks.example.com/secret-token"}` {
		t.Fatalf("非属主 target 未脱敏: %q", maskedTarget)
	}
	if !strings.Contains(maskedTarget, "***") {
		t.Fatalf("非属主 target 不含掩码标记: %q", maskedTarget)
	}
	own := channelByID(t, out, 2)
	if masked, _ := own["target_masked"].(bool); masked {
		t.Fatalf("属主通道 target_masked=true, want false（%v）", own)
	}
	if own["target"] != `{"url":"https://mine.example.com/plain"}` {
		t.Fatalf("属主 target=%v, want 原值", own["target"])
	}

	// 属主自看：原值 + target_masked=false
	owner := newNotificationChannelsRouter(h, 7, "user")
	status, out = doNotifyRequest(t, owner, http.MethodGet, "/notification/channels", "")
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("owner list status=%d body=%v", status, out)
	}
	row := channelByID(t, out, 1)
	if row["target"] != `{"url":"https://hooks.example.com/secret-token"}` {
		t.Fatalf("属主列表 target=%v, want 原值", row["target"])
	}
	if masked, _ := row["target_masked"].(bool); masked {
		t.Fatalf("属主列表 target_masked=true, want false")
	}
}

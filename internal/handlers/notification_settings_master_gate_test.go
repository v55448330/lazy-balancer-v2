package handlers

import (
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// 全局 API / MCP 接入开关只对主节点有意义：从节点放行 = 面板显示「已关闭」，
// 真正生效的接入面在主节点，用户以为断开了全部接入却什么也没断。
// 入口必须与通知中心其它写端点共用 requireNotifyMaster。
func TestUpdateNotificationSettingsRejectsSlave(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	router := newNotificationSemanticsRouter(h, 1, "admin")
	router.PUT("/notification/settings", h.UpdateNotificationSettings)

	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("切换从节点角色失败: %v", err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`) })

	status, out := doNotifyRequest(t, router, http.MethodPut, "/notification/settings", `{"api_enabled":false}`)
	if status != http.StatusForbidden {
		t.Fatalf("从节点改全局接入开关 status=%d body=%v, want 403（假成功）", status, out)
	}
	if msg, _ := out["message"].(string); !strings.Contains(msg, "通知配置仅主节点生效") {
		t.Fatalf("从节点提示=%q, want 通知配置仅主节点生效（与同族端点同文案）", msg)
	}
	// 实体面：开关值不得落库（否则从节点页面真的显示「已关闭」）。
	if v := notify.GetSetting(notify.KeyAPIEnabled); v == "0" {
		t.Fatalf("从节点请求仍写入 %s=0（假成功的实体面）", notify.KeyAPIEnabled)
	}
}

package handlers

import (
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 手动触发全员日报与「规则测试/日报测试」同族：从节点不存在 pending 消费方
// （投递 Daemon 仅主节点运行），放行=API 200 假成功 + pending 行堆积、消息
// 永不投递。入口必须与两端点共用 requireNotifyMaster，不得只做到管理员门。
func TestTriggerNotificationDailyRejectsSlave(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	router := newNotificationSemanticsRouter(h, 1, "admin")
	router.POST("/notification/daily/trigger", h.TriggerNotificationDaily)

	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("切换从节点角色失败: %v", err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`) })

	status, out := doNotifyRequest(t, router, http.MethodPost, "/notification/daily/trigger", "")
	if status != http.StatusForbidden {
		t.Fatalf("从节点手动触发全员日报 status=%d body=%v, want 403（假成功）", status, out)
	}
	if msg, _ := out["message"].(string); !strings.Contains(msg, "通知配置仅主节点生效") {
		t.Fatalf("从节点提示=%q, want 通知配置仅主节点生效（与同族两端点同文案）", msg)
	}
	var deliveries int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries`).Scan(&deliveries); err != nil {
		t.Fatalf("统计投递行失败: %v", err)
	}
	if deliveries != 0 {
		t.Fatalf("从节点仍落 %d 条投递行（假成功的实体面）", deliveries)
	}
}

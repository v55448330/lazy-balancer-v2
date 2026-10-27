package services

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// sync_users 全链只读不写：读取侧恒归一为 true（系统数据恒同步），写它只会产生
// 一次「值未变」的 global_config UPDATE，而 cluster_version 触发器没有值变更守卫
// （WHEN 只比 cluster_version）→ 无谓 bump，全部从节点白拉一轮快照。
func TestClusterService_UpdateSettings_syncUsersIsNotWritten(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()
	var before int
	if err := database.QueryRow("SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&before); err != nil {
		t.Fatal(err)
	}
	syncUsers := true
	if err := service.UpdateSettings(ctx, models.ClusterSettingsRequest{SyncUsers: &syncUsers}); err != nil {
		t.Fatalf("提交 sync_users=true 不得失败: %v", err)
	}
	var after int
	if err := database.QueryRow("SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("cluster_version %d → %d：值未变的 sync_users 写不应 bump 版本", before, after)
	}
	// 反向：关闭仍被拒绝（哨兵错误），且不发生写入。
	disable := false
	if err := service.UpdateSettings(ctx, models.ClusterSettingsRequest{SyncUsers: &disable}); err == nil {
		t.Fatal("sync_users=false 必须被拒绝")
	}
}

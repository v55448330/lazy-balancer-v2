package services

// 集群 apply human_secret 缓存失效时序：reset 必须在 commit 成功后——
// 事务内 reset 会让 reset→commit 窗口的并发渲染读 db.DB 已提交旧密钥回填
// 缓存，commit 后强制重载消费投毒旧值→主从密钥分叉（用户反复被挑战）。
// 确定性编排：commitSnapshotTx 缝在真实 Commit 前暂停，并发 getHumanSecret
// 读旧值回填缓存（模拟后台渲染），放行 commit 后断言缓存已被失效（下次读新值）。

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestApplySnapshot_humanSecretCacheResetAfterCommit(t *testing.T) {
	cluster, database, syncService, bump := syncSemanticsEnv(t)
	resetHumanSecretCacheForTest(t)
	ctx := context.Background()

	var oldSecret string
	if err := database.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&oldSecret); err != nil {
		t.Fatalf("read old secret: %v", err)
	}
	// 主端改新密钥后取快照。
	newSecret := "cluster-new-secret-0123456789abcdef0123456789abcdef"
	if _, err := database.Exec(`UPDATE global_config SET is_master=1, human_secret=? WHERE id=1`, newSecret); err != nil {
		t.Fatalf("seed master new secret: %v", err)
	}
	bump(200)
	snap := snapshotAsMaster(t, cluster, database)
	if snap.BasicSettings.HumanSecret == nil || *snap.BasicSettings.HumanSecret != newSecret {
		t.Fatalf("快照必须携带新密钥: %+v", snap.BasicSettings.HumanSecret)
	}
	// 从端库回旧密钥（模拟主从分叉起点：从端本地仍是旧值）。
	if _, err := database.Exec(`UPDATE global_config SET human_secret=? WHERE id=1`, oldSecret); err != nil {
		t.Fatalf("restore slave old secret: %v", err)
	}

	commitPaused := make(chan struct{})
	commitRelease := make(chan struct{})
	syncService.commitSnapshotTx = func(tx *sql.Tx) error {
		close(commitPaused)
		<-commitRelease // 暂停在真实 Commit 前（事务内写已发生，未提交）
		return tx.Commit()
	}
	t.Cleanup(func() { syncService.commitSnapshotTx = nil })

	applyDone := make(chan error, 1)
	go func() { applyDone <- syncService.applySnapshot(ctx, snap) }()

	<-commitPaused
	// reset→commit 窗口：并发渲染读旧密钥回填缓存（事务未提交，db.DB 读旧值）。
	if got := getHumanSecret(); got != oldSecret {
		t.Fatalf("commit 前并发渲染应读旧密钥 %q, got %q", oldSecret, got)
	}
	close(commitRelease)
	select {
	case err := <-applyDone:
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("apply 超时")
	}

	// commit 后缓存必须已失效：下次渲染读新密钥（修复前事务内 reset 已被
	// 并发读回填旧值，commit 后重载消费旧值→分叉）。
	if got := getHumanSecret(); got != newSecret {
		t.Fatalf("commit 后缓存未失效（reset-in-tx 竞态）：渲染读 %q, want 新密钥 %q", got, newSecret)
	}
}

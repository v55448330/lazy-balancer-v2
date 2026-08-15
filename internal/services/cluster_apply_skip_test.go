package services

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 回归锁定：跳过的节（开关关闭或哈希一致）绝不能被 DELETE 清空——
// 从节点 users 被清空导致登录票据 user_unavailable 的根因。
func TestReplaceSnapshotTx_SkippedSectionsAreNotCleared(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	// 本地已有用户与规则
	if _, err := database.ExecContext(ctx,
		`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'local-admin','hash','admin',1);
		 INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_local','local','http',8080,1)`,
	); err != nil {
		t.Fatalf("seed local data: %v", err)
	}

	// 快照：规则节内容不同、users 节哈希一致（跳过）
	snapshot := models.ClusterSnapshot{
		Version: 9,
		Rules:   []models.LbRule{}, // 空 = 主节点无规则
	}
	snapshot.SectionHashes = map[string]string{"users": "u9", "rules": "r9"}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	// users 哈希一致 → skip；rules 应用（清空主节点已删的规则）
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{"users": true}}
	if err := replaceSnapshotTx(ctx, tx, snapshot, sk); err != nil {
		t.Fatalf("replaceSnapshotTx: %v", err)
	}

	var userCount, ruleCount int
	tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount)
	tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM lb_rules").Scan(&ruleCount)
	if userCount != 1 {
		t.Fatalf("skipped users section must keep local rows, got %d", userCount)
	}
	if ruleCount != 0 {
		t.Fatalf("applied rules section must mirror snapshot (empty), got %d", ruleCount)
	}
}

func TestReplaceSnapshotTx_DisabledSwitchKeepsLocalAndIgnoresSnapshot(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'local-admin','hash','admin',1)`,
	); err != nil {
		t.Fatalf("seed local user: %v", err)
	}

	// 快照携带不同用户，但开关关闭 → 本地保留
	snapshot := models.ClusterSnapshot{
		Version: 4,
		Users:   []models.ClusterUser{{ID: 7, Username: "master-user", PasswordHash: "h", Role: "admin", IsEnabled: true}},
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	sk := &sectionSkips{disabled: map[string]bool{"users": true}, unchanged: map[string]bool{}}
	if err := replaceSnapshotTx(ctx, tx, snapshot, sk); err != nil {
		t.Fatalf("replaceSnapshotTx: %v", err)
	}

	var username string
	if err := tx.QueryRowContext(ctx, "SELECT username FROM users WHERE id=1").Scan(&username); err != nil || username != "local-admin" {
		t.Fatalf("disabled users section must keep local-admin, got %q err=%v", username, err)
	}
	var count int
	tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	if count != 1 {
		t.Fatalf("snapshot user must not be inserted when switch off, got %d users", count)
	}
}

package services

// RegistrationStatus 与 ConfirmRegistration 的幂等契约对称：主节点首个真实
// 快照（Snapshot 旧协议交付确认）按设计消费 registration_secret，而从节点
// 在令牌落库前可能重复轮询状态——消费后状态轮询不得返回 401（否则从端
// 5 连败轨道清空注册态，需人工重新注册）。approved 且密钥哈希命中且已消费
// → 按 permanentClusterToken 重交付同一令牌。

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// plantStatusIdempotentNode 种一枚已审批节点，其 cluster_token_hash 与
// permanentClusterToken("status-secret") 同源（RegistrationStatus 交付口径）
// ——幂等重交付分支以该哈希复核交付事实，夹具必须自洽。secret 传空=已消费。
func plantStatusIdempotentNode(t *testing.T, database *sql.DB, secret string) int {
	t.Helper()
	var storedSecret any
	if secret != "" {
		storedSecret = tokenHash(secret)
	}
	if _, err := database.Exec(`INSERT INTO nodes (name,mode,ip_address,cluster_token_hash,registration_secret,registration_secret_expires_at,is_approved,status)
		VALUES ('s1','slave','10.0.0.2',?,?,datetime('now','+30 minutes'),1,'online')`,
		tokenHash(permanentClusterToken("status-secret")), storedSecret); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	var nodeID int
	if err := database.QueryRow(`SELECT id FROM nodes WHERE name='s1'`).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	return nodeID
}

// Given 节点已审批、注册密钥未消费。
// When 首个真实快照消费密钥后，从节点继续以原密钥轮询注册状态（含多轮重试）。
// Then 每轮均 approved 且重交付同一令牌——消费后 401 会驱动从端终止轨道
// 清空 cluster_token，本用例必红。
func TestRegistrationStatus_redeliversTokenAfterFirstSnapshotConsumption(t *testing.T) {
	service, database := newClusterTestService(t)
	nodeID := plantStatusIdempotentNode(t, database, "status-secret")
	now := time.Now()

	if _, applied, err := service.Snapshot(context.Background(), 0, "", permanentClusterToken("status-secret")); err != nil {
		t.Fatalf("首个快照: %v", err)
	} else if !applied {
		t.Fatal("首个快照必须真实下发（前置）")
	}
	assertNodeSecretColumnsNull(t, database)

	for round := 1; round <= 3; round++ {
		status, err := service.RegistrationStatus(context.Background(), nodeID, "status-secret", now)
		if err != nil {
			t.Fatalf("第 %d 轮状态轮询失败: %v（secret 已消费后必须幂等重交付，401 会驱动从端终止轨道）", round, err)
		}
		if status.Status != "approved" || status.ClusterToken != permanentClusterToken("status-secret") {
			t.Fatalf("第 %d 轮状态=%#v, want approved 且重交付同一令牌", round, status)
		}
	}
	// 重交付的令牌与首快照交付的哈希同源（鉴权面不回归）。
	var storedHash string
	if err := database.QueryRow(`SELECT COALESCE(cluster_token_hash,'') FROM nodes WHERE id=?`, nodeID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != tokenHash(permanentClusterToken("status-secret")) {
		t.Fatalf("重交付后令牌哈希=%q, want 与 permanentClusterToken 同源", storedHash)
	}
	assertNodeSecretColumnsNull(t, database)
}

// Given 节点 secret 已消费。
// When 以错误密钥轮询状态。
// Then 仍按凭证无效拒绝——幂等分支不得放行不匹配的密钥。
func TestRegistrationStatus_rejectsWrongSecretAfterConsumption(t *testing.T) {
	service, database := newClusterTestService(t)
	plantConfirmableNode(t, database, sql.NullString{})
	now := time.Now()
	var nodeID int
	if err := database.QueryRow(`SELECT id FROM nodes WHERE name='s1'`).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RegistrationStatus(context.Background(), nodeID, "wrong-secret", now); !errors.Is(err, ErrInvalidClusterAuth) {
		t.Fatalf("消费后错误密钥轮询 err=%v, want ErrInvalidClusterAuth", err)
	}
}

// Given 节点 secret 已消费，但本节点已降级为从节点。
// When 状态轮询走幂等分支。
// Then 必须返回 ErrNotMasterNode（403 语义）——幂等分支同样受角色谓词约束。
func TestRegistrationStatus_idempotentPathHonorsRoleGate(t *testing.T) {
	service, database := newClusterTestService(t)
	nodeID := plantStatusIdempotentNode(t, database, "")
	now := time.Now()
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
			t.Logf("restore is_master: %v", err)
		}
	})
	if _, err := service.RegistrationStatus(context.Background(), nodeID, "status-secret", now); !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("降级后幂等状态轮询 err=%v, want ErrNotMasterNode（不得绕过角色谓词）", err)
	}
}

// Given 节点未审批且 secret 已消费（带外残留形态）。
// When 状态轮询。
// Then 不得借幂等分支交付令牌（审批是令牌交付的前提）。
func TestRegistrationStatus_consumedButUnapprovedDoesNotDeliver(t *testing.T) {
	service, database := newClusterTestService(t)
	plantConfirmableNode(t, database, sql.NullString{})
	if _, err := database.Exec(`UPDATE nodes SET is_approved=0, status='pending' WHERE name='s1'`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var nodeID int
	if err := database.QueryRow(`SELECT id FROM nodes WHERE name='s1'`).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	status, err := service.RegistrationStatus(context.Background(), nodeID, "status-secret", now)
	if err != nil {
		t.Fatalf("未审批消费态轮询 err=%v, want nil（pending 语义）", err)
	}
	if status.Status != "pending" || status.ClusterToken != "" {
		t.Fatalf("未审批消费态状态=%#v, want pending 且不带令牌", status)
	}
}

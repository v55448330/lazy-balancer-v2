package services

// 主节点 `Snapshot()` 在真实下发首个 200
// 快照时按设计消费 `nodes.registration_secret`（cluster_snapshot.go 旧协议
// 交付确认），而从节点的 confirm 是「冗余确认 + 每周期重试」：一旦同轮 Pull
// 先成功、confirm 随后才到（或 confirm 曾瞬时失败），`ConfirmRegistration`
// 的 0 行命中就会被当成「凭证无效」→ 401 → 从端 5 连败轨道清空
// `cluster_token` → 永久脱同步、需人工重新注册（与 API 文档「重复确认可安全
// 重试」直接矛盾）。
//
// 契约（本次修复）：0 行分判两种语义——
//   - hash 命中且 `registration_secret IS NULL`（首个快照/前次确认已消费）
//     → 幂等成功，返回节点名（审计归因不变）；
//   - hash 不匹配（或已降级）→ 保持 ErrInvalidClusterAuth / ErrNotMasterNode。

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// plantConfirmableNode 种一枚已审批、注册密钥未被消费的从节点行。
func plantConfirmableNode(t *testing.T, database *sql.DB, secret sql.NullString) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO nodes (name,mode,ip_address,cluster_token_hash,registration_secret,registration_secret_expires_at,is_approved,status)
		VALUES ('s1','slave','10.0.0.2',?,?,datetime('now','+30 minutes'),1,'online')`,
		tokenHash("slave-token"), secret); err != nil {
		t.Fatalf("seed node: %v", err)
	}
}

func assertNodeSecretColumnsNull(t *testing.T, database *sql.DB) {
	t.Helper()
	var secret, expires sql.NullString
	if err := database.QueryRow(`SELECT registration_secret, registration_secret_expires_at FROM nodes WHERE name='s1'`).Scan(&secret, &expires); err != nil {
		t.Fatalf("read node secret columns: %v", err)
	}
	if secret.Valid || expires.Valid {
		t.Fatalf("registration_secret.Valid=%v expires_at.Valid=%v（值 %q/%q）, want 双列均 NULL",
			secret.Valid, expires.Valid, secret.String, expires.String)
	}
}

// Given 节点已被审批且注册密钥未消费。
// When 首个真实快照（携带集群令牌，按设计消费 secret）下发后，从节点继续
// confirm（含瞬时失败后的重试轨，共 5 轮）。
// Then 每轮 confirm 均幂等成功并返回节点名——确认语句一旦带上
// 「registration_secret IS NOT NULL」谓词，消费后每轮即 0 行 → 401，本用例必红。
func TestConfirmRegistration_firstSnapshotConsumptionKeepsConfirmIdempotent(t *testing.T) {
	service, database := newClusterTestService(t)
	plantConfirmableNode(t, database, sql.NullString{String: "pending-secret", Valid: true})

	if _, applied, err := service.Snapshot(context.Background(), 0, "", "slave-token"); err != nil {
		t.Fatalf("首个快照: %v", err)
	} else if !applied {
		t.Fatal("首个快照必须真实下发（前置）")
	}
	assertNodeSecretColumnsNull(t, database)

	for round := 1; round <= 5; round++ {
		name, err := service.ConfirmRegistration(context.Background(), "slave-token")
		if err != nil {
			t.Fatalf("第 %d 轮确认失败: %v（首个快照已消费 secret 后 confirm 必须幂等成功——401 会让从端 5 连败清空 cluster_token 永久脱同步）", round, err)
		}
		if name != "s1" {
			t.Fatalf("第 %d 轮确认返回节点名=%q, want s1（审计归因依赖该值）", round, name)
		}
	}
	assertNodeSecretColumnsNull(t, database)
}

// Given secret 已被消费但过期时间戳残留（旧版本清理缺失的带外形态）。
// When confirm 走幂等分支。
// Then 成功，且过期戳一并收敛为 NULL（与 Snapshot 旧协议交付确认同口径）。
func TestConfirmRegistration_convergesResidualExpiryOnIdempotentPath(t *testing.T) {
	service, database := newClusterTestService(t)
	plantConfirmableNode(t, database, sql.NullString{}) // secret 已空（Valid=false）
	if _, err := database.Exec(`UPDATE nodes SET registration_secret_expires_at=datetime('now','+10 minutes') WHERE name='s1'`); err != nil {
		t.Fatalf("seed residual expiry: %v", err)
	}

	name, err := service.ConfirmRegistration(context.Background(), "slave-token")
	if err != nil {
		t.Fatalf("secret 已消费形态的确认必须成功: %v", err)
	}
	if name != "s1" {
		t.Fatalf("确认返回节点名=%q, want s1", name)
	}
	assertNodeSecretColumnsNull(t, database)
}

// Given 主节点存在一枚 secret 已消费的节点。
// When 以未知令牌（hash 不匹配）确认。
// Then 仍按凭证无效拒绝——幂等分支不得放行不匹配的令牌。
func TestConfirmRegistration_rejectsUnknownTokenAfterConsumption(t *testing.T) {
	service, database := newClusterTestService(t)
	plantConfirmableNode(t, database, sql.NullString{})

	if _, err := service.ConfirmRegistration(context.Background(), "unknown-token"); !errors.Is(err, ErrInvalidClusterAuth) {
		t.Fatalf("未知令牌确认 err=%v, want ErrInvalidClusterAuth（幂等分支不得放行 hash 不匹配的令牌）", err)
	}
}

// Given 节点 secret 已消费，但本节点已降级为从节点。
// When confirm。
// Then 必须返回 ErrNotMasterNode（403 语义）——幂等分支同样受角色谓词约束。
func TestConfirmRegistration_idempotentPathHonorsRoleGate(t *testing.T) {
	service, database := newClusterTestService(t)
	plantConfirmableNode(t, database, sql.NullString{})
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("demote: %v", err)
	}
	t.Cleanup(func() {
		if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
			t.Logf("restore is_master: %v", err)
		}
	})

	if _, err := service.ConfirmRegistration(context.Background(), "slave-token"); !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("降级后确认 err=%v, want ErrNotMasterNode（幂等分支不得绕过角色谓词）", err)
	}
}

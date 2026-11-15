package services

// AuthenticateRegistrationSecret 是注册状态轮询端点的中间件认证门
// （registrationAuth 唯一消费方）。它必须与 RegistrationStatus 的幂等契约
// 对称：首个真实快照消费 registration_secret 后，从节点在令牌落库前重复
// 轮询仍携带原密钥——门若对已消费密钥返回 401，服务层幂等分支不可达，
// 从端 5 连败轨道清空注册态。已审批且已交付令牌哈希与 permanentClusterToken
// 同源 → 放行（权限面不扩大：令牌由 secret 确定性派生且已真实交付）。

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// seedRegistrationAuthNode 种一枚节点行（认证门只读 nodes 表）。
func seedRegistrationAuthNode(t *testing.T, database *sql.DB, secretHash, tokenHashVal string, approved int) {
	t.Helper()
	var secret any
	if secretHash != "" {
		secret = secretHash
	}
	var token any
	if tokenHashVal != "" {
		token = tokenHashVal
	}
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,is_approved,status,registration_secret,registration_secret_expires_at,cluster_token_hash)
		VALUES (7,'auth-node','10.0.0.7',?,'online',?,datetime('now','+24 hours'),?)`, approved, secret, token); err != nil {
		t.Fatalf("seed node: %v", err)
	}
}

// Given 节点已审批、首个快照已消费 registration_secret 并交付令牌。
// When 从节点以原密钥再次通过认证门（状态轮询前置）。
// Then 放行——已消费密钥不得在门层 401（否则服务层幂等分支不可达）。
func TestAuthenticateRegistrationSecret_consumedApprovedSecretPasses(t *testing.T) {
	_, database := newClusterTestService(t)
	const secret = "auth-status-secret"
	seedRegistrationAuthNode(t, database, "", tokenHash(permanentClusterToken(secret)), 1)
	// 消费即清到期戳（Snapshot 旧协议交付确认同口径）。
	if _, err := database.Exec(`UPDATE nodes SET registration_secret_expires_at=NULL WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	if err := AuthenticateRegistrationSecret(context.Background(), database, 7, secret); err != nil {
		t.Fatalf("已消费已审批密钥必须放行: %v（门层 401 会让服务层幂等分支不可达）", err)
	}
}

// Given 节点 secret 已消费但令牌哈希与 permanentClusterToken 不同源。
// When 以该密钥通过认证门。
// Then 拒绝——幂等放行不得扩大到未真实交付该令牌的形态。
func TestAuthenticateRegistrationSecret_consumedMismatchedTokenRejected(t *testing.T) {
	_, database := newClusterTestService(t)
	seedRegistrationAuthNode(t, database, "", tokenHash("some-other-token"), 1)
	if err := AuthenticateRegistrationSecret(context.Background(), database, 7, "auth-status-secret"); !errors.Is(err, ErrInvalidClusterAuth) {
		t.Fatalf("令牌哈希不同源 err=%v, want ErrInvalidClusterAuth", err)
	}
}

// Given 节点未审批且 secret 已消费（带外残留）。
// When 以原密钥通过认证门。
// Then 拒绝——审批是幂等放行的前提。
func TestAuthenticateRegistrationSecret_consumedUnapprovedRejected(t *testing.T) {
	_, database := newClusterTestService(t)
	const secret = "auth-status-secret"
	seedRegistrationAuthNode(t, database, "", tokenHash(permanentClusterToken(secret)), 0)
	if err := AuthenticateRegistrationSecret(context.Background(), database, 7, secret); !errors.Is(err, ErrInvalidClusterAuth) {
		t.Fatalf("未审批消费态 err=%v, want ErrInvalidClusterAuth", err)
	}
}

// Given 节点 secret 未消费（正常注册态）。
// When 错误密钥 / 空密钥通过认证门。
// Then 拒绝——未消费形态的认证语义不回归。
func TestAuthenticateRegistrationSecret_unconsumedWrongSecretRejected(t *testing.T) {
	_, database := newClusterTestService(t)
	const secret = "auth-status-secret"
	seedRegistrationAuthNode(t, database, tokenHash(secret), "", 0)
	if err := AuthenticateRegistrationSecret(context.Background(), database, 7, "wrong-secret"); !errors.Is(err, ErrInvalidClusterAuth) {
		t.Fatalf("未消费错误密钥 err=%v, want ErrInvalidClusterAuth", err)
	}
	if err := AuthenticateRegistrationSecret(context.Background(), database, 7, ""); !errors.Is(err, ErrInvalidClusterAuth) {
		t.Fatalf("空密钥 err=%v, want ErrInvalidClusterAuth", err)
	}
	// 正确密钥仍放行（基线）。
	if err := AuthenticateRegistrationSecret(context.Background(), database, 7, secret); err != nil {
		t.Fatalf("未消费正确密钥必须放行: %v", err)
	}
}

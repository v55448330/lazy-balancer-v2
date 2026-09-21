package services

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
)

func AuthenticateClusterToken(ctx context.Context, database *sql.DB, token string) (int, error) {
	if token == "" {
		return 0, ErrInvalidClusterAuth
	}
	var nodeID int
	if err := database.QueryRowContext(ctx, `SELECT id FROM nodes WHERE cluster_token_hash=? AND is_approved=1`, tokenHash(token)).Scan(&nodeID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrInvalidClusterAuth
		}
		return 0, fmt.Errorf("校验集群令牌: %w", err)
	}
	return nodeID, nil
}

func AuthenticateRegistrationSecret(ctx context.Context, database *sql.DB, nodeID int, secret string) error {
	if secret == "" {
		return ErrInvalidClusterAuth
	}
	// CL45-3(第 45 轮):哈希比对改常量时间——镜像 RegistrationStatus 的
	// CL41-5 形态(SQL 等值比对是提前退出的 memcmp,泄露哈希前缀匹配长度)。
	// 到期过滤依赖存储值与请求密钥无关,保留在 WHERE;仅密钥相关比较移出。
	var storedSecretHash string
	err := database.QueryRowContext(ctx, "SELECT COALESCE(registration_secret,'') FROM nodes WHERE id=? AND (registration_secret_expires_at IS NULL OR registration_secret_expires_at='' OR datetime(registration_secret_expires_at) > datetime('now'))", nodeID).Scan(&storedSecretHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidClusterAuth
	}
	if err != nil {
		return fmt.Errorf("校验注册凭证: %w", err)
	}
	if storedSecretHash == "" || subtle.ConstantTimeCompare([]byte(storedSecretHash), []byte(tokenHash(secret))) != 1 {
		return ErrInvalidClusterAuth
	}
	return nil
}

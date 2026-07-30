package services

import (
	"context"
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
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE id=? AND registration_secret=? AND (registration_secret_expires_at IS NULL OR registration_secret_expires_at='' OR datetime(registration_secret_expires_at) > datetime('now'))", nodeID, tokenHash(secret)).Scan(&count); err != nil {
		return fmt.Errorf("校验注册凭证: %w", err)
	}
	if count != 1 {
		return ErrInvalidClusterAuth
	}
	return nil
}

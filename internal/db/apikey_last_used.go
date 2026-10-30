package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
)

// apiKeyLastUsed 批量合并 api_keys.last_used 写：请求热路径只标脏
// （MarkAPIKeyUsed），落库由 apikey-usage-flusher daemon 的 RunTicker 节拍
// （60s）与 db.Close 尾检承担——引擎外的 1min 自建 flusher 循环已按
// task-engine 标准 v2.2 归口退役。
var apiKeyLastUsed = struct {
	sync.Mutex
	dirty map[int]struct{}
}{dirty: make(map[int]struct{})}

func MarkAPIKeyUsed(keyID int) {
	apiKeyLastUsed.Lock()
	apiKeyLastUsed.dirty[keyID] = struct{}{}
	apiKeyLastUsed.Unlock()
}

func FlushAPIKeyLastUsed() error {
	apiKeyLastUsed.Lock()
	if len(apiKeyLastUsed.dirty) == 0 {
		apiKeyLastUsed.Unlock()
		return nil
	}
	ids := make([]int, 0, len(apiKeyLastUsed.dirty))
	for id := range apiKeyLastUsed.dirty {
		ids = append(ids, id)
	}
	apiKeyLastUsed.dirty = make(map[int]struct{})
	apiKeyLastUsed.Unlock()

	database := GetDB()
	if database == nil {
		restoreDirtyAPIKeys(ids)
		return nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for index, id := range ids {
		placeholders[index] = "?"
		args[index] = id
	}
	if _, err := database.Exec("UPDATE api_keys SET last_used=datetime('now') WHERE id IN ("+strings.Join(placeholders, ",")+")", args...); err != nil {
		restoreDirtyAPIKeys(ids)
		return fmt.Errorf("flush API key last_used: %w", err)
	}
	return nil
}

func restoreDirtyAPIKeys(ids []int) {
	apiKeyLastUsed.Lock()
	defer apiKeyLastUsed.Unlock()
	for _, id := range ids {
		apiKeyLastUsed.dirty[id] = struct{}{}
	}
}

// CleanupExpiredRevokedJTI 删除已过期的吊销 JWT 记录（每小时清理 tick 的
// 单一实现）。导出供测试驱动真实 SQL——此前测试自写
// 一条等价 DELETE，清理语句/时间格式回归不会
// 被任何测试发现。
// 写入侧为 RFC3339 T 分隔（models.RevokedTokenTimeFormat），
// datetime('now') 产出空格分隔——TEXT 逐字符比较下当日过期行永不满足
// <=（'T' > ' '），延迟约 24h 才清理。strftime 对齐写入格式。
func CleanupExpiredRevokedJTI(database *sql.DB) error {
	_, err := database.Exec("DELETE FROM revoked_jti WHERE expires_at<=strftime('%Y-%m-%dT%H:%M:%SZ','now')")
	return err
}

// CleanupAPIKeyAuxTables 单轮清理附表过期数据（apikey-usage-flusher daemon
// 每小时节拍的工作体；loop 自建循环已移出 db 包——db 只暴露无状态工作体）：
// ①已过期吊销 JWT；②已过期集群注册密钥。
func CleanupAPIKeyAuxTables(ctx context.Context) error {
	database := GetDB()
	if database == nil {
		return nil
	}
	if err := CleanupExpiredRevokedJTI(database); err != nil {
		return fmt.Errorf("cleanup revoked JWT IDs: %w", err)
	}
	if err := cleanupExpiredRegistrationSecrets(ctx, database); err != nil {
		return err
	}
	return nil
}

// cleanupExpiredRegistrationSecrets 每小时清理过期注册密钥（句柄注入单源，
// 测试直驱真实 SQL）。nodes 是集群拓扑
// 簿记表，本写必须带 SQL 级主节点角色条件（MasterRoleConditionSQL，与
// services/middleware 同一单源）：flusher 主/从两角色都在跑，无条件时从端会
// 经此旁路写拓扑数据，破坏「从端零写」不变量。
func cleanupExpiredRegistrationSecrets(ctx context.Context, database *sql.DB) error {
	if _, err := database.ExecContext(ctx, `UPDATE nodes
		SET registration_secret=NULL, registration_secret_expires_at=NULL
		WHERE registration_secret IS NOT NULL
		  AND registration_secret_expires_at IS NOT NULL
		  AND registration_secret_expires_at<=datetime('now')
		  AND `+MasterRoleConditionSQL); err != nil {
		return fmt.Errorf("cleanup expired cluster registration secrets: %w", err)
	}
	return nil
}

package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
)

// ErrAPIKeyNotFound 表示明文 API Key 不存在、已禁用、所有者已禁用或已过期
// （统一按「认证失败」处理，不区分具体原因，避免枚举探测）。
var ErrAPIKeyNotFound = errors.New("API key not found or inactive")

// APIKeyIdentity 是 API Key 认证与 MCP 可见性判定的统一解析结果。
// middleware 认证查询与 mcpserver 只读可见性查询此前是
// 两份手写 SQL + 哈希逻辑（prefix 取 12 字节 + sha256 + 同一套有效性条件）；
// 认证条件一旦变更（新增撤销/作用域），可见性会静默漂移。收敛到本函数单源。
type APIKeyIdentity struct {
	ID             int
	Name           string
	UserID         int
	Username       string
	Role           string
	MCPEnabled     bool
	APIEnabled     bool
	ReadOnly       bool //  legacy 合并值（api_read_only AND mcp_read_only 的写侧同步列）
	APIReadOnly    bool
	MCPReadOnly    bool
	MCPIPWhitelist string
}

// IsAdmin 报告 Key 属主是否为管理员（决定 admin 组路由可达性与 MCP 工具可见性）。
func (k APIKeyIdentity) IsAdmin() bool { return k.Role == "admin" }

// ResolveAPIKeyIdentity 按明文解析有效 API Key：前缀（前 12 字节）与全文
// sha256 必须同时匹配复合索引；Key 与属主均启用且未过期。
func ResolveAPIKeyIdentity(database *sql.DB, plaintext string) (APIKeyIdentity, error) {
	var identity APIKeyIdentity
	if database == nil || len(plaintext) < 13 {
		return identity, ErrAPIKeyNotFound
	}
	hash := sha256.Sum256([]byte(plaintext))
	err := database.QueryRow(`
		SELECT k.id, k.name, u.id, u.username, u.role,
		       COALESCE(k.mcp_enabled,0), COALESCE(k.api_enabled,1), COALESCE(k.read_only,0),
		       COALESCE(k.api_read_only,0), COALESCE(k.mcp_read_only,0), COALESCE(k.mcp_ip_whitelist,'')
		FROM api_keys k
		JOIN users u ON u.id = k.created_by
		WHERE k.key_prefix = ? AND k.key_hash = ?
		  -- is_enabled 刻意用裸比较（NULL 行 fail-closed 拒绝）：写侧恒写值、
		  -- 备份/快照导入按缺省 1 归一，NULL 仅带外改库可达。改 COALESCE 放行
		  -- 会让历史 NULL 行静默获得鉴权；列表侧 COALESCE(is_enabled,1) 的
		  -- 「启用」显示是有意接受的排障口径差异。
		  AND k.is_enabled = 1
		  AND u.is_enabled = 1
		  AND (k.expires_at IS NULL OR datetime(k.expires_at) > datetime('now'))
	`, plaintext[:12], hex.EncodeToString(hash[:])).Scan(
		&identity.ID, &identity.Name, &identity.UserID, &identity.Username, &identity.Role,
		&identity.MCPEnabled, &identity.APIEnabled, &identity.ReadOnly,
		&identity.APIReadOnly, &identity.MCPReadOnly, &identity.MCPIPWhitelist)
	if errors.Is(err, sql.ErrNoRows) {
		return APIKeyIdentity{}, ErrAPIKeyNotFound
	}
	if err != nil {
		return APIKeyIdentity{}, err
	}
	return identity, nil
}

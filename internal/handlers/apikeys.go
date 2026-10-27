package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// requireAPIKeyStepUp 装配 API Key 特权授予的 step-up 决策与响应（创建/更新
// 两条路径共用单源）：开关读失败/状态查询失败一律 500 中断；已验证时回写
// X-Mfa-Verified-Seconds-Ago 供前端提示，未验证返回 428 + MFA_STEP_UP_REQUIRED。
// 返回 true 表示已写响应，调用方必须立即 return。
//
// 判定单源：与 mfaStepUpGuard 共用 DecideMFAStepUp——OIDC 会话短路、只读
// 语义豁免等条件只有一份，不再各自漂移；本层仅保留「特权授予」覆盖面语义
// 与 fail-closed 口径（守卫按裁定 fail-open）。
func requireAPIKeyStepUp(c *gin.Context) bool {
	decision, derr := DecideMFAStepUp(c, true, db.DB, services.MFAUserEnabled)
	if derr != nil {
		if errors.Is(derr, ErrMFAStepUpGuardUnreadable) {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 写操作验证开关读取失败"})
			return true
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 状态查询失败"})
		return true
	}
	if !decision.Applies {
		return false
	}
	if decision.Verified {
		c.Header("X-Mfa-Verified-Seconds-Ago", strconv.FormatInt(decision.SecondsAgo, 10))
		return false
	}
	c.JSON(http.StatusPreconditionRequired, gin.H{"code": 428, "message": "MFA_STEP_UP_REQUIRED", "detail": "此操作需要 MFA 验证"})
	return true
}

// apiKeyMaxPerUser 每用户 API Key 数量配额。
const apiKeyMaxPerUser = 50

// apiKeyWhitelistCachePurge 由 middleware 包注入（middleware 导入 handlers，
// 反向会成环——①）：删除/禁用 Key 时按 keyID 前缀清扫白名单 CIDR
// 解析缓存（条目永不再命中却永久驻留=无界累积）。nil=未装配（单测直连
// handlers 时静默跳过）。
var apiKeyWhitelistCachePurge func(keyID int)

// SetAPIKeyWhitelistCachePurge 装配缓存清扫钩子（middleware init 注册）。
func SetAPIKeyWhitelistCachePurge(purge func(keyID int)) {
	apiKeyWhitelistCachePurge = purge
}

func purgeAPIKeyWhitelistCache(keyID int) {
	if apiKeyWhitelistCachePurge != nil {
		apiKeyWhitelistCachePurge(keyID)
	}
}

// apiKeyWhitelistCachePurgeAll 由 middleware 包注入（同上的倒置装配）
// 配置备份导入整体替换 api_keys 表——键含 keyID 前缀无法枚举存活 Key，须全量
// 清空。nil=未装配（单测直连 handlers 时静默跳过）。
var apiKeyWhitelistCachePurgeAll func()

// SetAPIKeyWhitelistCachePurgeAll 装配全量清扫钩子（middleware init 注册）。
func SetAPIKeyWhitelistCachePurgeAll(purge func()) {
	apiKeyWhitelistCachePurgeAll = purge
}

func purgeAllAPIKeyWhitelistCache() {
	if apiKeyWhitelistCachePurgeAll != nil {
		apiKeyWhitelistCachePurgeAll()
	}
}

// apiKeyListColumns API Key 列表查询的列清单（单一事实源：两处
// handler 共用，新增列只改一处）。布尔列一律 COALESCE：带外写入/历史数据
// 的 NULL 扫进 bool 会整表 500。鉴权侧（db.ResolveAPIKeyIdentity）对
// mcp_enabled/read_only 同口径 COALESCE，但 is_enabled **刻意保持裸比较**
// （NULL 行鉴权 fail-closed 401）：此处列表按 COALESCE(is_enabled,1) 显示
// 「启用」与鉴权结果不一致是已知的有意取舍——不得把鉴权侧改成 COALESCE
// 放行 NULL 行，排障时以「列表显示启用但调用恒 401」记录该形态。
const apiKeyListColumns = `k.id, k.name, k.key_prefix, k.created_by, k.last_used, k.expires_at,
	COALESCE(k.is_enabled,1), COALESCE(k.mcp_enabled,0), COALESCE(k.read_only,0),
	COALESCE(k.mcp_ip_whitelist,''), k.created_at, u.username`

// queryAPIKeys 按可选 WHERE 片段查询 API Key 列表（扫描仍走 scanAPIKeys）。
func queryAPIKeys(where string, args ...any) (*sql.Rows, error) {
	return db.DB.Query(`SELECT `+apiKeyListColumns+`
		FROM api_keys k
		JOIN users u ON k.created_by = u.id `+where+`
		ORDER BY k.id`, args...)
}

func (h *Handlers) ListCurrentUserAPIKeys(c *gin.Context) {
	userID := int(contextUserID(c))
	// 与创建/更新/删除三入口同形的认证上下文门：缺身份时不得退化为
	// created_by=0 的孤儿行查询（会话异常的前端应重登而非拿 200 空列表）。
	if userID <= 0 {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "认证上下文缺失"})
		return
	}
	rows, err := queryAPIKeys("WHERE k.created_by = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	defer rows.Close()
	keys, err := scanAPIKeys(rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: keys})
}

// CreateCurrentUserAPIKey 是唯一的创建入口——管理端路由 POST /api-keys
// 直接复用本 handler（管理端无「指定属主」参数，属主恒为当前认证身份，
// 与自助语义一致）；此前两个逐字相同的 handler 已收敛。
func (h *Handlers) CreateCurrentUserAPIKey(c *gin.Context) {
	createAPIKeyForUser(c, int(contextUserID(c)))
}

func (h *Handlers) DeleteCurrentUserAPIKey(c *gin.Context) {
	userID := int(contextUserID(c))
	// scopedUserID==0 在 deleteAPIKey 中表示「全局删除」；自助入口缺少
	// 认证上下文时必须拒绝，不能退化成管理员级删除。
	if userID <= 0 {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "认证上下文缺失"})
		return
	}
	deleteAPIKey(c, userID)
}

func (h *Handlers) DeleteAPIKey(c *gin.Context) {
	deleteAPIKey(c, 0)
}

// deleteAPIKey 删除 API 密钥（DeleteAPIKey 与
// DeleteCurrentUserAPIKey 30+ 行逐字重复，仅作用域差异收敛为单实现）。
// scopedUserID>0 时限本人创建（WHERE created_by=?），0 时全局删除；其余
// （审计留痕、白名单缓存清扫、响应文案）两入口完全同源。
func deleteAPIKey(c *gin.Context, scopedUserID int) {
	// api_keys 在导入全量替代表清单内：窗口内写入会被静默覆盖或阻塞至
	// busy_timeout——与节点写族同口径 409 fast-fail，先于参数解析。
	if rejectWriteDuringImport(c, "执行 API 密钥写操作") {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ID 参数无效"})
		return
	}
	where := "id = ?"
	args := []any{id}
	if scopedUserID > 0 {
		where += " AND created_by = ?"
		args = append(args, scopedUserID)
	}
	var name string
	if err := db.DB.QueryRow("SELECT name FROM api_keys WHERE "+where, args...).Scan(&name); dbQueryNotFound(c, err, "API 密钥不存在", "deleteAPIKey query key") {
		return
	}
	result, err := db.DB.Exec("DELETE FROM api_keys WHERE "+where, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除 API 密钥失败"})
		return
	}
	rows, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "确认 API 密钥删除结果失败"})
		return
	}
	if rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "API 密钥不存在"})
		return
	}
	recordAudit(c, "删除", "API密钥", services.FormatAuditDetail(fmt.Sprintf("密钥 %d", id), name))
	purgeAPIKeyWhitelistCache(id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "API 密钥已删除"})
}

func scanAPIKeys(rows *sql.Rows) ([]models.APIKeyWithUserResponse, error) {
	var keys []models.APIKeyWithUserResponse
	for rows.Next() {
		var key models.APIKey
		var username string
		var whitelistJSON string
		if err := rows.Scan(&key.ID, &key.Name, &key.KeyPrefix, &key.CreatedBy, &key.LastUsed, &key.ExpiresAt, &key.IsEnabled, &key.MCPEnabled, &key.ReadOnly, &whitelistJSON, &key.CreatedAt, &username); err != nil {
			return nil, fmt.Errorf("scan API key: %w", err)
		}
		if whitelistJSON != "" {
			// 单行白名单损坏只降级该行（空数组=不限制来源），不再让整张
			// 列表 500——坏值来自带外写入/历史版本，用户仍需能看见并删除它。
			if err := json.Unmarshal([]byte(whitelistJSON), &key.MCPIPWhitelist); err != nil {
				services.Logf("warn", "API Key 白名单 JSON 解析失败（已按空列表展示）: key_id=%d: %v", key.ID, err)
				key.MCPIPWhitelist = nil
			}
		}
		if key.MCPIPWhitelist == nil {
			key.MCPIPWhitelist = []string{}
		}
		keys = append(keys, models.NewAPIKeyWithUserResponse(key, username))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate API keys: %w", err)
	}
	if keys == nil {
		keys = []models.APIKeyWithUserResponse{}
	}
	return keys, nil
}

func createAPIKeyForUser(c *gin.Context, userID int) {
	// userID<=0 表示认证上下文缺失——与删除路径同形守卫：不得写入
	// created_by=0 的孤儿 Key（配额按 0 计数，列表 JOIN users 隐藏它 →
	// 不可见但可用）。生产链 jwtAuth/apiKeyAuth 必写 user_id，此为防御门。
	if userID <= 0 {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "认证上下文缺失"})
		return
	}
	// 导入窗口 409，先于解析 body。
	if rejectWriteDuringImport(c, "执行 API 密钥写操作") {
		return
	}
	var req models.CreateAPIKeyRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// 名称 TrimSpace 后非空且 ≤100 字符——空白名/超长名
	// 此前直接落库(api_keys.name VARCHAR(100) 在 SQLite 不强制长度),列表与
	// 审计出现不可读名;修剪后落库。重名不拒绝(既有产品决策保持)。
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "名称不能为空"})
		return
	}
	if utf8.RuneCountInString(req.Name) > 100 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "名称过长(上限 100 字符)"})
		return
	}
	// 每用户配额 ≤50：此前无数量上限，普通用户可
	// 无界增长 api_keys 表（自伤型资源膨胀）。判定与插入的原子化见下方单语句
	// 条件插入。
	if c.GetString("role") != "admin" {
		req.ReadOnly = true
	}
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "过期时间不能早于当前时间"})
		return
	}
	// （2026-09 用户裁定）：特权 Key（非只读或 MCP）创建不验密码——API Key
	// 面向程序使用，创建/使用均不叠加交互确认；改密亦不吊销 Key（风险由后台
	// 禁用 Key/账户与只读 Key 承载）。可选防线是「写操作验证」（mfa_write_guard）：
	// 开启且创建者为启用 MFA 的 JWT 用户时，特权 Key 创建按 mfaStepUpGuard 同
	// 语义要求 60 秒内 MFA 验证（428 → 全局弹码 → 携新 JWT 重试）；API Key
	// 机器身份豁免（与路由级守卫一致），未启用 MFA 直通。
	// 判定与响应装配单源 requireAPIKeyStepUp（与更新侧共用）。
	if !req.ReadOnly || req.MCPEnabled {
		if requireAPIKeyStepUp(c) {
			return
		}
	}
	whitelist, err := services.NormalizeCIDRs(req.MCPIPWhitelist)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "MCP IP 白名单无效: " + err.Error()})
		return
	}
	whitelistJSON, err := encodeMCPIPWhitelist(whitelist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "序列化 MCP IP 白名单失败"})
		return
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成 API 密钥失败"})
		return
	}
	apiKey := "lb_sk_" + base64.URLEncoding.EncodeToString(keyBytes)[:32]
	hash := sha256.Sum256([]byte(apiKey))
	keyHash := hex.EncodeToString(hash[:])
	keyPrefix := apiKey[:12]

	// 配额判定与插入原子化——此前 count-then-insert
	// 两步在并发创建下 TOCTOU 越限（55 并发实测 55 全部越过 50 上限）。单语句
	// 条件插入：计数子查询与写入同语句，SQLite 语句级原子，无判定窗口；
	// WHERE 不满足时 0 行插入，按超限 400 拒绝。
	result, err := db.DB.ExecContext(c.Request.Context(), `
		INSERT INTO api_keys (name, key_hash, key_prefix, created_by, expires_at, mcp_enabled, read_only, mcp_ip_whitelist)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?
		WHERE (SELECT COUNT(*) FROM api_keys WHERE created_by = ?) < ?
	`, req.Name, keyHash, keyPrefix, userID, req.ExpiresAt, req.MCPEnabled, req.ReadOnly, whitelistJSON, userID, apiKeyMaxPerUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建 API 密钥失败"})
		return
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取创建结果失败"})
		return
	}
	if inserted == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("API Key 数量已达上限（每用户 %d 个），请先删除不再使用的密钥", apiKeyMaxPerUser)})
		return
	}
	id, err := result.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取新建 API 密钥 ID 失败"})
		return
	}
	expiry := "永不过期"
	if req.ExpiresAt != nil {
		expiry = req.ExpiresAt.Format("2006-01-02")
	}
	// 字段级留痕——只读/可写、MCP 开关、白名单条数此前
	// 不可见，「可写 + MCP 开启 + 白名单」的高权授予与只读 Key 审计文案相同。
	// 不落完整密钥（明文仅在创建响应出现一次）。
	recordAudit(c, "创建", "API密钥", services.FormatAuditDetail(
		fmt.Sprintf("密钥 %d", id),
		req.Name,
		fmt.Sprintf("过期：%s", expiry),
		"权限："+map[bool]string{true: "只读", false: "可写"}[req.ReadOnly],
		"MCP："+boolOnOff(req.MCPEnabled),
		fmt.Sprintf("IP 白名单（约束全部 REST 与 MCP）：%d 条", len(whitelist)),
	))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Data: gin.H{
		"id":      id,
		"key":     apiKey,
		"message": "完整密钥仅显示一次，请妥善保存。",
	}})
}

func (h *Handlers) ListAPIKeys(c *gin.Context) {
	rows, err := queryAPIKeys("")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	defer rows.Close()
	keys, err := scanAPIKeys(rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: keys})
}

func (h *Handlers) UpdateCurrentUserAPIKeyStatus(c *gin.Context) {
	updateAPIKeyStatus(c, true)
}

func (h *Handlers) UpdateAPIKeyStatus(c *gin.Context) {
	updateAPIKeyStatus(c, false)
}

func updateAPIKeyStatus(c *gin.Context, currentUserOnly bool) {
	// 导入窗口 409，先于参数解析。
	if rejectWriteDuringImport(c, "执行 API 密钥写操作") {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ID 参数无效"})
		return
	}
	userID := int(contextUserID(c))
	// 自助入口缺少认证上下文时必须拒绝——与删除/创建同形守卫：不得退化成
	// 按 created_by=0 查询后回答「不存在」的 404（客户端无法区分未认证与
	// 不存在，三入口契约须一致）。
	if currentUserOnly && userID <= 0 {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "认证上下文缺失"})
		return
	}
	var req models.UpdateAPIKeyRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if req.IsEnabled == nil && req.MCPEnabled == nil && req.ReadOnly == nil && req.MCPIPWhitelist == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "至少需要提交一个字段"})
		return
	}
	if currentUserOnly && c.GetString("role") != "admin" && req.ReadOnly != nil && !*req.ReadOnly {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "普通用户密钥必须为只读"})
		return
	}
	if currentUserOnly && c.GetString("role") != "admin" {
		readOnly := true
		req.ReadOnly = &readOnly
	}
	var whitelistJSON *string
	// 归一化后的白名单条目数（审计 delta 的「变更后条数」必须与库内落值
	// 同源：请求原值含重复/未压缩 CIDR，直接计数会虚报）。
	whitelistCount := 0
	if req.MCPIPWhitelist != nil {
		whitelist, err := services.NormalizeCIDRs(*req.MCPIPWhitelist)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "MCP IP 白名单无效: " + err.Error()})
			return
		}
		whitelistCount = len(whitelist)
		encoded, err := encodeMCPIPWhitelist(whitelist)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "序列化 MCP IP 白名单失败"})
			return
		}
		whitelistJSON = &encoded
	}
	// 审计 delta 需要变更前的键状态（启用态/MCP/只读/
	// 白名单），与更新同条件取行（currentUserOnly 时限定创建者）。
	// 启用态取裸列（非 COALESCE）：鉴权侧 db.ResolveAPIKeyIdentity 对
	// is_enabled 裸比较，NULL 恒 401 即运行期「未启用」；step-up 判据与审计
	// delta 必须同口径，否则带外 NULL 行被 NULL→1 真正激活时既不判
	// enablePrivileged 也不记变更（列表 COALESCE 显示「启用」为有意设计，
	// 属展示面，不参与本判定）。
	query := "SELECT name, is_enabled, COALESCE(mcp_enabled,0), COALESCE(read_only,0), COALESCE(mcp_ip_whitelist,'') FROM api_keys WHERE id = ?"
	args := []any{id}
	if currentUserOnly {
		query += " AND created_by = ?"
		args = append(args, userID)
	}
	var name string
	var beforeEnabledRaw sql.NullInt64
	var beforeMCPEnabled, beforeReadOnly int
	var beforeWhitelist string
	if err := db.DB.QueryRow(query, args...).Scan(&name, &beforeEnabledRaw, &beforeMCPEnabled, &beforeReadOnly, &beforeWhitelist); dbQueryNotFound(c, err, "API 密钥不存在", "updateAPIKeyStatus query key") {
		return
	}
	beforeEnabled := 0
	if beforeEnabledRaw.Valid && beforeEnabledRaw.Int64 != 0 {
		beforeEnabled = 1
	}
	// 特权变更（收回只读/开启 MCP/实际白名单变化）与创建侧同构走
	// requireAPIKeyStepUp（判定/响应单源）。此集合是「守卫开关读失败」场景下
	// 的纵深防御口径。白名单实际约束该 Key 的全部 REST 与 MCP 调用
	//（middleware 不看 mcp_enabled），字段名 mcp_ip_whitelist 为历史遗留。
	afterMCPEnabled := beforeMCPEnabled == 1
	if req.MCPEnabled != nil {
		afterMCPEnabled = *req.MCPEnabled
	}
	whitelistChanged := req.MCPIPWhitelist != nil && whitelistJSON != nil && *whitelistJSON != beforeWhitelist
	// 重新启用特权 Key（禁用→启用且启用后具备写/MCP 能力）与「收回只读」
	// 对称：启用=恢复可写/MCP 可达性，属授予动作。只读 Key 的启用不构成
	// 特权变更（仍不可写）。
	enablePrivileged := req.IsEnabled != nil && *req.IsEnabled && beforeEnabled != 1 &&
		(beforeReadOnly == 0 || afterMCPEnabled)
	privilegeEscalation := enablePrivileged ||
		(req.ReadOnly != nil && !*req.ReadOnly && beforeReadOnly == 1) ||
		(req.MCPEnabled != nil && *req.MCPEnabled && beforeMCPEnabled != 1) ||
		whitelistChanged
	if privilegeEscalation {
		if requireAPIKeyStepUp(c) {
			return
		}
	}
	setClauses := make([]string, 0, 4)
	updateArgs := make([]any, 0, 6)
	for _, field := range []struct {
		name  string
		value any
	}{{"is_enabled", req.IsEnabled}, {"mcp_enabled", req.MCPEnabled}, {"read_only", req.ReadOnly}, {"mcp_ip_whitelist", whitelistJSON}} {
		switch value := field.value.(type) {
		case *bool:
			if value != nil {
				setClauses = append(setClauses, field.name+" = ?")
				updateArgs = append(updateArgs, *value)
			}
		case *string:
			if value != nil {
				setClauses = append(setClauses, field.name+" = ?")
				updateArgs = append(updateArgs, *value)
			}
		}
	}
	update := "UPDATE api_keys SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
	updateArgs = append(updateArgs, id)
	if currentUserOnly {
		update += " AND created_by = ?"
		updateArgs = append(updateArgs, userID)
	}
	result, err := db.DB.Exec(update, updateArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新 API 密钥失败"})
		return
	}
	rows, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "确认 API 密钥更新结果失败"})
		return
	}
	if rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "API 密钥不存在"})
		return
	}
	// 更新审计记真 delta——启用态/MCP/只读/白名单是安全
	// 相关变更，此前四个字段零留痕（同族先例：安全策略）。
	auditDetail := services.FormatAuditDetail(fmt.Sprintf("密钥 %d", id), name)
	changes := make([]string, 0, 4)
	if req.IsEnabled != nil && *req.IsEnabled != (beforeEnabled == 1) {
		changes = append(changes, "启用状态："+boolOnOff(beforeEnabled == 1)+"→"+boolOnOff(*req.IsEnabled))
	}
	if req.MCPEnabled != nil && *req.MCPEnabled != (beforeMCPEnabled == 1) {
		changes = append(changes, "MCP："+boolOnOff(beforeMCPEnabled == 1)+"→"+boolOnOff(*req.MCPEnabled))
	}
	if req.ReadOnly != nil && *req.ReadOnly != (beforeReadOnly == 1) {
		changes = append(changes, "只读："+boolOnOff(beforeReadOnly == 1)+"→"+boolOnOff(*req.ReadOnly))
	}
	if req.MCPIPWhitelist != nil && whitelistJSON != nil {
		beforeCount := apiKeyWhitelistCount(beforeWhitelist)
		if beforeCount != whitelistCount || *whitelistJSON != beforeWhitelist {
			changes = append(changes, fmt.Sprintf("IP 白名单（约束全部 REST 与 MCP）：%d 条→%d 条", beforeCount, whitelistCount))
		}
	}
	if len(changes) > 0 {
		auditDetail = services.FormatAuditDetail(auditDetail, "变更："+strings.Join(changes, "、"))
	}
	recordAudit(c, "更新", "API密钥", auditDetail)
	// ①：禁用即清扫白名单解析缓存（条目随 Key 失活永不再命中）。
	// 在位编辑白名单也清扫——缓存键含白名单内容，旧键
	// 成为孤儿永不再命中（曾仅禁用/删除清扫）。
	if (req.IsEnabled != nil && !*req.IsEnabled) || req.MCPIPWhitelist != nil {
		purgeAPIKeyWhitelistCache(id)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "API 密钥已更新"})
}

// apiKeyWhitelistCount 统计库内 IP 白名单条目数（审计 delta 用；字段名
// mcp_ip_whitelist 为历史遗留，作用域是全部 REST 与 MCP 调用——注释与
// 审计文案必须同口径。损坏/空值按 0 计——只影响审计文案，不参与鉴权判定）。
func apiKeyWhitelistCount(raw string) int {
	if raw == "" {
		return 0
	}
	var items []string
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return 0
	}
	return len(items)
}

func encodeMCPIPWhitelist(whitelist []string) (string, error) {
	if len(whitelist) == 0 {
		return "", nil
	}
	data, err := json.Marshal(whitelist)
	if err != nil {
		return "", fmt.Errorf("marshal MCP IP whitelist: %w", err)
	}
	return string(data), nil
}

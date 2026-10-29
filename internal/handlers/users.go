package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) ListUsers(c *gin.Context) {
	rows, err := db.DB.Query("SELECT " + db.UserRowColumns("") + " FROM users ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	defer rows.Close()

	var users = make([]models.UserResponse, 0) // F-SYSR-1：空表出口归一 []，与 scanAPIKeys 同形（null 会使前端判空分裂）
	for rows.Next() {
		var meta db.UserRowMeta
		u, err := db.ScanUserRow(rows, &meta)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
			return
		}
		// mfa_enabled/is_setup_admin/auth_provider 均由单源扫描载入，
		// 构造器单点复制（删除手工补字段）。
		users = append(users, models.NewUserResponse(u, meta.MFAEnabled))
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: users})
}

func (h *Handlers) CreateUser(c *gin.Context) {
	// users 在导入全量替代表清单内：窗口内写入会被静默覆盖或阻塞至
	// busy_timeout——与节点写族同口径 409 fast-fail，先于解析 body。
	if rejectWriteDuringImport(c, "执行用户写操作") {
		return
	}
	var req models.CreateUserRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}

	if req.Role != "admin" && req.Role != "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "角色无效"})
		return
	}
	if err := validateUsernamePolicy(req.Username); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := validatePasswordPolicy(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "密码加密失败"})
		return
	}

	result, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, display_name, is_enabled) VALUES (?, ?, ?, ?, 1)",
		req.Username, string(hash), req.Role, req.DisplayName)
	if err != nil {
		if isUniqueConstraintError(err) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "用户名已存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建用户失败"})
		return
	}

	id, _ := result.LastInsertId()
	recordAudit(c, "创建", "用户", services.FormatAuditDetail(services.AuditUserPart(int(id), req.Username), fmt.Sprintf("角色：%s", req.Role)))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "用户创建成功", Data: gin.H{"id": id}})
}

// passwordResetColumns 改密时必须同步更新的列片段
// 密码哈希/变更时间/版本递增 + 登录失败计数与锁定清零。UpdateUser 的密码分支
// 与 ResetUserPassword 共用，防止两处再次分裂。
func passwordResetColumns() []string {
	return []string{
		"password_hash = ?",
		"password_changed_at = datetime('now')",
		"password_version = password_version + 1",
		"login_failed_attempts = 0",
		"login_locked_until = NULL",
	}
}

// revokeMFAChallenges 改密时吊销在册 MFA 登录挑战
// 三条改密路径（管理员更新/重置、自助改密）都必须在同一事务内调用——
// 版本绑定是主防线，删除保证旧挑战不以任何路径残留。
func revokeMFAChallenges(tx *sql.Tx, userID int) error {
	_, err := tx.Exec("DELETE FROM mfa_challenges WHERE user_id = ?", userID)
	return err
}

func (h *Handlers) UpdateUser(c *gin.Context) {
	// 导入窗口 409。
	if rejectWriteDuringImport(c, "执行用户写操作") {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	var req struct {
		Username    *string `json:"username" binding:"omitempty,min=3,max=50"`
		Password    *string `json:"password" binding:"omitempty"` // F-SYSR-3：长度交 validatePasswordPolicy（友好文案， 收口）——bcrypt 物理上限 72 由策略 24 上限先行拦截
		Role        *string `json:"role"`
		DisplayName *string `json:"display_name" binding:"omitempty,max=50"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}

	if req.Role != nil && *req.Role != "" && *req.Role != "admin" && *req.Role != "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "角色无效"})
		return
	}
	// break-glass 管理入口（初始化创建的首个管理员，按 is_setup_admin 标记
	// 判定）不可降级——与不可删除/禁用同语义，存在另一管理员时也不放行。
	protected, ok := setupAdminProtected(c, id)
	if !ok {
		return
	}
	if protected && req.Role != nil && *req.Role == "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "初始管理员不可降级"})
		return
	}
	// 2026-09-18 用户裁定:OIDC 用户显示名/密码源自 IdP,管理员亦不可改
	// (角色/启停是本地管理语义,不受限)。username 同为 IdP 源属性
	// (JIT 取 preferred_username),与显示名/密码同一裁定口径一并拦截。
	// 空 password 键在策略层语义为「不修改」
	// （validatePasswordPolicy 空值放行、passwordHash 仅非空生成）——携带
	// 空串不算改密尝试，不得触发 OIDC 门；非空仍拦截。
	// 门控按「值实际变化」而非「字段出现」判定——
	// 携带与库中同值的 display_name、空 username 属无变更的局部更新（写侧
	// 同样跳过，见下方 UPDATE 分支），不得整单 400。故门控前移到事务内读到
	// 旧值之后再判。
	passwordChangeRequested := req.Password != nil && *req.Password != ""
	if req.Password != nil {
		if err := validatePasswordPolicy(*req.Password); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "UpdateUser rollback failed for id=%d: %v", id, rollbackErr)
			}
		}
	}()

	var oldUsername, oldRole, oldDisplayName string
	var oldEnabled bool
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT username, role, COALESCE(display_name,''), is_enabled FROM users WHERE id = ?", id).Scan(&oldUsername, &oldRole, &oldDisplayName, &oldEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		}
		return
	}

	// OIDC 门（值变化判定，见上方）：username 空串/同值、display_name
	// 同值均为「不修改」（与下方 UPDATE 分支同一谓词），非空密码恒视为改密尝试。
	usernameChanged := req.Username != nil && *req.Username != "" && *req.Username != oldUsername
	displayNameChanged := req.DisplayName != nil && *req.DisplayName != oldDisplayName
	// 非管理员本人自助（用户管理页）只允许改显示名与重置密码；用户名/角色是
	// 管理语义，自助路径一律拒绝（防提权/身份漂移）。管理员不受此门限制。
	// 判据必须与守卫链同口径「非管理员 = role != 'admin'」：users.role 无
	// CHECK 约束，遗留/带外数据可产生 admin/user 之外的取值（旧备份、直接改
	// 库）。此前用 == "user" 判定，脏角色值会同时绕过只读门的 admin 分支与
	// 本自助锁，把 role 改成 admin 提权。
	if c.GetString("role") != "admin" {
		if usernameChanged {
			c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "非管理员不能修改用户名"})
			return
		}
		if req.Role != nil && *req.Role != "" && *req.Role != oldRole {
			c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "非管理员不能修改角色"})
			return
		}
	}
	if usernameChanged || displayNameChanged || passwordChangeRequested {
		oidcUser, err := isOIDCUser(c.Request.Context(), id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户身份失败"})
			return
		}
		if oidcUser {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "OIDC 用户的用户名、显示名与密码由认证服务管理，请前往 OIDC 服务修改"})
			return
		}
	}
	var passwordHash string
	if passwordChangeRequested {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "密码加密失败"})
			return
		}
		passwordHash = string(hash)
	}

	changed := []string{}
	sets := make([]string, 0, 5)
	args := make([]any, 0, 5)
	if usernameChanged {
		if err := validateUsernamePolicy(*req.Username); err != nil { // 改名须过策略（创建/注册已查、更新曾漏）
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		sets = append(sets, "username = ?")
		args = append(args, *req.Username)
		// 审计记旧→新(角色降权等高敏变更可取证重建;密码只记名)。
		changed = append(changed, "用户名："+oldUsername+"→"+*req.Username)
	}
	if req.Role != nil && *req.Role != "" && *req.Role != oldRole {
		sets = append(sets, "role = ?")
		args = append(args, *req.Role)
		changed = append(changed, "角色："+oldRole+"→"+*req.Role)
	}
	if displayNameChanged {
		sets = append(sets, "display_name = ?")
		args = append(args, *req.DisplayName)
		changed = append(changed, "昵称："+oldDisplayName+"→"+*req.DisplayName)
	}
	if passwordHash != "" {
		// 改密同时清空登录锁定（与 ResetUserPassword 共用同一列片段）
		// ——否则锁定态用户改密后仍被 auth.go 的锁判定拒绝。
		sets = append(sets, passwordResetColumns()...)
		args = append(args, passwordHash)
		changed = append(changed, "密码")
	}
	if len(sets) > 0 {
		args = append(args, id)
		query := "UPDATE users SET " + strings.Join(sets, ", ") + " WHERE id = ?"
		if oldEnabled && oldRole == "admin" && req.Role != nil && *req.Role == "user" {
			query += " AND EXISTS (SELECT 1 FROM users WHERE id <> ? AND role = 'admin' AND is_enabled = 1)"
			args = append(args, id)
		}
		result, err := tx.ExecContext(c.Request.Context(), query, args...)
		if err != nil {
			if isUniqueConstraintError(err) {
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "用户名已存在"})
				return
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
			return
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
			return
		}
		if rowsAffected == 0 {
			// 0 行按 COUNT 分判（镜像 ToggleUserStatus
			// 先例）——行已消失（并发删除）→ 404；行仍在=末管理员 EXISTS 门
			// 拦截 → 409。此前一律 409 会把并发删除误报成管理员锁。
			var exists int
			if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM users WHERE id = ?", id).Scan(&exists); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
			} else if exists == 0 {
				c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
			} else {
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "不能移除最后一个已启用管理员"})
			}
			return
		}
	}
	var meta db.UserRowMeta
	// 改密成功后在提交前吊销在册 MFA 挑战。
	if passwordHash != "" {
		if err := revokeMFAChallenges(tx, id); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
			return
		}
	}
	// 响应必须回填与 GET /users 同口径（单源列清单：mfa_enabled 与
	// is_setup_admin 一并载入）——此前该端点响应恒 mfa_enabled=false，
	// is_setup_admin 同样恒 false，API 消费者/脚本误判。
	user, err := db.ScanUserRow(tx.QueryRowContext(c.Request.Context(), `SELECT `+db.UserRowColumns("")+` FROM users WHERE id=?`, id), &meta)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
		return
	}
	committed = true

	if len(changed) == 0 {
		recordAudit(c, "更新", "用户", services.FormatAuditDetail(services.AuditUserPart(id, user.Username), "无修改"))
	} else {
		recordAudit(c, "更新", "用户", services.FormatAuditDetail(services.AuditUserPart(id, user.Username), fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	}
	response := models.NewUserResponse(user, meta.MFAEnabled)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "用户更新成功", Data: response})
}

// authProviderOf 读取用户身份来源（单源：isOIDCUser 与
// rejectOIDCUserMFAOperation 共用同一查询与归一化，调用方只保留各自的
// 错误→响应映射）。返回原始错误（含 sql.ErrNoRows），归一化口径与 users
// 列默认值一致（空→'local'）。
func authProviderOf(ctx context.Context, userID int) (string, error) {
	var provider string
	err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(auth_provider,'local') FROM users WHERE id=?", userID).Scan(&provider)
	return provider, err
}

// isOIDCUser 判定用户是否 OIDC 来源（读失败与「非 OIDC」分判——
// 身份来源不可判定时调用方必须拒绝写操作,不得静默放行;ErrNoRows 除外:
// 用户不存在是调用方可判定的已知条件,交由后续 0 行 UPDATE → 404)。
func isOIDCUser(ctx context.Context, userID int) (bool, error) {
	provider, err := authProviderOf(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 用户不存在是调用方可判定的已知条件(后续 UPDATE 0 行 → 404),
			// 不属于「身份来源不可判定」的基础设施故障。
			return false, nil
		}
		return false, err
	}
	return provider == "oidc", nil
}

// setupAdminProtected 判定目标用户是否为受保护的 break-glass 管理入口
// （初始化创建的首个管理员，按 users.is_setup_admin 标记判定；标记缺失的
// 旧库回落到 db.SetupAdminFallbackUserID）。读库失败必须 500 fail-closed——
// 无法判定保护目标时不得放行删除/禁用/降级。
func setupAdminProtected(c *gin.Context, id int) (protected bool, ok bool) {
	protected, err := db.IsSetupAdmin(c.Request.Context(), db.DB, id)
	if err != nil {
		services.Logf("error", "读取 setup 管理员标记失败: user_id=%d: %v", id, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户保护状态失败"})
		return false, false
	}
	return protected, true
}

func (h *Handlers) DeleteUser(c *gin.Context) {
	// 导入窗口 409。
	if rejectWriteDuringImport(c, "执行用户写操作") {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	// 复用 contextUserID(消除三连手写)。
	userIDInt := int(contextUserID(c))

	if userIDInt == id {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "不能删除当前登录用户"})
		return
	}

	// break-glass 管理入口（setup 创建的首个用户）不可删除——存在另一
	// 管理员时也不放行（2026-09-18 裁定：提权后的 OIDC 管理员同样不可动）。
	protected, ok := setupAdminProtected(c, id)
	if !ok {
		return
	}
	if protected {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "初始管理员不可删除"})
		return
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			services.Logf("error", "DeleteUser rollback failed for id=%d: %v", id, err)
		}
	}()

	var targetUsername, targetRole, targetProvider string
	var targetEnabled bool
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT username, role, is_enabled, COALESCE(auth_provider,'local') FROM users WHERE id = ?", id).Scan(&targetUsername, &targetRole, &targetEnabled, &targetProvider); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		}
		return
	}
	if targetRole == "admin" && targetEnabled {
		var otherAdmins int
		if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM users WHERE id <> ? AND role = 'admin' AND is_enabled = 1", id).Scan(&otherAdmins); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
			return
		}
		if otherAdmins == 0 {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "不能删除最后一个已启用管理员"})
			return
		}
	}
	// ①：连带删除的 Key 同样按 keyID 前缀清扫白名单解析缓存——
	// 先取 id 集（删除后无从按键清扫），删除成功后逐键清扫。
	var cascadeKeyIDs []int
	keyRows, keyErr := tx.QueryContext(c.Request.Context(), "SELECT id FROM api_keys WHERE created_by = ?", id)
	if keyErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}
	for keyRows.Next() {
		var keyID int
		if err := keyRows.Scan(&keyID); err != nil {
			keyRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
			return
		}
		cascadeKeyIDs = append(cascadeKeyIDs, keyID)
	}
	// 级联 Key 清单迭代失败须留痕——cascadeKeyIDs 缺项
	// 意味着对应 Key 的白名单解析缓存不被清扫（孤儿缓存驻留，无越权面；
	// 删除照常——warn-only 口径）。
	if err := keyRows.Err(); err != nil {
		services.Logf("warn", "删除用户 %d：级联 Key 清单读取迭代失败（部分 Key 白名单缓存可能未清扫）: %v", id, err)
	}
	keyRows.Close()
	if _, err := tx.ExecContext(c.Request.Context(), "DELETE FROM api_keys WHERE created_by = ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}
	// 连带清理该用户的 MFA 登录挑战——无越权面（消费端按 token+user_id 判定
	// 且登录第二步 JOIN users），但簿记残留不应依赖 MFAIssueChallenge 的
	// 惰性过期清理（过期才删；未过期行会残留至到期）。
	if _, err := tx.ExecContext(c.Request.Context(), "DELETE FROM mfa_challenges WHERE user_id = ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}
	for _, keyID := range cascadeKeyIDs {
		purgeAPIKeyWhitelistCache(keyID)
	}
	result, err := tx.ExecContext(c.Request.Context(), "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}
	// 用户删除后其登录后验码限流条目（进程内内存态）不再可被访问，顺带清除
	// 避免条目随一次性用户数量无界驻留（另有阈值清扫兜底）。
	services.MFAClearVerifyAttempts(id)

	recordAudit(c, "删除", "用户", services.AuditUserPart(id, targetUsername))
	message := "用户删除成功"
	if targetProvider == "oidc" {
		message = "OIDC 用户已删除；同一身份下次 SSO 登录会重新开户（默认普通用户，原角色与禁用状态不继承）。如需撤销访问并保留原身份，请改用禁用。"
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message})
}

func (h *Handlers) ToggleUserStatus(c *gin.Context) {
	// 导入窗口 409。
	if rejectWriteDuringImport(c, "执行用户写操作") {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	// *bool——缺省/拼错字段不得被零值当成「禁用」。{
	// 请求体 {} 此前绑定成功且 IsEnabled=false，直接把用户静默停用。
	var req struct {
		IsEnabled *bool `json:"is_enabled"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if req.IsEnabled == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "缺少 is_enabled 字段"})
		return
	}
	enable := *req.IsEnabled

	// 自禁用防护——禁用自己=当前会话立即
	// 失效,与 DeleteUser 自保护不对称。UI 已挡/API 未挡。
	if !enable {
		if userIDInt := int(contextUserID(c)); userIDInt == id {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "不能禁用当前登录用户"})
			return
		}
	}

	// break-glass 管理入口不可禁用（同 DeleteUser 保护）
	if !enable {
		protected, ok := setupAdminProtected(c, id)
		if !ok {
			return
		}
		if protected {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "初始管理员不可禁用"})
			return
		}
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		return
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			services.Logf("error", "ToggleUserStatus rollback failed for id=%d: %v", id, err)
		}
	}()
	var statusUsername, statusProvider string
	var wasEnabled bool
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT username, is_enabled, COALESCE(auth_provider,'local') FROM users WHERE id = ?", id).Scan(&statusUsername, &wasEnabled, &statusProvider); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		}
		return
	}
	statusChanged := wasEnabled != enable
	versionBump := ""
	if statusChanged {
		versionBump = ", password_version = password_version + 1"
	}
	var query string
	var args []any
	if enable {
		// 启用即「恢复该账号」：沿用改密语义的解锁片段（passwordResetColumns
		// 同款）——锁定中/失败计数残留会让管理员刚启用的账号继续 429，且错误
		// 文案会让人以为账号仍被禁用，恢复意图被 10 分钟锁定打断。
		query = "UPDATE users SET is_enabled = 1, login_failed_attempts = 0, login_locked_until = NULL" + versionBump + " WHERE id = ?"
		args = []any{id}
	} else {
		query = "UPDATE users SET is_enabled = 0" + versionBump + " WHERE id = ? AND (role <> 'admin' OR is_enabled = 0 OR EXISTS (SELECT 1 FROM users WHERE id <> ? AND role = 'admin' AND is_enabled = 1))"
		args = []any{id, id}
	}
	result, err := tx.ExecContext(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		return
	}
	if rowsAffected == 0 {
		var exists int
		if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM users WHERE id = ?", id).Scan(&exists); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		} else if exists == 0 {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		} else {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "不能禁用最后一个已启用管理员"})
		}
		return
	}
	if statusChanged {
		if err := revokeMFAChallenges(tx, id); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		return
	}

	status := "disabled"
	if enable {
		status = "enabled"
	}
	recordAudit(c, "修改状态", "用户", services.FormatAuditDetail(services.AuditUserPart(id, statusUsername), services.AuditResultPart(status)))
	message := "用户状态更新成功"
	if statusProvider == "oidc" && !enable {
		message = "OIDC 用户已禁用，SSO 登录将被拒绝；重新启用可恢复原身份、角色与绑定，无需删除后重新开户。"
	} else if statusProvider == "oidc" {
		message = "OIDC 用户已重新启用，可继续使用原 SSO 身份登录。"
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message})
}

// ResetUserPassword 重置密码（管理员重置任意用户 / 非管理员重置本人）。
// 重置语义：不验证当前密码，也不接受 current_password——自助重置与管理员
// 重置共用同一语义（用户裁定维持：正常改密走 PATCH /users/me，该端点要求
// current_password；本端点只做「重置」）。授权仍由路由级 adminOrSelfParam
// 决定，不放宽到他人。成功后 pwd_ver 递增、在册 MFA 挑战吊销。
func (h *Handlers) ResetUserPassword(c *gin.Context) {
	// 导入窗口 409。
	if rejectWriteDuringImport(c, "执行用户写操作") {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	var req struct {
		NewPassword string `json:"new_password" binding:"required"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// OIDC 用户无本地密码(bcrypt 恒空),重置/设置本地密码会破坏「OIDC 用户
	// 密码登录天然不可用」设计——拒绝(2026-09-18 用户裁定)。
	oidcUser, err := isOIDCUser(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户身份失败"})
		return
	}
	if oidcUser {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "OIDC 用户的密码由认证服务管理，无法本地重置"})
		return
	}
	if err := validatePasswordPolicy(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "密码加密失败"})
		return
	}

	// 单条 UPDATE 事务（保持事务化改造的回滚完整性，吊销已按用户裁定移除）。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重置密码失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "ResetUserPassword rollback failed for id=%d: %v", id, rollbackErr)
			}
		}
	}()
	query := "UPDATE users SET " + strings.Join(passwordResetColumns(), ", ") + " WHERE id = ?"
	result, err := tx.ExecContext(c.Request.Context(), query, string(hash), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重置密码失败"})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重置密码失败"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		return
	}
	// 密码重置吊销在册 MFA 挑战（与更新/自助改密同语义）。
	if err := revokeMFAChallenges(tx, id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重置密码失败"})
		return
	}
	var resetUsername string
	// 同 ToggleUserStatus——审计富化回填读失败 500。
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT username FROM users WHERE id = ?", id).Scan(&resetUsername); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重置密码失败"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重置密码失败"})
		return
	}
	committed = true

	recordAudit(c, "重置密码", "用户", services.FormatAuditDetail(services.AuditUserPart(id, resetUsername), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "密码重置成功"})
}

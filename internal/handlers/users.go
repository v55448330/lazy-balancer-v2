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
	rows, err := db.DB.Query("SELECT id, username, role, display_name, is_enabled, created_at, last_login, COALESCE(mfa_enabled,0), COALESCE(auth_provider,'local') FROM users ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	defer rows.Close()

	var users = make([]models.UserResponse, 0) // F-SYSR-1（第 71 轮）：空表出口归一 []，与 scanAPIKeys 同形（null 会使前端判空分裂）
	for rows.Next() {
		var u models.User
		var mfaEnabled int
		var authProvider string
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.DisplayName, &u.IsEnabled, &u.CreatedAt, &u.LastLogin, &mfaEnabled, &authProvider); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
			return
		}
		response := models.NewUserResponse(u)
		response.MFAEnabled = mfaEnabled == 1
		response.AuthProvider = authProvider
		users = append(users, response)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: users})
}

func (h *Handlers) CreateUser(c *gin.Context) {
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

// passwordResetColumns 改密时必须同步更新的列片段（U07-F02 单一事实源）：
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

func (h *Handlers) UpdateUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	var req struct {
		Username    *string `json:"username" binding:"omitempty,min=3,max=50"`
		Password    *string `json:"password" binding:"omitempty"` // F-SYSR-3（第 71 轮）：长度交 validatePasswordPolicy（友好文案，R63-P2-5 收口）——bcrypt 物理上限 72 由策略 24 上限先行拦截
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
	// R39-15:初始管理员(setup 首个用户)不可降级——与不可删除/禁用同语义,
	// break-glass 能力不可被移除(存在另一管理员时也不放行)。
	if id == setupAdminUserID && req.Role != nil && *req.Role == "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "初始管理员不可降级"})
		return
	}
	// 2026-09-18 用户裁定:OIDC 用户显示名/密码源自 IdP,管理员亦不可改
	// (角色/启停是本地管理语义,不受限)。SYS39-2:username 同为 IdP 源属性
	// (JIT 取 preferred_username),与显示名/密码同一裁定口径一并拦截。
	if req.DisplayName != nil || req.Password != nil || req.Username != nil {
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
	if req.Password != nil {
		if err := validatePasswordPolicy(*req.Password); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	var passwordHash string
	if req.Password != nil && *req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "密码加密失败"})
			return
		}
		passwordHash = string(hash)
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

	changed := []string{}
	sets := make([]string, 0, 5)
	args := make([]any, 0, 5)
	if req.Username != nil && *req.Username != "" && *req.Username != oldUsername {
		if err := validateUsernamePolicy(*req.Username); err != nil { // R63-U4-P3-1：改名须过策略（创建/注册已查、更新曾漏）
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		sets = append(sets, "username = ?")
		args = append(args, *req.Username)
		// SLB10-N8:审计记旧→新(角色降权等高敏变更可取证重建;密码只记名)。
		changed = append(changed, "用户名："+oldUsername+"→"+*req.Username)
	}
	if req.Role != nil && *req.Role != "" && *req.Role != oldRole {
		sets = append(sets, "role = ?")
		args = append(args, *req.Role)
		changed = append(changed, "角色："+oldRole+"→"+*req.Role)
	}
	if req.DisplayName != nil && *req.DisplayName != oldDisplayName {
		sets = append(sets, "display_name = ?")
		args = append(args, *req.DisplayName)
		changed = append(changed, "昵称："+oldDisplayName+"→"+*req.DisplayName)
	}
	if passwordHash != "" {
		// U07-F02：改密同时清空登录锁定（与 ResetUserPassword 共用同一列片段）
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
			// SYS-F4（第 72 轮 P5）：0 行按 COUNT 分判（镜像 ToggleUserStatus
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
	var user models.User
	var authProvider string
	if err := tx.QueryRowContext(c.Request.Context(), `SELECT id,username,role,display_name,is_enabled,created_at,last_login,COALESCE(auth_provider,'local') FROM users WHERE id=?`, id).
		Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin, &authProvider); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}
	user.AuthProvider = authProvider
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
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "用户更新成功", Data: models.NewUserResponse(user)})
}

// isOIDCUser 判定用户是否 OIDC 来源(SYS40-1:读失败与「非 OIDC」分判——
// 身份来源不可判定时调用方必须拒绝写操作,不得静默放行;ErrNoRows 除外:
// 用户不存在是调用方可判定的已知条件,交由后续 0 行 UPDATE → 404)。
func isOIDCUser(ctx context.Context, userID int) (bool, error) {
	var provider string
	err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(auth_provider,'') FROM users WHERE id=?", userID).Scan(&provider)
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

// setupAdminUserID:系统 setup 创建的首个用户(auth.go SetupAdmin 仅在
// users 空表时插入一行)——恒为 id=1,作为本地 break-glass 入口受保护。
const setupAdminUserID = 1

func (h *Handlers) DeleteUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	// SEC19-P5-2(第 19 轮):复用 contextUserID(消除三连手写)。
	userIDInt := int(contextUserID(c))

	if userIDInt == id {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "不能删除当前登录用户"})
		return
	}

	// 初始管理员(setup 创建的首个用户)不可删除——break-glass 入口保护
	// (2026-09-18 用户裁定:提权后的 OIDC 管理员也不可动)。
	if id == setupAdminUserID {
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

	var targetUsername, targetRole string
	var targetEnabled bool
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT username, role, is_enabled FROM users WHERE id = ?", id).Scan(&targetUsername, &targetRole, &targetEnabled); err != nil {
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
	// F49-P5-19①：连带删除的 Key 同样按 keyID 前缀清扫白名单解析缓存——
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
	// F-SYSR-2（第 71 轮）：级联 Key 清单迭代失败须留痕——cascadeKeyIDs 缺项
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

	recordAudit(c, "删除", "用户", services.AuditUserPart(id, targetUsername))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "用户删除成功"})
}

func (h *Handlers) ToggleUserStatus(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	var req struct {
		IsEnabled bool `json:"is_enabled"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}

	// SYSRENDER27-P5-3(第 27 轮审计):自禁用防护——禁用自己=当前会话立即
	// 失效,与 DeleteUser 自保护(SEC19-P5-2)不对称。UI 已挡/API 未挡。
	if !req.IsEnabled {
		if userIDInt := int(contextUserID(c)); userIDInt == id {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "不能禁用当前登录用户"})
			return
		}
	}

	// 初始管理员不可禁用(同 DeleteUser 保护)
	if !req.IsEnabled && id == setupAdminUserID {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "初始管理员不可禁用"})
		return
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
	query := "UPDATE users SET is_enabled = ? WHERE id = ?"
	args := []any{req.IsEnabled, id}
	if !req.IsEnabled {
		query += " AND (role <> 'admin' OR is_enabled = 0 OR EXISTS (SELECT 1 FROM users WHERE id <> ? AND role = 'admin' AND is_enabled = 1))"
		args = append(args, id)
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
	var statusUsername string
	_ = tx.QueryRowContext(c.Request.Context(), "SELECT username FROM users WHERE id = ?", id).Scan(&statusUsername)
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		return
	}

	status := "disabled"
	if req.IsEnabled {
		status = "enabled"
	}
	recordAudit(c, "修改状态", "用户", services.FormatAuditDetail(services.AuditUserPart(id, statusUsername), services.AuditResultPart(status)))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "用户状态更新成功"})
}

func (h *Handlers) ResetUserPassword(c *gin.Context) {
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

	// 单条 UPDATE 事务（保持 G2 事务化改造的回滚完整性，M6 吊销已按用户裁定移除）。
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
	var resetUsername string
	_ = tx.QueryRowContext(c.Request.Context(), "SELECT username FROM users WHERE id = ?", id).Scan(&resetUsername)
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重置密码失败"})
		return
	}
	committed = true

	recordAudit(c, "重置密码", "用户", services.FormatAuditDetail(services.AuditUserPart(id, resetUsername), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "密码重置成功"})
}

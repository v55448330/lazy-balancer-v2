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

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/i18n"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) ListUsers(c *gin.Context) {
	rows, err := db.DB.Query("SELECT " + db.UserRowColumns("") + " FROM users ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "common.databaseError"))
		return
	}
	defer rows.Close()

	var users = make([]models.UserResponse, 0) // F-SYSR-1：空表出口归一 []，与 scanAPIKeys 同形（null 会使前端判空分裂）
	for rows.Next() {
		var meta db.UserRowMeta
		u, err := db.ScanUserRow(rows, &meta)
		if err != nil {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "common.databaseError"))
			return
		}
		// mfa_enabled/is_setup_admin/auth_provider 均由单源扫描载入，
		// 构造器单点复制（删除手工补字段）。
		users = append(users, models.NewUserResponse(u, meta.MFAEnabled))
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "common.databaseError"))
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
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "common.malformedRequest"))
		return
	}

	if req.Role != "admin" && req.Role != "user" {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.invalidRole"))
		return
	}
	if err := validateUsernamePolicy(req.Username); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.ErrMsg(c, err)})
		return
	}
	if err := validatePasswordPolicy(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.ErrMsg(c, err)})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.passwordHashingFailed"))
		return
	}

	// 刻意无 ctx 豁免（登记表=auth_oidc_write_ctx_guard_test.go）：单行 INSERT
	// 自洽无半途态（唯一约束 409/写失败 500 已分判留痕），取消无一致性收益。
	result, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, display_name, is_enabled) VALUES (?, ?, ?, ?, 1)",
		req.Username, string(hash), req.Role, req.DisplayName)
	if err != nil {
		if isUniqueConstraintError(err) {
			c.JSON(http.StatusConflict, apimsg.Envelope(c, 409, "user.usernameAlreadyExists"))
			return
		}
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.createFailed"))
		return
	}

	id, _ := result.LastInsertId()
	recordAudit(c, "创建", "用户", services.FormatAuditDetail(services.AuditUserPart(int(id), req.Username), fmt.Sprintf("角色：%s", req.Role)))
	notify.Publish(notify.Event{Type: notify.EvtUserCreated,
		Fields: map[string]string{"1": c.GetString("username"), "2": req.Username, "3": req.Role}})
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: apimsg.T(c, "user.created"), MessageKey: "user.created", Data: gin.H{"id": id}})
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
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.invalidId"))
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
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "common.malformedRequest"))
		return
	}

	if req.Role != nil && *req.Role != "" && *req.Role != "admin" && *req.Role != "user" {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.invalidRole"))
		return
	}
	// break-glass 管理入口（初始化创建的首个管理员，按 is_setup_admin 标记
	// 判定）不可降级——与不可删除/禁用同语义，存在另一管理员时也不放行。
	protected, ok := setupAdminProtected(c, id)
	if !ok {
		return
	}
	if protected && req.Role != nil && *req.Role == "user" {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.initialAdminCannotBeDemoted"))
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
	// 密码门先于策略校验（单源门，见 oidcManagedWriteGate）：OIDC 用户的密码
	// 不归本地管，弱密码不得先报「长度不能少于 N 位」。
	if oidcManagedWriteGate(c, id, oidcManagedWriteFields{PasswordChanged: passwordChangeRequested}) {
		return
	}
	if req.Password != nil {
		if err := validatePasswordPolicy(*req.Password); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.ErrMsg(c, err)})
			return
		}
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.updateFailed"))
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
			c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "user.notFound"))
		} else {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "auth.userLoadFailed"))
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
			c.JSON(http.StatusForbidden, apimsg.Envelope(c, 403, "user.usernameChangeAdminOnly"))
			return
		}
		if req.Role != nil && *req.Role != "" && *req.Role != oldRole {
			c.JSON(http.StatusForbidden, apimsg.Envelope(c, 403, "user.roleChangeAdminOnly"))
			return
		}
	}
	// username/display_name 门在事务内读到旧值之后再判（值变化判定，密码门
	// 已在上方先于策略校验处走同一单源门）。
	if oidcManagedWriteGate(c, id, oidcManagedWriteFields{
		UsernameChanged:    usernameChanged,
		DisplayNameChanged: displayNameChanged,
	}) {
		return
	}
	var passwordHash string
	if passwordChangeRequested {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.passwordHashingFailed"))
			return
		}
		passwordHash = string(hash)
	}

	changed := []string{}
	// profileChanged 仅供 auth.user_updated 事件：只含角色/显示名变更摘要
	// （用户名/密码有各自事件，不并入本事件，避免双发/混淆）。
	profileChanged := []string{}
	sets := make([]string, 0, 5)
	args := make([]any, 0, 5)
	if usernameChanged {
		if err := validateUsernamePolicy(*req.Username); err != nil { // 改名须过策略（创建/注册已查、更新曾漏）
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.ErrMsg(c, err)})
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
		profileChanged = append(profileChanged, "角色："+oldRole+"→"+*req.Role)
	}
	if displayNameChanged {
		sets = append(sets, "display_name = ?")
		args = append(args, *req.DisplayName)
		changed = append(changed, "昵称："+oldDisplayName+"→"+*req.DisplayName)
		profileChanged = append(profileChanged, "昵称："+oldDisplayName+"→"+*req.DisplayName)
	}
	if passwordHash != "" {
		// 改密同时清空登录锁定（与 ResetUserPassword 共用同一列片段）
		// ——否则锁定态用户改密后仍被 auth.go 的锁判定拒绝。
		sets = append(sets, passwordResetColumns()...)
		args = append(args, passwordHash)
		changed = append(changed, "密码")
	}
	if len(sets) > 0 {
		// 降级最后一个启用管理员：单源判定先行（同一事务内，写锁已由
		// BEGIN IMMEDIATE 持有，不存在并发窗口）。
		if oldEnabled && oldRole == "admin" && req.Role != nil && *req.Role == "user" {
			hasOther, err := ensureOtherEnabledAdmin(c.Request.Context(), tx, id)
			if err != nil {
				c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.updateFailed"))
				return
			}
			if !hasOther {
				c.JSON(http.StatusConflict, apimsg.Envelope(c, 409, "user.cannotDemoteLastEnabledAdmin"))
				return
			}
		}
		args = append(args, id)
		query := "UPDATE users SET " + strings.Join(sets, ", ") + " WHERE id = ?"
		result, err := tx.ExecContext(c.Request.Context(), query, args...)
		if err != nil {
			if isUniqueConstraintError(err) {
				c.JSON(http.StatusConflict, apimsg.Envelope(c, 409, "user.usernameAlreadyExists"))
				return
			}
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.updateFailed"))
			return
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.updateFailed"))
			return
		}
		if rowsAffected == 0 {
			// 0 行按 COUNT 分判（镜像 ToggleUserStatus
			// 先例）——行已消失（并发删除）→ 404；行仍在=末管理员 EXISTS 门
			// 拦截 → 409。此前一律 409 会把并发删除误报成管理员锁。
			var exists int
			if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM users WHERE id = ?", id).Scan(&exists); err != nil {
				c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.updateFailed"))
			} else if exists == 0 {
				c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "user.notFound"))
			} else {
				c.JSON(http.StatusConflict, apimsg.Envelope(c, 409, "user.cannotDemoteLastEnabledAdmin"))
			}
			return
		}
	}
	var meta db.UserRowMeta
	// 改密成功后在提交前吊销在册 MFA 挑战。
	if passwordHash != "" {
		if err := revokeMFAChallenges(tx, id); err != nil {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.updateFailed"))
			return
		}
	}
	// 响应必须回填与 GET /users 同口径（单源列清单：mfa_enabled 与
	// is_setup_admin 一并载入）——此前该端点响应恒 mfa_enabled=false，
	// is_setup_admin 同样恒 false，API 消费者/脚本误判。
	user, err := db.ScanUserRow(tx.QueryRowContext(c.Request.Context(), `SELECT `+db.UserRowColumns("")+` FROM users WHERE id=?`, id), &meta)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "auth.userLoadFailed"))
		return
	}
	if err := tx.Commit(); err != nil {
		// Commit 失败 Tx 已 done，defer Rollback 不触达 driver——池级补发。
		rollbackLeakedTx()
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.updateFailed"))
		return
	}
	committed = true

	if len(changed) == 0 {
		recordAudit(c, "更新", "用户", services.FormatAuditDetail(services.AuditUserPart(id, user.Username), "无修改"))
	} else {
		recordAudit(c, "更新", "用户", services.FormatAuditDetail(services.AuditUserPart(id, user.Username), fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	}
	// 角色/显示名变更通知（纯启停继续走 auth.user_status_changed，不双发）。
	if len(profileChanged) > 0 {
		level := notify.LevelInfo // 仅改显示名（含管理员）属常规信息
		for _, f := range profileChanged {
			if f == "角色" {
				level = notify.LevelWarn // 权限变更需醒目
				break
			}
		}
		notify.Publish(notify.Event{Type: notify.EvtUserUpdated, Level: level,
			Fields: map[string]string{
				"1": c.GetString("username"),
				"2": user.Username,
				"3": strings.Join(profileChanged, "、"),
			}})
	}
	response := models.NewUserResponse(user, meta.MFAEnabled)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "user.updated"), MessageKey: "user.updated", Data: response})
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

// oidcManagedWriteFields 本次请求实际改动的 IdP 源属性（调用方已按「值是否
// 真的变化」判定过——携带与库中同值的字段属无变更局部更新，不算改动）。
type oidcManagedWriteFields struct {
	UsernameChanged    bool
	DisplayNameChanged bool
	PasswordChanged    bool
}

// oidcManagedWriteGate OIDC 托管身份（auth_provider='oidc'）写保护门的唯一
// 实现：用户名/显示名/密码源自 IdP，本地改这些属性一律 400；身份读取失败
// 映射 500（无法判定身份来源时不得让写继续，也不得折叠成 400 放行）。
// 返回 true 表示已写出响应，调用方立即 return。
//
// 调用点约定：**必须先于密码策略校验**——否则「OIDC 用户 + 弱密码」会先撞
// 「密码长度不能少于 N 位」，把「这账号的密码不归本地管」误报成「换个长点的
// 密码就行」（两条改密路径曾各自实现且次序不同）。
func oidcManagedWriteGate(c *gin.Context, userID int, fields oidcManagedWriteFields) bool {
	if !fields.UsernameChanged && !fields.DisplayNameChanged && !fields.PasswordChanged {
		return false
	}
	oidcUser, err := isOIDCUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.identityLoadFailed"))
		return true
	}
	if !oidcUser {
		return false
	}
	c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.oidcManagedFieldsReadOnly", oidcManagedWriteFieldsText(c, fields)))
	return true
}

// oidcManagedWriteFieldsText 按本次实际改动的属性拼出插入模板的字段清单（单源）：
// admin 路径与自助路径改同一组属性时必须得到同一句话，不因各自手写而措辞分叉。
// 字段名走词条，en 界面不出现中文属性名。
func oidcManagedWriteFieldsText(c *gin.Context, fields oidcManagedWriteFields) string {
	attrs := make([]string, 0, 3)
	if fields.UsernameChanged {
		attrs = append(attrs, apimsg.T(c, "user.oidcManagedAttrUsername"))
	}
	if fields.DisplayNameChanged {
		attrs = append(attrs, apimsg.T(c, "user.oidcManagedAttrDisplayName"))
	}
	if fields.PasswordChanged {
		attrs = append(attrs, apimsg.T(c, "user.oidcManagedAttrPassword"))
	}
	// 顿号只属中文：en 界面用逗号，不留中文标点。
	separator := "、"
	if i18n.FromCtx(c) != i18n.ZH {
		separator = ", "
	}
	return strings.Join(attrs, separator)
}

// ensureOtherEnabledAdmin 「至少保留一个启用管理员」不变量的唯一判定：同一
// 事务内判断除 excludeID 之外是否还有已启用管理员。三个写端点（改角色、启停、
// 删除）共用这一份判定，不再各自内联 EXISTS/COUNT SQL。
//
// 判定与后续写在同一事务内完成；事务由 DSN 的 _txlock=immediate 串行化
// （BEGIN IMMEDIATE 即持写锁），故「先查后写」不存在 TOCTOU 窗口——并发互删
// 用例（TestDeleteUser_concurrentMutualDeletionKeepsOneAdministrator）与
// 并发互相降级用例是该保证的行为网。
func ensureOtherEnabledAdmin(ctx context.Context, tx *sql.Tx, excludeID int) (bool, error) {
	var others int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE id <> ? AND role = 'admin' AND is_enabled = 1", excludeID).Scan(&others); err != nil {
		return false, err
	}
	return others > 0, nil
}

// setupAdminProtected 判定目标用户是否为受保护的 break-glass 管理入口
// （初始化创建的首个管理员，按 users.is_setup_admin 标记判定；标记缺失的
// 旧库回落到 db.SetupAdminFallbackUserID）。读库失败必须 500 fail-closed——
// 无法判定保护目标时不得放行删除/禁用/降级。
func setupAdminProtected(c *gin.Context, id int) (protected bool, ok bool) {
	protected, err := db.IsSetupAdmin(c.Request.Context(), db.DB, id)
	if err != nil {
		services.Logf("error", "读取 setup 管理员标记失败: user_id=%d: %v", id, err)
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.protectionStatusLoadFailed"))
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
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.invalidId"))
		return
	}

	// 复用 contextUserID(消除三连手写)。
	userIDInt := int(contextUserID(c))

	if userIDInt == id {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.cannotDeleteSelf"))
		return
	}

	// break-glass 管理入口（setup 创建的首个用户）不可删除——存在另一
	// 管理员时也不放行（2026-09-18 裁定：提权后的 OIDC 管理员同样不可动）。
	protected, ok := setupAdminProtected(c, id)
	if !ok {
		return
	}
	if protected {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.initialAdminCannotBeDeleted"))
		return
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.deleteFailed"))
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
			c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "user.notFound"))
		} else {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "auth.userLoadFailed"))
		}
		return
	}
	if targetRole == "admin" && targetEnabled {
		hasOther, err := ensureOtherEnabledAdmin(c.Request.Context(), tx, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.deleteFailed"))
			return
		}
		if !hasOther {
			c.JSON(http.StatusConflict, apimsg.Envelope(c, 409, "user.cannotDeleteLastEnabledAdmin"))
			return
		}
	}
	// 连带删除的 Key 同样按 keyID 前缀清扫白名单解析缓存——
	// 先取 id 集（删除后无从按键清扫），删除成功后逐键清扫。
	var cascadeKeyIDs []int
	keyRows, keyErr := tx.QueryContext(c.Request.Context(), "SELECT id FROM api_keys WHERE created_by = ?", id)
	if keyErr != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.deleteFailed"))
		return
	}
	for keyRows.Next() {
		var keyID int
		if err := keyRows.Scan(&keyID); err != nil {
			keyRows.Close()
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.deleteFailed"))
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
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.deleteFailed"))
		return
	}
	// 连带清理该用户的 MFA 登录挑战——无越权面（消费端按 token+user_id 判定
	// 且登录第二步 JOIN users），但簿记残留不应依赖 MFAIssueChallenge 的
	// 惰性过期清理（过期才删；未过期行会残留至到期）。
	if _, err := tx.ExecContext(c.Request.Context(), "DELETE FROM mfa_challenges WHERE user_id = ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.deleteFailed"))
		return
	}
	// 通知表随用户连带清理：通道是已删账号仍可继续收安全事件的外部投递面
	// （投递侧不 JOIN users），订阅行在重建同名账号时会串用旧意志——二者都
	// 必须在删除事务内一并移除。投递流水保留：它是
	// 安全事件留痕，不是可再触达的凭据面。
	for _, stmt := range []string{
		"DELETE FROM notification_channels WHERE user_id = ?",
		"DELETE FROM notification_subscriptions WHERE user_id = ?",
	} {
		if _, err := tx.ExecContext(c.Request.Context(), stmt, id); err != nil {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.deleteFailed"))
			return
		}
	}
	for _, keyID := range cascadeKeyIDs {
		purgeAPIKeyWhitelistCache(keyID)
	}
	result, err := tx.ExecContext(c.Request.Context(), "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.deleteFailed"))
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.deleteFailed"))
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "user.notFound"))
		return
	}
	if err := tx.Commit(); err != nil {
		// Commit 失败 Tx 已 done，defer Rollback 不触达 driver——池级补发。
		rollbackLeakedTx()
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.deleteFailed"))
		return
	}
	// 用户删除后其登录后验码限流条目（进程内内存态）不再可被访问，顺带清除
	// 避免条目随一次性用户数量无界驻留（另有阈值清扫兜底）。
	services.MFAClearVerifyAttempts(id)

	recordAudit(c, "删除", "用户", services.AuditUserPart(id, targetUsername))
	notify.Publish(notify.Event{Type: notify.EvtUserDeleted,
		Fields: map[string]string{"1": c.GetString("username"), "2": targetUsername}})
	messageKey := "user.deleteSucceeded"
	if targetProvider == "oidc" {
		messageKey = "user.oidcDeletedSsoReopens"
	}
	c.JSON(http.StatusOK, apimsg.Envelope(c, 0, messageKey))
}

func (h *Handlers) ToggleUserStatus(c *gin.Context) {
	// 导入窗口 409。
	if rejectWriteDuringImport(c, "执行用户写操作") {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.invalidId"))
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
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "common.malformedRequest"))
		return
	}
	if req.IsEnabled == nil {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.isEnabledFieldRequired"))
		return
	}
	enable := *req.IsEnabled

	// 自禁用防护——禁用自己=当前会话立即
	// 失效,与 DeleteUser 自保护不对称。UI 已挡/API 未挡。
	if !enable {
		if userIDInt := int(contextUserID(c)); userIDInt == id {
			c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.cannotDisableSelf"))
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
			c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.initialAdminCannotBeDisabled"))
			return
		}
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.statusUpdateFailed"))
		return
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			services.Logf("error", "ToggleUserStatus rollback failed for id=%d: %v", id, err)
		}
	}()
	var statusUsername, statusRole, statusProvider string
	var wasEnabled bool
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT username, role, is_enabled, COALESCE(auth_provider,'local') FROM users WHERE id = ?", id).Scan(&statusUsername, &statusRole, &wasEnabled, &statusProvider); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "user.notFound"))
		} else {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.statusUpdateFailed"))
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
		// 停用最后一个启用管理员：单源判定先行（同一事务内，写锁已由
		// BEGIN IMMEDIATE 持有）。目标不是「启用中的管理员」时该判定必然通过
		// （不变量保证至少一个启用管理员存在），与旧内联 EXISTS 的谓词等价。
		if wasEnabled && statusRole == "admin" {
			hasOther, checkErr := ensureOtherEnabledAdmin(c.Request.Context(), tx, id)
			if checkErr != nil {
				c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.statusUpdateFailed"))
				return
			}
			if !hasOther {
				c.JSON(http.StatusConflict, apimsg.Envelope(c, 409, "user.cannotDisableLastEnabledAdmin"))
				return
			}
		}
		query = "UPDATE users SET is_enabled = 0" + versionBump + " WHERE id = ?"
		args = []any{id}
	}
	result, err := tx.ExecContext(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.statusUpdateFailed"))
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.statusUpdateFailed"))
		return
	}
	if rowsAffected == 0 {
		var exists int
		if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM users WHERE id = ?", id).Scan(&exists); err != nil {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.statusUpdateFailed"))
		} else if exists == 0 {
			c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "user.notFound"))
		} else {
			c.JSON(http.StatusConflict, apimsg.Envelope(c, 409, "user.cannotDisableLastEnabledAdmin"))
		}
		return
	}
	if statusChanged {
		if err := revokeMFAChallenges(tx, id); err != nil {
			c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.statusUpdateFailed"))
			return
		}
	}
	if err := tx.Commit(); err != nil {
		// Commit 失败 Tx 已 done，defer Rollback 不触达 driver——池级补发。
		rollbackLeakedTx()
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.statusUpdateFailed"))
		return
	}

	status := "disabled"
	if enable {
		status = "enabled"
	}
	recordAudit(c, "修改状态", "用户", services.FormatAuditDetail(services.AuditUserPart(id, statusUsername), services.AuditResultPart(status)))
	statusAction := "禁用"
	if enable {
		statusAction = "启用"
	}
	notify.Publish(notify.Event{Type: notify.EvtUserStatusChanged,
		Fields: map[string]string{"1": c.GetString("username"), "2": statusUsername, "3": statusAction}})
	messageKey := "user.statusUpdateSucceeded"
	if statusProvider == "oidc" && !enable {
		messageKey = "user.oidcDisabledSsoRejected"
	} else if statusProvider == "oidc" {
		messageKey = "user.oidcReenabledSsoAvailable"
	}
	c.JSON(http.StatusOK, apimsg.Envelope(c, 0, messageKey))
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
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.invalidId"))
		return
	}

	var req struct {
		NewPassword string `json:"new_password" binding:"required"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "common.malformedRequest"))
		return
	}
	// OIDC 用户无本地密码(bcrypt 恒空),重置/设置本地密码会破坏「OIDC 用户
	// 密码登录天然不可用」设计——拒绝(2026-09-18 用户裁定)。
	oidcUser, err := isOIDCUser(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.identityLoadFailed"))
		return
	}
	if oidcUser {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "user.oidcPasswordResetNotAllowed"))
		return
	}
	if err := validatePasswordPolicy(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.ErrMsg(c, err)})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.passwordHashingFailed"))
		return
	}

	// 单条 UPDATE 事务（保持事务化改造的回滚完整性）。Key 吊销已按用户裁定
	// 移除（改密不吊销 Key，见认证底线）；MFA 挑战吊销保留（下方 revoke）。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.passwordResetFailed"))
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
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.passwordResetFailed"))
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.passwordResetFailed"))
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "user.notFound"))
		return
	}
	// 密码重置吊销在册 MFA 挑战（与更新/自助改密同语义）。
	if err := revokeMFAChallenges(tx, id); err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.passwordResetFailed"))
		return
	}
	var resetUsername string
	// 同 ToggleUserStatus——审计富化回填读失败 500。
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT username FROM users WHERE id = ?", id).Scan(&resetUsername); err != nil {
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.passwordResetFailed"))
		return
	}
	if err := tx.Commit(); err != nil {
		// Commit 失败 Tx 已 done，defer Rollback 不触达 driver——池级补发。
		rollbackLeakedTx()
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, 500, "user.passwordResetFailed"))
		return
	}
	committed = true

	recordAudit(c, "重置密码", "用户", services.FormatAuditDetail(services.AuditUserPart(id, resetUsername), services.AuditResultPart("success")))
	notify.Publish(notify.Event{Type: notify.EvtPasswordReset,
		Fields: map[string]string{"1": c.GetString("username"), "2": resetUsername}})
	c.JSON(http.StatusOK, apimsg.Envelope(c, 0, "user.passwordResetSucceeded"))
}

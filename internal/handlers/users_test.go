package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestDeleteUser_deletesOwnedAPIKeys(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 2, "target", "user", true)
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by) VALUES ('owned','hash','prefix',2)`); err != nil {
		t.Fatal(err)
	}

	response := serveUserMutation(h, http.MethodDelete, "/users/2", "", 1, h.DeleteUser)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var users, keys int
	if err := db.DB.QueryRow("SELECT (SELECT COUNT(*) FROM users WHERE id=2), (SELECT COUNT(*) FROM api_keys WHERE created_by=2)").Scan(&users, &keys); err != nil {
		t.Fatal(err)
	}
	if users != 0 || keys != 0 {
		t.Fatalf("remaining users=%d keys=%d", users, keys)
	}
}

func TestDeleteUser_cleansMFAChallenges(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 2, "target", "user", true)
	// 未过期的 MFA 登录挑战残留——删除用户后不应依赖惰性过期清理。
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,password_version) VALUES ('tok-target',2,datetime('now','+5 minutes'),0)`); err != nil {
		t.Fatal(err)
	}

	response := serveUserMutation(h, http.MethodDelete, "/users/2", "", 1, h.DeleteUser)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var challenges int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM mfa_challenges WHERE user_id=2").Scan(&challenges); err != nil {
		t.Fatal(err)
	}
	if challenges != 0 {
		t.Fatalf("remaining mfa_challenges=%d, want 0（删除用户须连带清理挑战残留）", challenges)
	}
}

func TestDeleteUser_rejectsSelfDeletion(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	response := serveUserMutation(h, http.MethodDelete, "/users/1", "", 1, h.DeleteUser)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestDeleteUser_rejectsLastEnabledAdministrator(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 5, "admin-5", "admin", true)
	response := serveUserMutation(h, http.MethodDelete, "/users/5", "", 99, h.DeleteUser)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestToggleUserStatus_rejectsDisablingLastEnabledAdministrator(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 5, "admin-5", "admin", true)
	// 自禁用守卫(400)先于最后管理员守卫(409)——
	// 本测试意图是最后管理员守卫,actorID 改 99(非自身)避开自禁用前置拦截。
	// 目标用 id=5:id=1 已被初始管理员保护(2026-09-18)先行 400 拦截。
	response := serveUserMutation(h, http.MethodPut, "/users/5", `{"is_enabled":false}`, 99, h.ToggleUserStatus)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUpdateUser_rejectsDemotingLastEnabledAdministrator(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 目标用 id=5:id=1 受初始管理员不可降级保护先行 400 拦截。
	seedUserAuditTest(t, 5, "admin", "admin", true)
	response := serveUserMutation(h, http.MethodPut, "/users/5", `{"role":"user"}`, 5, h.UpdateUser)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// UpdateUser 的 UPDATE 命中 0 行此前一律误报
// 409「不能移除最后一个已启用管理员」——并发删除形态（读旧行后、UPDATE 前
// 行消失）应镜像 ToggleUserStatus 先例按 COUNT 分判：行已不在 → 404；
// 行仍在（末管理员 EXISTS 门拦截）→ 409。
func TestUpdateUser_rowVanishingBeforeUpdateReturns404(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 5, "vanish-user", "user", true)
	// 触发器模拟并发删除：UPDATE 命中前删行 + RAISE(IGNORE) 吞掉本次更新
	//（等价于 DELETE 抢在 UPDATE 前提交——RowsAffected=0 且行已不存在）。
	if _, err := db.DB.Exec(`CREATE TRIGGER users_vanish_5 BEFORE UPDATE ON users WHEN OLD.id=5 BEGIN DELETE FROM users WHERE id=5; SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("DROP TRIGGER IF EXISTS users_vanish_5") })

	response := serveUserMutation(h, http.MethodPut, "/users/5", `{"display_name":"renamed"}`, 1, h.UpdateUser)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404（并发删除不得误报管理员锁）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "用户不存在") {
		t.Fatalf("body=%s, want 用户不存在", response.Body.String())
	}
}

func TestUpdateUser_concurrentDemotionsPreserveEnabledAdministrator(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "bystander", "user", true) // id=1 占位(非 admin,不参与末管理员计数)
	seedUserAuditTest(t, 3, "admin-3", "admin", true)
	seedUserAuditTest(t, 4, "admin-4", "admin", true)

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var workers sync.WaitGroup
	for id := 3; id <= 4; id++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			<-start
			response := serveUserMutation(h, http.MethodPut, "/users/"+strconv.Itoa(id), `{"role":"user"}`, id, h.UpdateUser)
			statuses <- response.Code
		}(id)
	}
	close(start)
	workers.Wait()
	close(statuses)
	seenOK, seenConflict := false, false
	for status := range statuses {
		seenOK = seenOK || status == http.StatusOK
		seenConflict = seenConflict || status == http.StatusConflict
	}
	if !seenOK || !seenConflict {
		t.Fatalf("concurrent statuses require one 200 and one 409")
	}
	var admins int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin' AND is_enabled=1").Scan(&admins); err != nil {
		t.Fatal(err)
	}
	if admins != 1 {
		t.Fatalf("enabled administrators=%d, want 1", admins)
	}
}

func TestLastAdministratorGuard_allowsChangeWhenAnotherEnabledAdministratorExists(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 4, "admin-4", "admin", true)
	seedUserAuditTest(t, 2, "admin-2", "admin", true)
	// actorID 改 2(admin-2 操作 admin-4)——
	// 自禁用守卫(400)前置,本测试意图是「另一管理员存在时允许」;目标非
	// id=1(初始管理员保护会先行 400)。
	response := serveUserMutation(h, http.MethodPut, "/users/4", `{"is_enabled":false}`, 2, h.ToggleUserStatus)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUpdateUser_validatesUsernameLength(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)

	// When: 用户名过短
	response := serveUserMutation(h, http.MethodPut, "/users/1", `{"username":"ab"}`, 1, h.UpdateUser)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("short username status=%d body=%s, want 400", response.Code, response.Body.String())
	}

	// When: 用户名满足 min=3
	response = serveUserMutation(h, http.MethodPut, "/users/1", `{"username":"abc"}`, 1, h.UpdateUser)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("valid username status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}

func TestUpdateCurrentUser_validatesDisplayNameLength(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,display_name) VALUES (1,'current','old-hash','admin','Before')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	router.PATCH("/users/me", func(c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) })

	// When: display_name 超过 50 字符
	request := httptest.NewRequest(http.MethodPatch, "/users/me", strings.NewReader(`{"display_name":"`+strings.Repeat("名", 51)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("51-char display_name status=%d body=%s, want 400", response.Code, response.Body.String())
	}

	// When: display_name 恰好 50 字符
	request = httptest.NewRequest(http.MethodPatch, "/users/me", strings.NewReader(`{"display_name":"`+strings.Repeat("名", 50)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("50-char display_name status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}

func seedUserAuditTest(t *testing.T, id int, username, role string, enabled bool) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (?,?,?,?,?)", id, username, "hash", role, enabled); err != nil {
		t.Fatal(err)
	}
}

func serveUserMutation(h *Handlers, method, path, body string, actorID int, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	context.Request.Header.Set("Content-Type", "application/json")
	context.Params = gin.Params{{Key: "id", Value: strings.TrimPrefix(path, "/users/")}}
	context.Set("user_id", actorID)
	context.Set("role", "admin")
	handler(context)
	return response
}

// 自禁用守卫目标形状——操作者禁用自己被 400 拒绝。
func TestToggleUserStatus_rejectsDisablingSelf(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin-1", "admin", true)
	seedUserAuditTest(t, 2, "admin-2", "admin", true)
	// actorID=1 目标=1——自禁用(即使另一管理员存在也应 400)
	response := serveUserMutation(h, http.MethodPut, "/users/1", `{"is_enabled":false}`, 1, h.ToggleUserStatus)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 cannot_disable_self", response.Code, response.Body.String())
	}
}

// 初始管理员(setup 创建的首个用户 id=1)禁止禁用与删除——即使操作者是
// 另一管理员(如被提权的 OIDC 用户)也不可。否则全部凭证丢失时失去
// break-glass 入口(用户 2026-09-18 裁定)。
func TestSetupAdmin_cannotBeDisabledOrDeleted(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true) // setup 初始管理员
	seedUserAuditTest(t, 2, "oidc-admin", "admin", true)

	// When: 管理员 2 删除初始管理员 → 400
	rec := serveUserMutation(h, http.MethodDelete, "/users/1", "", 2, h.DeleteUser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "初始管理员") {
		t.Fatalf("delete setup admin: status=%d body=%s, want 400 初始管理员", rec.Code, rec.Body.String())
	}
	// When: 管理员 2 禁用初始管理员 → 400
	rec = serveUserMutation(h, http.MethodPatch, "/users/1", `{"is_enabled":false}`, 2, h.ToggleUserStatus)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "初始管理员") {
		t.Fatalf("disable setup admin: status=%d body=%s, want 400 初始管理员", rec.Code, rec.Body.String())
	}
	// 回归形状:普通管理员之间仍可正常禁用(2 禁用 3 不受影响)
	seedUserAuditTest(t, 3, "admin-3", "admin", true)
	rec = serveUserMutation(h, http.MethodPatch, "/users/3", `{"is_enabled":false}`, 2, h.ToggleUserStatus)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable ordinary admin should pass: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// OIDC 用户数据显示名/密码来自 IdP(随登录/同步刷新)——自助与管理员路径
// 均不得修改(2026-09-18 用户裁定:要改去 OIDC 服务改)。
func TestOIDCUser_cannotModifyDisplayNameOrPassword(t *testing.T) {
	h := newBackupTestHandlers(t)
	// Given: OIDC 用户 id=7,管理员 id=1
	seedUserAuditTest(t, 1, "admin", "admin", true)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,display_name) VALUES (7,'sso@example.com','','user',1,'oidc','IdP Name')`); err != nil {
		t.Fatal(err)
	}

	// When: OIDC 用户自助改显示名 → 400
	rec := serveUserMutation(h, http.MethodPatch, "/users/7", `{"display_name":"Hacked"}`, 7, h.UpdateCurrentUser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OIDC") {
		t.Fatalf("self display_name: status=%d body=%s, want 400 OIDC 提示", rec.Code, rec.Body.String())
	}
	// When: OIDC 用户自助改密码(带当前密码,空哈希恒败故先绕过密码门——直接断言 OIDC 门先拦)→ 400
	rec = serveUserMutation(h, http.MethodPatch, "/users/7", `{"password":"Newpass123!","current_password":"x"}`, 7, h.UpdateCurrentUser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OIDC") {
		t.Fatalf("self password: status=%d body=%s, want 400 OIDC 提示", rec.Code, rec.Body.String())
	}
	// When: 管理员改 OIDC 用户显示名 → 400
	rec = serveUserMutation(h, http.MethodPut, "/users/7", `{"display_name":"AdminSet"}`, 1, h.UpdateUser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OIDC") {
		t.Fatalf("admin display_name: status=%d body=%s, want 400 OIDC 提示", rec.Code, rec.Body.String())
	}
	// When: 管理员重置 OIDC 用户密码 → 400
	pwRec := httptest.NewRecorder()
	pwCtx, _ := gin.CreateTestContext(pwRec)
	pwCtx.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_password":"Reset123!"}`))
	pwCtx.Request.Header.Set("Content-Type", "application/json")
	pwCtx.Params = gin.Params{{Key: "id", Value: "7"}}
	pwCtx.Set("user_id", 1)
	h.ResetUserPassword(pwCtx)
	rec = pwRec
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OIDC") {
		t.Fatalf("admin reset password: status=%d body=%s, want 400 OIDC 提示", rec.Code, rec.Body.String())
	}
	// 回归:本地用户自助改显示名不受影响
	rec = serveUserMutation(h, http.MethodPatch, "/users/1", `{"display_name":"NewName"}`, 1, h.UpdateCurrentUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("local user display_name should pass: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// OIDC 门按「值实际变化」判定（与 UpdateUser 同构）：携带与库中同值的
// display_name 属无变更局部更新，必须放行；改值仍 400。
func TestUpdateCurrentUser_oidcGateByValueChange(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,display_name) VALUES (7,'sso@example.com','','user',1,'oidc','IdP Name')`); err != nil {
		t.Fatal(err)
	}

	// 同值提交 → 放行（无修改）。
	rec := serveUserMutation(h, http.MethodPatch, "/users/7", `{"display_name":"IdP Name"}`, 7, h.UpdateCurrentUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-value display_name status=%d body=%s, want 200（同值属无变更）", rec.Code, rec.Body.String())
	}
	// 改值 → 400 OIDC 提示保持。
	rec = serveUserMutation(h, http.MethodPatch, "/users/7", `{"display_name":"Hacked"}`, 7, h.UpdateCurrentUser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OIDC") {
		t.Fatalf("changed display_name status=%d body=%s, want 400 OIDC 提示", rec.Code, rec.Body.String())
	}
	// 非空密码恒视为改密尝试 → 400（不依赖旧值比对）。
	rec = serveUserMutation(h, http.MethodPatch, "/users/7", `{"password":"Newpass123!","current_password":"x"}`, 7, h.UpdateCurrentUser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OIDC") {
		t.Fatalf("password change status=%d body=%s, want 400 OIDC 提示", rec.Code, rec.Body.String())
	}
}

// 身份来源(auth_provider)读失败不得按「非 OIDC」静默放行——
// DB 故障下 OIDC 管理门形同虚设。不可判定时拒绝写操作(500)。
func TestUserMutations_rejectWhenIdentityUnreadable(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 7, "victim", "user", true)
	// 注入读失败形状:auth_provider 列不可读(仅命中 OIDC 身份判定查询)
	if _, err := db.DB.Exec("ALTER TABLE users RENAME COLUMN auth_provider TO auth_provider_unreadable"); err != nil {
		t.Fatalf("break auth_provider column: %v", err)
	}

	rec := serveUserMutation(h, http.MethodPut, "/users/7", `{"display_name":"x"}`, 1, h.UpdateUser)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "读取用户身份失败") {
		t.Fatalf("update with unreadable identity must 500, got %d %s", rec.Code, rec.Body.String())
	}

	pwRec := httptest.NewRecorder()
	pwCtx, _ := gin.CreateTestContext(pwRec)
	pwCtx.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_password":"Reset123!"}`))
	pwCtx.Request.Header.Set("Content-Type", "application/json")
	pwCtx.Params = gin.Params{{Key: "id", Value: "7"}}
	pwCtx.Set("user_id", 1)
	h.ResetUserPassword(pwCtx)
	rec = pwRec
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "读取用户身份失败") {
		t.Fatalf("reset-password with unreadable identity must 500, got %d %s", rec.Code, rec.Body.String())
	}

	rec = serveUserMutation(h, http.MethodPatch, "/users/7", `{"display_name":"x"}`, 7, h.UpdateCurrentUser)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "读取用户身份失败") {
		t.Fatalf("self update with unreadable identity must 500, got %d %s", rec.Code, rec.Body.String())
	}

	rec = serveUserMutation(h, http.MethodPost, "/auth/mfa/setup", `{}`, 7, h.MFASetup)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "读取用户身份失败") {
		t.Fatalf("mfa setup with unreadable identity must 500, got %d %s", rec.Code, rec.Body.String())
	}
}

// 管理员重置密码必须同时清零登录失败计数与锁定——重置语义即
// 「凭据已换新」,旧凭据的锁定残留会把新密码也锁在门外。
func TestResetUserPassword_clearsLoginLockout(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 7, "locked-user", "user", true)
	if _, err := db.DB.Exec(`UPDATE users SET login_failed_attempts=5, login_locked_until='2099-01-01 00:00:00' WHERE id=7`); err != nil {
		t.Fatal(err)
	}

	pwRec := httptest.NewRecorder()
	pwCtx, _ := gin.CreateTestContext(pwRec)
	pwCtx.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_password":"Fresh123!"}`))
	pwCtx.Request.Header.Set("Content-Type", "application/json")
	pwCtx.Params = gin.Params{{Key: "id", Value: "7"}}
	pwCtx.Set("user_id", 1)
	h.ResetUserPassword(pwCtx)
	if pwRec.Code != http.StatusOK {
		t.Fatalf("reset password should succeed, got %d %s", pwRec.Code, pwRec.Body.String())
	}

	var attempts int
	var lockedUntil sql.NullString
	if err := db.DB.QueryRow("SELECT login_failed_attempts, login_locked_until FROM users WHERE id=7").Scan(&attempts, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || lockedUntil.Valid {
		t.Fatalf("lockout must be cleared on admin reset, got attempts=%d locked_until=%v", attempts, lockedUntil)
	}
}

// （2026-09-19 用户裁定「统一遵循请求体大小配置项限制」)
// 端点级实证:CreateUser 在 bind 前经 guardConfiguredJSONBody——配置 1MB 上限时
// ≈2MB body 预检 413(未接 guard 则落入 username max=50 校验 400),小 body 正常 201。
func TestCreateUser_configuredBodyLimit413(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET request_body_max_size_mb=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	big := `{"username":"u` + strings.Repeat("a", 2<<20) + `","password":"Secret123!","role":"user"}`
	if response := serveUserMutation(h, http.MethodPost, "/users", big, 1, h.CreateUser); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%.200s, want 413", response.Code, response.Body.String())
	}
	if response := serveUserMutation(h, http.MethodPost, "/users", `{"username":"newuser1","password":"Secret123!","role":"user"}`, 1, h.CreateUser); response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%.200s, want 201(配置上限下小 body 不受影响)", response.Code, response.Body.String())
	}
}

// ListUsers 空表出口归一——data 须为 [] 而非 null
// （与 apikeys scanAPIKeys 出口同形，两形状并存会让前端判空逻辑分裂）。
func TestListUsers_emptyTableReturnsEmptyArray(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.GET("/users", h.ListUsers)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/users", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), `"data":null`) {
		t.Fatalf("空表返回 data=null，须归一为 []: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"data":[]`) {
		t.Fatalf("空表 data 须为 []: %s", response.Body.String())
	}
}

// ListUsers 必须透出 is_setup_admin：前端据此禁用「删除/禁用」两个操作，
// 后端保护（DeleteUser/UpdateUser status 分支）已存在，缺标记会让按钮可点后
// 报 400，属可见契约断裂。
func TestListUsers_exposesSetupAdminFlag(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 7, "other", "user", true)
	if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=0 WHERE id=7`); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.GET("/users", h.ListUsers)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct {
			ID           int  `json:"id"`
			IsSetupAdmin bool `json:"is_setup_admin"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	flags := map[int]bool{}
	for _, u := range resp.Data {
		flags[u.ID] = u.IsSetupAdmin
	}
	if !flags[1] {
		t.Fatalf("初始化管理员 is_setup_admin 应为 true: %+v", flags)
	}
	if flags[7] {
		t.Fatalf("普通用户 is_setup_admin 应为 false: %+v", flags)
	}
}

// OIDC 门对 password 字段的拦截粒度——空密码串在策略层
// 语义为「不修改」（validatePasswordPolicy 空值放行、passwordHash 仅在非空时
// 生成），管理员更新 OIDC 用户角色/启停时载荷携带空 password 键不应被拒。
func TestUpdateUser_oidcEmptyPasswordTreatedAsUnchanged(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,display_name) VALUES (7,'sso@example.com','','user',1,'oidc','IdP Name')`); err != nil {
		t.Fatal(err)
	}

	// When: 管理员改 OIDC 用户角色并携带空 password 键 → 放行（空=不修改）
	rec := serveUserMutation(h, http.MethodPut, "/users/7", `{"role":"admin","password":""}`, 1, h.UpdateUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty password must be treated as unchanged: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var role, hash string
	if err := db.DB.QueryRow("SELECT role, password_hash FROM users WHERE id=7").Scan(&role, &hash); err != nil {
		t.Fatal(err)
	}
	if role != "admin" || hash != "" {
		t.Fatalf("role=%q hash=%q, want role=admin 且密码未动", role, hash)
	}

	// 回归形状：非空密码仍被 OIDC 门拦截
	rec = serveUserMutation(h, http.MethodPut, "/users/7", `{"password":"Newpass123!"}`, 1, h.UpdateUser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OIDC") {
		t.Fatalf("non-empty password: status=%d body=%s, want 400 OIDC 提示", rec.Code, rec.Body.String())
	}
}

// 审计富化的 username 回填查询此前静默吞错（_ = Scan）——
// DB 故障下操作照常 200 且审计详情缺失用户名。改为与其余 DB 错误同口径 500
// （RENAME COLUMN 注入读失败，同 TestUserMutations_rejectWhenIdentityUnreadable 形状）。
func TestUserMutations_failWhenUsernameUnreadable(t *testing.T) {
	t.Run("toggle status", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedUserAuditTest(t, 1, "admin", "admin", true)
		seedUserAuditTest(t, 7, "victim", "user", false)
		if _, err := db.DB.Exec("ALTER TABLE users RENAME COLUMN username TO username_unreadable"); err != nil {
			t.Fatalf("break username column: %v", err)
		}
		rec := serveUserMutation(h, http.MethodPut, "/users/7", `{"is_enabled":true}`, 1, h.ToggleUserStatus)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("toggle with unreadable username must 500, got %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("reset password", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedUserAuditTest(t, 1, "admin", "admin", true)
		seedUserAuditTest(t, 7, "victim", "user", true)
		if _, err := db.DB.Exec("ALTER TABLE users RENAME COLUMN username TO username_unreadable"); err != nil {
			t.Fatalf("break username column: %v", err)
		}
		rec := serveUserMutation(h, http.MethodPut, "/users/7", `{"new_password":"Secret123!"}`, 1, h.ResetUserPassword)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("reset with unreadable username must 500, got %d %s", rec.Code, rec.Body.String())
		}
	})
}

// OIDC 写保护门按「值实际变化」判定——携带与库中
// 同值的 display_name、空 username 或同值 username 属无实际变更的局部更新，
// 不得整单 400（角色/启停是本地管理语义）；真实字段变更仍 400。
func TestUpdateUser_oidcGateComparesValuesNotFieldPresence(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,display_name) VALUES (7,'sso@example.com','','user',1,'oidc','IdP Name')`); err != nil {
		t.Fatal(err)
	}

	// 同值 display_name + 角色变更 → 200，角色本地生效
	rec := serveUserMutation(h, http.MethodPut, "/users/7", `{"role":"admin","display_name":"IdP Name"}`, 1, h.UpdateUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("same display_name + role change: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var role string
	if err := db.DB.QueryRow("SELECT role FROM users WHERE id=7").Scan(&role); err != nil || role != "admin" {
		t.Fatalf("role=%q err=%v, want admin", role, err)
	}
	// 注：空 username 在绑定层（binding:"omitempty,min=3" 对 *string 仍校验
	// 空串）即 400，到不了 OIDC 门——该形状的既有拒绝与本次修复无关。
	// 同值 username → 200
	rec = serveUserMutation(h, http.MethodPut, "/users/7", `{"username":"sso@example.com"}`, 1, h.UpdateUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("same username: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	// 真实变更仍拦截（回归）
	rec = serveUserMutation(h, http.MethodPut, "/users/7", `{"display_name":"Other Name"}`, 1, h.UpdateUser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OIDC") {
		t.Fatalf("real display_name change: status=%d body=%s, want 400 OIDC", rec.Code, rec.Body.String())
	}
}

// 重新启用用户必须清零历史登录失败与锁定（与改密的解锁语义同源）：管理员
// 「恢复该账号」的意图不得被前 5 次失败留下的 10 分钟锁定打断。
func TestToggleUserStatus_enableClearsLoginLock(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 2, "locked-user", "user", false)
	if _, err := db.DB.Exec(`UPDATE users SET login_failed_attempts=5, login_locked_until=datetime('now','+9 minutes') WHERE id=2`); err != nil {
		t.Fatalf("seed lock state: %v", err)
	}

	rec := serveUserMutation(h, http.MethodPut, "/users/2", `{"is_enabled":true}`, 1, h.ToggleUserStatus)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var attempts int
	var lockedUntil sql.NullString
	if err := db.DB.QueryRow(`SELECT login_failed_attempts, login_locked_until FROM users WHERE id=2`).Scan(&attempts, &lockedUntil); err != nil {
		t.Fatalf("read lock state: %v", err)
	}
	if attempts != 0 || lockedUntil.Valid {
		t.Fatalf("attempts=%d locked_until=%v, want 0/NULL（启用即解锁）", attempts, lockedUntil)
	}
}

// 禁用分支不得顺带解锁：禁用≠换凭据，历史失败计数保留（重启后仍生效）。
func TestToggleUserStatus_disableKeepsLoginLock(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin-1", "admin", true)
	seedUserAuditTest(t, 2, "admin-2", "admin", true)
	seedUserAuditTest(t, 5, "locked-user", "user", true)
	if _, err := db.DB.Exec(`UPDATE users SET login_failed_attempts=3, login_locked_until=datetime('now','+4 minutes') WHERE id=5`); err != nil {
		t.Fatalf("seed lock state: %v", err)
	}

	rec := serveUserMutation(h, http.MethodPut, "/users/5", `{"is_enabled":false}`, 1, h.ToggleUserStatus)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var attempts int
	var lockedUntil sql.NullString
	if err := db.DB.QueryRow(`SELECT login_failed_attempts, login_locked_until FROM users WHERE id=5`).Scan(&attempts, &lockedUntil); err != nil {
		t.Fatalf("read lock state: %v", err)
	}
	if attempts != 3 || !lockedUntil.Valid {
		t.Fatalf("attempts=%d locked_until=%v, want 3/保留（禁用不解锁）", attempts, lockedUntil)
	}
}

func TestToggleUserStatus_challengeRevocationFailureRollsBack(t *testing.T) {
	for _, initiallyEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("initially_enabled=%v", initiallyEnabled), func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedUserAuditTest(t, 1, "admin", "admin", true)
			seedUserAuditTest(t, 5, "target", "user", initiallyEnabled)
			if _, err := db.DB.Exec("UPDATE users SET password_version=4 WHERE id=5"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec("INSERT INTO mfa_challenges (token,user_id,expires_at) VALUES ('status-challenge',5,datetime('now','+5 minutes'))"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec("CREATE TRIGGER reject_status_challenge_revoke BEFORE DELETE ON mfa_challenges BEGIN SELECT RAISE(FAIL,'revoke blocked'); END"); err != nil {
				t.Fatal(err)
			}
			body := `{"is_enabled":true}`
			if initiallyEnabled {
				body = `{"is_enabled":false}`
			}
			response := serveUserMutation(h, http.MethodPut, "/users/5", body, 1, h.ToggleUserStatus)
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
			}
			var enabled bool
			var version, challenges int
			if err := db.DB.QueryRow("SELECT is_enabled,password_version,(SELECT COUNT(*) FROM mfa_challenges WHERE user_id=5) FROM users WHERE id=5").Scan(&enabled, &version, &challenges); err != nil {
				t.Fatal(err)
			}
			if enabled != initiallyEnabled || version != 4 || challenges != 1 {
				t.Fatalf("事务未回滚: enabled=%v version=%d challenges=%d", enabled, version, challenges)
			}
		})
	}
}

func TestToggleUserStatus_sameValueDoesNotRevokeSessionsOrChallenges(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedUserAuditTest(t, 1, "admin", "admin", true)
			seedUserAuditTest(t, 5, "target", "user", enabled)
			if _, err := db.DB.Exec("UPDATE users SET password_version=7 WHERE id=5"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec("INSERT INTO mfa_challenges (token,user_id,expires_at) VALUES ('same-status-challenge',5,datetime('now','+5 minutes'))"); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"is_enabled":%v}`, enabled)
			response := serveUserMutation(h, http.MethodPut, "/users/5", body, 1, h.ToggleUserStatus)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var version, challenges int
			if err := db.DB.QueryRow("SELECT password_version,(SELECT COUNT(*) FROM mfa_challenges WHERE user_id=5) FROM users WHERE id=5").Scan(&version, &challenges); err != nil {
				t.Fatal(err)
			}
			if version != 7 || challenges != 1 {
				t.Fatalf("同值请求误吊销会话: version=%d challenges=%d", version, challenges)
			}
		})
	}
}

func TestDeleteUser_oidcResponseExplainsRebindAndDisableAlternative(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer)
		VALUES (7,'sso-user','','user',1,'oidc','sub-7','https://idp.example.com')`); err != nil {
		t.Fatal(err)
	}

	response := serveUserMutation(h, http.MethodDelete, "/users/7", "", 1, h.DeleteUser)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	for _, want := range []string{"重新开户", "禁用"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("delete response=%s, want recovery/rebind hint containing %q", response.Body.String(), want)
		}
	}
}

func TestToggleUserStatus_oidcDisableResponseExplainsRestore(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer)
		VALUES (7,'sso-user','','user',1,'oidc','sub-7','https://idp.example.com')`); err != nil {
		t.Fatal(err)
	}

	response := serveUserMutation(h, http.MethodPut, "/users/7", `{"is_enabled":false}`, 1, h.ToggleUserStatus)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	for _, want := range []string{"重新启用", "原身份"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("disable response=%s, want restore hint containing %q", response.Body.String(), want)
		}
	}
}

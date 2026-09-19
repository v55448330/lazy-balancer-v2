package handlers

import (
	"database/sql"
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
	// SYSRENDER27-P5-3(第 27 轮):自禁用守卫(400)先于最后管理员守卫(409)——
	// 本测试意图是最后管理员守卫,actorID 改 99(非自身)避开自禁用前置拦截。
	// 目标用 id=5:id=1 已被初始管理员保护(2026-09-18)先行 400 拦截。
	response := serveUserMutation(h, http.MethodPut, "/users/5", `{"is_enabled":false}`, 99, h.ToggleUserStatus)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUpdateUser_rejectsDemotingLastEnabledAdministrator(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 目标用 id=5:id=1 受初始管理员不可降级保护(R39-15)先行 400 拦截。
	seedUserAuditTest(t, 5, "admin", "admin", true)
	response := serveUserMutation(h, http.MethodPut, "/users/5", `{"role":"user"}`, 5, h.UpdateUser)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
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
	// SYSRENDER27-P5-3(第 27 轮):actorID 改 2(admin-2 操作 admin-4)——
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
	handler(context)
	return response
}

// SYSRENDER28-P5-3(第 28 轮审计):自禁用守卫目标形状——操作者禁用自己被 400 拒绝。
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
	rec = serveUserMutation(h, http.MethodPatch, "/users/7", `{"password":"newpass123","current_password":"x"}`, 7, h.UpdateCurrentUser)
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
	pwCtx.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_password":"reset123"}`))
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

// SYS40-1:身份来源(auth_provider)读失败不得按「非 OIDC」静默放行——
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
	pwCtx.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_password":"reset123"}`))
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

// SYS40-2:管理员重置密码必须同时清零登录失败计数与锁定——重置语义即
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
	pwCtx.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_password":"fresh123"}`))
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

// APIMCP41-2(第 41 轮审计,2026-09-19 用户裁定「统一遵循请求体大小配置项限制」)
// 端点级实证:CreateUser 在 bind 前经 guardConfiguredJSONBody——配置 1MB 上限时
// ≈2MB body 预检 413(未接 guard 则落入 username max=50 校验 400),小 body 正常 201。
func TestCreateUser_configuredBodyLimit413(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET request_body_max_size_mb=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	big := `{"username":"u` + strings.Repeat("a", 2<<20) + `","password":"secret123","role":"user"}`
	if response := serveUserMutation(h, http.MethodPost, "/users", big, 1, h.CreateUser); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%.200s, want 413", response.Code, response.Body.String())
	}
	if response := serveUserMutation(h, http.MethodPost, "/users", `{"username":"newuser1","password":"secret123","role":"user"}`, 1, h.CreateUser); response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%.200s, want 201(配置上限下小 body 不受影响)", response.Code, response.Body.String())
	}
}

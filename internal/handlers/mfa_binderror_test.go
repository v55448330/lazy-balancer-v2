package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// F5-3（bind-error 约定）：MFASetup 重新绑定确认段与 MFAResetByAdmin 的请求体
// `_ = c.ShouldBindJSON(...)` 吞错——畸形 JSON 落入零值字段，报出误导性的
// 「密码错误」/「验证码错误」401 而非 400「请求格式错误」。对齐 Login
// （auth.go:51-55）约定：绑定失败即 400。

// malformedMfaBody 截断的畸形 JSON（语法层即非法）。
const malformedMfaBody = `{"password":`

func postRaw(router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// 场景 1：已启用 MFA 用户重新 setup（确认段）收到畸形 JSON → 400「请求格式错误」。
// 修复前：绑定错误被吞，零值密码走 bcrypt 比较 → 401「密码错误」。
func TestMFASetup_malformedJSON_returns400(t *testing.T) {
	// Given 已启用 MFA 的用户（进入密码+验证码确认段）
	h := newBackupTestHandlers(t)
	seedMfaGateUser(t, gateTestPassword)
	router := mfaSetupTestRouter(h)

	// When 畸形 JSON
	rec := postRaw(router, "/auth/mfa/setup", malformedMfaBody)

	// Then 400 + 请求格式错误（修复前：401 密码错误）
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（绑定失败应按 Login 约定返回请求格式错误）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "请求格式错误") {
		t.Fatalf("body=%s, want 包含「请求格式错误」", rec.Body.String())
	}
}

// 场景 2：MFAResetByAdmin 收到畸形 JSON → 400「请求格式错误」。
// 修复前：绑定错误被吞，零值 code 走验码 → 401「验证码错误」。
func TestMFAResetByAdmin_malformedJSON_returns400(t *testing.T) {
	// Given 操作者启用 MFA + 守卫关（第一层必须验码的路径——畸形体才能落到绑定点）
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, false)
	router := mfaResetRouter(h, "jwt")

	// When 畸形 JSON
	rec := postRaw(router, "/users/2/mfa/reset", malformedMfaBody)

	// Then 400 + 请求格式错误（修复前：401 验证码错误）
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（绑定失败应按 Login 约定返回请求格式错误）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "请求格式错误") {
		t.Fatalf("body=%s, want 包含「请求格式错误」", rec.Body.String())
	}
}

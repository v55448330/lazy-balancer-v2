package handlers

// MFA verify-step 的导入窗口门：五个 MFA 写端点同门（setup/activate/disable/
// recovery-codes/admin-reset），verify-step 换发 JWT（mfa_ts 刷新）同属写面——
// 导入事务全量替换 users 表，窗口内换发的会话可能基于被覆盖的用户行。
// 门只产生导入期 409，不构成 428 死锁（step-up 机制本体豁免的是「要求验码」，
// 不是「导入期拒绝写」）。

import (
	"fmt"
	"net/http"
	"testing"
)

// Given 已启用 MFA 的操作者 + 导入窗口开启。
// When verify-step 携有效动态码请求换发 JWT。
// Then 409 import_in_progress，且不换发 token（窗口内写被拒）。
func TestMFAVerifyStep_blockedDuringImportWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.JWTSecret = "test-secret"
	secret := seedMfaVerifyStepUser(t)
	router := mfaVerifyStepRouter(h, "jwt")

	closeWindow := beginImportWindowForTest(t)
	rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, currentTOTPCode(t, secret)))
	closeWindow()
	if rec.Code != http.StatusConflict {
		t.Fatalf("导入窗口内 verify-step status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}

	// 对照：窗口关闭后同一端点照常换发 JWT（门不是恒拒）。
	rec2 := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, currentTOTPCode(t, secret)))
	if rec2.Code != http.StatusOK {
		t.Fatalf("窗口关闭后 verify-step status=%d body=%s, want 200", rec2.Code, rec2.Body.String())
	}
}

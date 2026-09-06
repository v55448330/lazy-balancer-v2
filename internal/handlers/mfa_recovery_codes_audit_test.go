package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// S-8（2026-09-05 审计复核收窄）：恢复码重生成是纯会话门（2026-09 裁定）下
// 「旧码全部作废 + 明文下发 10 个登录可用凭证」的高敏动作（恢复码可在登录
// MFA 验证步消费），与同卡片禁用/重置 MFA 的留痕密度对齐——成功路径必须产生
// 审计事件（此前 AuditPolicySkip + handler 零 recordAudit，事后零痕）。
func TestMFARecoveryCodes_regeneratesWithAuditTrail(t *testing.T) {
	// Given：已启用 MFA 的用户
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled,mfa_recovery_codes) VALUES (1,'recycler','x','user',1,1,'[\"old-hash\"]')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// When：重生成恢复码
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/auth/mfa/recovery-codes", nil)
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)
	h.MFARecoveryCodes(ctx)

	// Then：请求成功且审计库留痕（动作「生成」/对象「恢复码」）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var events int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='生成' AND resource='恢复码'").Scan(&events); err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	if events == 0 {
		t.Fatal("recovery-codes regeneration produced no audit event（高敏动作须留痕）")
	}
}

package handlers

import (
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

func mfaActivateAuditCount(t *testing.T, detail string) int {
	t.Helper()
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='认证拒绝' AND resource='用户认证' AND detail LIKE ?`, "%"+detail+"%").Scan(&count); err != nil {
		t.Fatalf("query MFA activate audit: %v", err)
	}
	return count
}

func mfaActivateTestRouter(h *Handlers) *gin.Engine {
	router := mfaSetupTestRouter(h)
	router.POST("/auth/mfa/activate", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", "jwt")
		h.MFAActivate(c)
	})
	return router
}

func TestMFAActivate_rejectedAttemptsWriteAudit(t *testing.T) {
	t.Run("no pending secret", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedMfaSetupUser(t)
		router := mfaActivateTestRouter(h)
		response := postRaw(router, "/auth/mfa/activate", `{"code":"123456"}`)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
		}
		if got := mfaActivateAuditCount(t, "没有待激活"); got != 1 {
			t.Fatalf("audit rows=%d, want 1", got)
		}
	})

	t.Run("wrong code and invalidation", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedMfaSetupUser(t)
		if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_secret='junk',mfa_pending_fails=0 WHERE id=1`); err != nil {
			t.Fatal(err)
		}
		router := mfaActivateTestRouter(h)
		for attempt := 1; attempt <= 5; attempt++ {
			response := postRaw(router, "/auth/mfa/activate", `{"code":"000000"}`)
			wantStatus := http.StatusBadRequest
			if attempt == 5 {
				wantStatus = http.StatusUnauthorized
			}
			if response.Code != wantStatus {
				t.Fatalf("attempt=%d status=%d body=%s, want %d", attempt, response.Code, response.Body.String(), wantStatus)
			}
			if got := mfaActivateAuditCount(t, "验证码错误"); got != attempt {
				t.Fatalf("attempt=%d audit rows=%d, want %d", attempt, got, attempt)
			}
		}
		if got := mfaActivateAuditCount(t, "绑定已作废"); got != 1 {
			t.Fatalf("invalidation audit rows=%d, want 1", got)
		}
	})
}

func TestMFAActivate_storageFailuresWriteAuditAndLog(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(t *testing.T)
		code       func(t *testing.T) string
		wantDetail string
	}{
		{
			name: "pending read",
			prepare: func(t *testing.T) {
				if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_secret='junk' WHERE id=1; ALTER TABLE users DROP COLUMN mfa_pending_secret`); err != nil {
					t.Fatal(err)
				}
			},
			code:       func(t *testing.T) string { return "000000" },
			wantDetail: "验证服务故障",
		},
		{
			name: "failure counter write",
			prepare: func(t *testing.T) {
				if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_secret='junk',mfa_pending_fails=0 WHERE id=1;
					CREATE TRIGGER reject_pending_failure_count BEFORE UPDATE ON users
					WHEN NEW.mfa_pending_fails IS NOT OLD.mfa_pending_fails
					BEGIN SELECT RAISE(FAIL, 'counter write blocked'); END`); err != nil {
					t.Fatal(err)
				}
			},
			code:       func(t *testing.T) string { return "000000" },
			wantDetail: "记录 MFA 绑定失败次数",
		},
		{
			name: "activation write",
			prepare: func(t *testing.T) {
				if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_secret='JBSWY3DPEHPK3PXP',mfa_pending_fails=0 WHERE id=1;
					CREATE TRIGGER reject_mfa_activation BEFORE UPDATE ON users
					WHEN NEW.mfa_enabled=1 AND OLD.mfa_enabled=0
					BEGIN SELECT RAISE(FAIL, 'activation write blocked'); END`); err != nil {
					t.Fatal(err)
				}
			},
			code:       func(t *testing.T) string { return currentTOTPCode(t, "JBSWY3DPEHPK3PXP") },
			wantDetail: "激活",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedMfaSetupUser(t)
			tc.prepare(t)
			router := mfaActivateTestRouter(h)
			logs := captureLog(t)
			response := postRaw(router, "/auth/mfa/activate", `{"code":"`+tc.code(t)+`"}`)
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
			}
			if got := mfaActivateAuditCount(t, tc.wantDetail); got != 1 {
				t.Fatalf("audit rows=%d, want 1 containing %q", got, tc.wantDetail)
			}
			if !strings.Contains(logs.String(), "MFA") || !strings.Contains(logs.String(), "失败") {
				t.Fatalf("storage failure log=%q, want MFA failure detail", logs.String())
			}
		})
	}
}

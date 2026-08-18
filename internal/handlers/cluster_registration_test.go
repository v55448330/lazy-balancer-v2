package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestRegisterAuditField_truncates_and_strips_control_chars(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{name: "empty", input: "", want: ""},
		{name: "plain", input: "slave-a", want: "slave-a"},
		{name: "newline stripped", input: "node\nEVIL", want: "nodeEVIL"},
		{name: "control char stripped", input: "node\x01x", want: "nodex"},
		{name: "DEL stripped", input: "node\x7f", want: "node"},
		{name: "long truncated", input: strings.Repeat("x", 300), want: strings.Repeat("x", 128)},
		{name: "long multibyte valid utf8", input: strings.Repeat("中", 100), want: strings.Repeat("中", 42)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := registerAuditField(tt.input)
			if got != tt.want {
				t.Fatalf("registerAuditField(%q)=%q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRegisterClusterNode_rejects_oversized_body(t *testing.T) {
	// Given：超大注册请求体（>16KB）
	h := newBackupTestHandlers(t)
	bigName := strings.Repeat("x", 20<<10)
	body := fmt.Sprintf(`{"token":"t","name":%q,"ip_address":"10.0.0.1","port":8000}`, bigName)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	// When
	h.RegisterClusterNode(ctx)

	// Then：超限 body 必须被拒绝，且不得写入任何审计记录
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("oversized request must not write audit rows, got %d", count)
	}
}

func TestRegisterClusterNode_invalid_token_audit_detail_is_generic(t *testing.T) {
	// Given：无效令牌 + 攻击者注入的 name/ip（超长 + 换行）
	h := newBackupTestHandlers(t)
	attackerName := "evil-" + strings.Repeat("x", 200) + "\nINJECTED"
	body := fmt.Sprintf(`{"token":"definitely-invalid","name":%q,"ip_address":"10.0.0.1","port":8000}`, attackerName)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	// When
	h.RegisterClusterNode(ctx)

	// Then：401 且审计详情不含攻击者输入（R35-6/8）
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "注册令牌无效或已过期") {
		t.Fatalf("response must use generic message, got %s", recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE action='注册失败' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	if detail != "注册令牌无效" {
		t.Fatalf("audit detail=%q, want generic %q", detail, "注册令牌无效")
	}
	if strings.Contains(detail, attackerName) || strings.Contains(detail, "10.0.0.1") {
		t.Fatalf("audit detail must not contain attacker input: %q", detail)
	}
}

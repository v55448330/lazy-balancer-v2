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
	// Given：无效令牌 + 攻击者注入的 name/ip（换行注入；长度在 binding max=100
	// 之内——超长名现在由 binding 直接 400，见
	// TestRegisterClusterNode_rejectsOversizedName）
	h := newBackupTestHandlers(t)
	attackerName := "evil-" + strings.Repeat("x", 40) + "\nINJECTED"
	body := fmt.Sprintf(`{"token":"definitely-invalid","name":%q,"ip_address":"10.0.0.1","port":8000}`, attackerName)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	// When
	h.RegisterClusterNode(ctx)

	// Then：401 且审计详情不含攻击者输入
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

// （自 apikeys_current_test.go 迁回——本族为集群注册校验
// 主题，此前仅因共用 newBackupTestHandlers 夹具寄居于 API Key 文件。）
func TestRegisterClusterNodeRejectsInvalidAddressAndPort(t *testing.T) {
	h := newBackupTestHandlers(t)
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid IP", body: `{"token":"token","name":"node","ip_address":"not-an-ip","port":8000}`},
		{name: "negative port", body: `{"token":"token","name":"node","ip_address":"127.0.0.1","port":-1}`},
		{name: "port too large", body: `{"token":"token","name":"node","ip_address":"127.0.0.1","port":65536}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(tt.body))
			ctx.Request.Header.Set("Content-Type", "application/json")
			h.RegisterClusterNode(ctx)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
			}
		})
	}
}

// GET /cluster/register/:id/status 必须与同族机器端点（register/
// confirm/snapshot/waf-files/report）一致带主节点门——降级节点残留注册行
// 不得继续应答 approved/重发集群令牌。
func TestGetClusterRegistrationStatus_rejectsSlaveNode(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/cluster/register/:id/status", h.GetClusterRegistrationStatus)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/cluster/register/1/status", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403 (master-only)", recorder.Code, recorder.Body.String())
	}
}

// 注册状态轮询的 handler 级凭证拒绝必须留痕（与同族机器端点同口径）：
// 中间件验密后事务内复核仍可能拒（密钥轮换/到期），零审计会让残留凭证的
// 枚举尝试在取证面无痕。留痕经 middleware 注入的钩子（一分钟去重单源）。
func TestGetClusterRegistrationStatus_credentialRejectionInvokesAuditRecorder(t *testing.T) {
	h := newBackupTestHandlers(t)
	// pending 节点带注册密钥哈希——错误密钥在事务内复核被拒（ErrInvalidClusterAuth）。
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,registration_secret)
		VALUES (5,'pending-node','10.0.0.5',8000,'pending',0,'stored-secret-hash')`); err != nil {
		t.Fatal(err)
	}
	calls := 0
	old := registrationStatusRejectionRecorder
	registrationStatusRejectionRecorder = func(*gin.Context) { calls++ }
	t.Cleanup(func() { registrationStatusRejectionRecorder = old })

	router := gin.New()
	router.GET("/cluster/register/:id/status", func(c *gin.Context) {
		c.Set("registration_secret", "wrong-secret")
		h.GetClusterRegistrationStatus(c)
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/cluster/register/5/status", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
	}
	if calls != 1 {
		t.Fatalf("拒绝留痕钩子调用=%d, want 1（凭证拒绝必须进审计面）", calls)
	}
}

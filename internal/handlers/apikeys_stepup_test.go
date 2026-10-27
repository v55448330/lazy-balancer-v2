package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// API Key 更新面的特权变更（read_only→false / mcp_enabled→true）与创建侧同构
// 走 MFA step-up 判定：开关/状态读失败 fail-closed 500（创建侧同口径）；守卫
// 开启且操作者启用 MFA 时 428；守卫关闭直通。非特权变更不受此门影响。

// serveAPIKeyStatusUpdate 以 admin JWT 身份调用 UpdateAPIKeyStatus。
func serveAPIKeyStatusUpdate(h *Handlers, keyID, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/v1/api-keys/"+keyID+"/status", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: keyID}}
	ctx.Set("user_id", 1)
	ctx.Set("username", "admin")
	ctx.Set("role", "admin")
	ctx.Set("auth_type", "jwt")
	h.UpdateAPIKeyStatus(ctx)
	return rec
}

func seedAPIKeyForStepUp(t *testing.T, id int, readOnly, mcpEnabled int) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','x','admin',1)"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,is_enabled,read_only,mcp_enabled) VALUES (?,'k','h','p',1,1,?,?)", id, readOnly, mcpEnabled); err != nil {
		t.Fatalf("seed api key: %v", err)
	}
}

// 开关读失败时特权变更必须 fail-closed 500（与创建侧同口径）——此前更新面
// 根本不做 step-up 判定，开关读失败下特权授予静默放行。
func TestUpdateAPIKeyStatus_privilegeChangeFailsClosedWhenGuardUnreadable(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedAPIKeyForStepUp(t, 10, 1, 0)
	if _, err := db.DB.Exec("ALTER TABLE global_config RENAME COLUMN mfa_write_guard TO mfa_write_guard_unreadable"); err != nil {
		t.Fatalf("break guard switch column: %v", err)
	}

	if rec := serveAPIKeyStatusUpdate(h, "10", `{"read_only":false}`); rec.Code != http.StatusInternalServerError ||
		!strings.Contains(rec.Body.String(), "MFA 写操作验证开关读取失败") {
		t.Fatalf("read_only→false with unreadable guard: status=%d body=%s, want 500 fail-closed", rec.Code, rec.Body.String())
	}
	if rec := serveAPIKeyStatusUpdate(h, "10", `{"mcp_enabled":true}`); rec.Code != http.StatusInternalServerError ||
		!strings.Contains(rec.Body.String(), "MFA 写操作验证开关读取失败") {
		t.Fatalf("mcp_enabled→true with unreadable guard: status=%d body=%s, want 500 fail-closed", rec.Code, rec.Body.String())
	}
	// 开关不可读时特权不得已被变更（fail-closed 不发生半写）。
	var readOnly, mcpEnabled int
	if err := db.DB.QueryRow("SELECT COALESCE(read_only,0), COALESCE(mcp_enabled,0) FROM api_keys WHERE id=10").Scan(&readOnly, &mcpEnabled); err != nil {
		t.Fatal(err)
	}
	if readOnly != 1 || mcpEnabled != 0 {
		t.Fatalf("privilege must be unchanged after fail-closed: read_only=%d mcp_enabled=%d", readOnly, mcpEnabled)
	}

	// 非特权变更（启停）不经过 step-up 门——开关读失败不影响。
	if rec := serveAPIKeyStatusUpdate(h, "10", `{"is_enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("non-privilege toggle: status=%d body=%s, want 200（非特权变更不受 step-up 门影响）", rec.Code, rec.Body.String())
	}
}

// 守卫开启 + 操作者已启用 MFA + 无新鲜 mfa_ts → 特权变更 428（与创建侧同构）。
func TestUpdateAPIKeyStatus_privilegeChangeRequiresStepUp(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedAPIKeyForStepUp(t, 10, 1, 0)
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret='JBSWY3DPEHPK3PXP' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })

	if rec := serveAPIKeyStatusUpdate(h, "10", `{"read_only":false}`); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("read_only→false under guard: status=%d body=%s, want 428", rec.Code, rec.Body.String())
	}
	if rec := serveAPIKeyStatusUpdate(h, "10", `{"mcp_enabled":true}`); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("mcp_enabled→true under guard: status=%d body=%s, want 428", rec.Code, rec.Body.String())
	}
	// 同值/降权提交不触发 step-up：read_only 提交 true（库中已是 1）直通。
	if rec := serveAPIKeyStatusUpdate(h, "10", `{"read_only":true}`); rec.Code == http.StatusPreconditionRequired {
		t.Fatalf("read_only→true (no change) must not require step-up, got 428")
	}
}

func TestUpdateAPIKeyStatus_whitelistChangeFailsClosedWhenGuardUnreadable(t *testing.T) {
	for _, mcpEnabled := range []int{0, 1} {
		t.Run(fmt.Sprintf("mcp_enabled=%d", mcpEnabled), func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedAPIKeyForStepUp(t, 10, 1, mcpEnabled)
			const originalWhitelist = `["10.0.0.1/32"]`
			if _, err := db.DB.Exec("UPDATE api_keys SET mcp_ip_whitelist=? WHERE id=10", originalWhitelist); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec("ALTER TABLE global_config RENAME COLUMN mfa_write_guard TO mfa_write_guard_unreadable"); err != nil {
				t.Fatalf("break guard switch column: %v", err)
			}

			rec := serveAPIKeyStatusUpdate(h, "10", `{"mcp_ip_whitelist":["192.0.2.1"]}`)
			if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "MFA 写操作验证开关读取失败") {
				t.Fatalf("status=%d body=%s, want 500 fail-closed", rec.Code, rec.Body.String())
			}
			var enabled, readOnly, gotMCPEnabled int
			var whitelist string
			if err := db.DB.QueryRow("SELECT is_enabled,read_only,mcp_enabled,mcp_ip_whitelist FROM api_keys WHERE id=10").Scan(&enabled, &readOnly, &gotMCPEnabled, &whitelist); err != nil {
				t.Fatal(err)
			}
			if enabled != 1 || readOnly != 1 || gotMCPEnabled != mcpEnabled || whitelist != originalWhitelist {
				t.Fatalf("fail-closed 后 Key 被修改: enabled=%d read_only=%d mcp_enabled=%d whitelist=%q", enabled, readOnly, gotMCPEnabled, whitelist)
			}
		})
	}
}

func TestUpdateAPIKeyStatus_whitelistChangeRequiresStepUp(t *testing.T) {
	for _, mcpEnabled := range []int{0, 1} {
		t.Run(fmt.Sprintf("mcp_enabled=%d", mcpEnabled), func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedAPIKeyForStepUp(t, 10, 1, mcpEnabled)
			const originalWhitelist = `["10.0.0.1/32","192.0.2.1/32"]`
			if _, err := db.DB.Exec("UPDATE api_keys SET mcp_ip_whitelist=? WHERE id=10", originalWhitelist); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret='JBSWY3DPEHPK3PXP' WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			setMfaWriteGuard(t, true)

			// 收窄也是实际白名单变化，与放宽同样进入既有 step-up 集合。
			rec := serveAPIKeyStatusUpdate(h, "10", `{"mcp_ip_whitelist":["10.0.0.1"]}`)
			if rec.Code != http.StatusPreconditionRequired {
				t.Fatalf("status=%d body=%s, want 428", rec.Code, rec.Body.String())
			}
			var whitelist string
			if err := db.DB.QueryRow("SELECT mcp_ip_whitelist FROM api_keys WHERE id=10").Scan(&whitelist); err != nil {
				t.Fatal(err)
			}
			if whitelist != originalWhitelist {
				t.Fatalf("428 后白名单=%q, want 原值 %q", whitelist, originalWhitelist)
			}
		})
	}
}

func TestUpdateAPIKeyStatus_canonicalUnchangedWhitelistDoesNotRequireStepUp(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedAPIKeyForStepUp(t, 10, 1, 0)
	if _, err := db.DB.Exec("UPDATE api_keys SET mcp_ip_whitelist='[\"10.0.0.1/32\"]' WHERE id=10"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret='JBSWY3DPEHPK3PXP' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	setMfaWriteGuard(t, true)

	rec := serveAPIKeyStatusUpdate(h, "10", `{"mcp_ip_whitelist":["10.0.0.1"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("归一化同值不应触发 step-up: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// 守卫关闭（默认）时特权变更直通（回归形状：门不得做成恒拒）。
func TestUpdateAPIKeyStatus_privilegeChangePassesWhenGuardOff(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedAPIKeyForStepUp(t, 10, 1, 0)
	if rec := serveAPIKeyStatusUpdate(h, "10", `{"read_only":false}`); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	// 审计 delta 的布尔口径与创建侧/同族一致：boolOnOff（开/关），非 %t。
	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE action='更新' AND resource='API密钥' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if !strings.Contains(detail, "只读：开→关") {
		t.Fatalf("audit detail=%q, want 含「只读：开→关」（boolOnOff 同族口径，非 %%t）", detail)
	}
}

// 重新启用「启用后具备写/MCP 能力」的 Key 与「收回只读」对称，同走 step-up：
// 禁用→启用会恢复可写/MCP 可达性，属授予动作。
func TestUpdateAPIKeyStatus_enablingPrivilegedKeyRequiresStepUp(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','x','admin',1)"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// 两条禁用态 Key：可写（启用=授予）与只读（启用不构成特权变更）。
	if _, err := db.DB.Exec("INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,is_enabled,read_only,mcp_enabled) VALUES (11,'w','h11','p',1,0,0,0)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,is_enabled,read_only,mcp_enabled) VALUES (12,'r','h12','p',1,0,1,0)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret='JBSWY3DPEHPK3PXP' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })

	if rec := serveAPIKeyStatusUpdate(h, "11", `{"is_enabled":true}`); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("启用可写 Key 必须要求 step-up: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := serveAPIKeyStatusUpdate(h, "12", `{"is_enabled":true}`); rec.Code == http.StatusPreconditionRequired {
		t.Fatalf("启用只读 Key 不构成特权变更（不得 428）: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// 带外 NULL is_enabled 行：鉴权侧裸比较恒 401（运行期即未启用），而列表
// COALESCE 显示「启用」。更新侧 step-up 判据必须与鉴权侧同口径——否则
// 提交 {"is_enabled":true} 会把「恒 401 的可写 Key」真正激活却不要求 step-up。
func TestUpdateAPIKeyStatus_nullEnabledRowActivationRequiresStepUp(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','x','admin',1)"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// 可写（read_only=0）+ is_enabled IS NULL（仅带外改库/导入遗留可造出）。
	if _, err := db.DB.Exec("INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,is_enabled,read_only,mcp_enabled) VALUES (13,'n','h13','p',1,NULL,0,0)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret='JBSWY3DPEHPK3PXP' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })

	if rec := serveAPIKeyStatusUpdate(h, "13", `{"is_enabled":true}`); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("NULL→1 激活可写 Key 必须要求 step-up: status=%d body=%s", rec.Code, rec.Body.String())
	}
	// 拒绝时库内零改动（仍为 NULL——不是部分写）。
	var enabled sql.NullInt64
	if err := db.DB.QueryRow("SELECT is_enabled FROM api_keys WHERE id=13").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled.Valid {
		t.Fatalf("is_enabled=%v, want NULL（step-up 拒绝期间不得写入）", enabled.Int64)
	}
}

// 列表入口与创建/更新/删除三入口同形：缺认证上下文的调用必须 401，
// 不得退化为 created_by=0 的孤儿行查询。
func TestListCurrentUserAPIKeys_rejectsMissingAuthContext(t *testing.T) {
	h := newBackupTestHandlers(t)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/users/me/api-keys", nil)
	h.ListCurrentUserAPIKeys(ctx)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
}

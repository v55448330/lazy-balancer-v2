package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 导入受信代理引用复核：分类导入携带 security_ip_lists（名单表将被全量替换）且备份未携带
// trusted_proxy_range_refs（未选系统数据/Config 缺席或 Config 未含该键）时，
// 导入后 refs=live 值、名单=备份行集合——live refs 指向不在备份内的名单 id
// 即导入后悬空。锁内复核必须按备份名单 id 集合重验 live refs 并 400。
func TestRevalidateImportTrustedProxyRefsAgainstCarriedLists(t *testing.T) {
	newBackupTestHandlers(t)
	listID := seedIPListRow(t, "live-trusted-proxy", `[{"value":"203.0.113.0/24","remark":""}]`)
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs=? WHERE id=1`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatalf("seed live trusted proxy refs: %v", err)
	}

	// _txlock=immediate：每个复核用独立短事务，检查完立即 Rollback，
	// 否则前一事务持写锁导致后续 BeginTx busy_timeout。
	check := func(t *testing.T, backup *configBackup) error {
		tx, err := db.DB.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		return revalidateImportLiveDependencies(context.Background(), tx, backup, map[string]bool{"security_ip_lists": true})
	}

	// Given：备份携带名单表（替换后名单集合={99}），未携带 refs 键。
	carriedLists := map[string][]map[string]any{
		"security_ip_lists": {{"id": 99, "name": "carried", "entries": "[]"}},
	}

	// When/Then 1：Config==nil（未选系统数据）——live refs 悬空必须报错。
	backupNilConfig := &configBackup{Tables: carriedLists}
	if err := check(t, backupNilConfig); err == nil ||
		!strings.Contains(err.Error(), "受信代理引用的地址列表") {
		t.Fatalf("Config==nil 且名单表被替换：live refs 悬空必须拒绝，err=%v", err)
	}

	// When/Then 2：Config 非nil 但未携带 refs 键——同形缺口同门。
	backupNoRefsKey := &configBackup{Config: map[string]any{"timezone": "UTC"}, Tables: carriedLists}
	if err := check(t, backupNoRefsKey); err == nil ||
		!strings.Contains(err.Error(), "受信代理引用的地址列表") {
		t.Fatalf("Config 未携带 refs 键且名单表被替换：live refs 悬空必须拒绝，err=%v", err)
	}

	// 回归形状：备份名单集合包含被引用 id → 放行。
	backupOK := &configBackup{Tables: map[string][]map[string]any{
		"security_ip_lists": {{"id": listID, "name": "carried", "entries": "[]"}},
	}}
	if err := check(t, backupOK); err != nil {
		t.Fatalf("备份名单含被引用 id 不应被拒: %v", err)
	}

	// 回归形状：live refs 为空 → 放行。
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := check(t, backupNilConfig); err != nil {
		t.Fatalf("live refs 为空不应被拒: %v", err)
	}
}

// 导入拦截页引用复核：备份携带 lb_rules（引用阶段拦截页）且未携带 security_block_pages 时，
// 初检按锁外 live 页集合放行后、加锁前窗口内被引用页可被删除（live 删除守卫
// 只看 live 规则，看不到备份行的引用）。锁内必须按事务视图重验并 400。
func TestRevalidateImportStageBlockPagesCatchesWindowDeletion(t *testing.T) {
	newBackupTestHandlers(t)
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default) VALUES ('窗口删除页', '<html></html>', 0)`)
	if err != nil {
		t.Fatalf("seed block page: %v", err)
	}
	pageID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	tables := map[string][]map[string]any{
		"lb_rules": {{
			"caddy_id": "lb_win", "name": "win", "protocol": "http", "enabled": 1,
			"block_page_stage1_id": pageID, "block_page_stage1_status": 403,
			"block_page_stage3_id": pageID, "block_page_stage3_status": 503,
		}},
	}

	// 形状 1（回归）：页在事务视图内存在 → 放行。
	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := revalidateImportStageBlockPages(context.Background(), tx, tables); err != nil {
		tx.Rollback()
		t.Fatalf("页存在时不应被拒: %v", err)
	}
	// 形状 2：模拟初检→加锁窗口内删除被引用页 → 必须报错。
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM security_block_pages WHERE id=?`, pageID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := revalidateImportStageBlockPages(context.Background(), tx, tables); err == nil ||
		!strings.Contains(err.Error(), "拦截页不存在") {
		tx.Rollback()
		t.Fatalf("窗口内删除被引用拦截页必须拒绝，err=%v", err)
	}
	tx.Rollback()

	// 形状 3：page=0 但 status≠0 的配对门与初检同口径（无需删除页）。
	badPair := map[string][]map[string]any{
		"lb_rules": {{
			"caddy_id": "lb_pair", "name": "pair", "protocol": "http", "enabled": 1,
			"block_page_stage1_id": 0, "block_page_stage1_status": 403,
		}},
	}
	tx2, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback()
	if err := revalidateImportStageBlockPages(context.Background(), tx2, badPair); err == nil ||
		!strings.Contains(err.Error(), "需要先选择拦截页") {
		t.Fatalf("有码无页必须按初检同口径拒绝，err=%v", err)
	}

	// 形状 4：页表随备份携带时由初检按备份行解析，锁内复核不适用 → 放行。
	carriedTables := map[string][]map[string]any{"lb_rules": tables["lb_rules"], "security_block_pages": {}}
	if err := revalidateImportStageBlockPages(context.Background(), tx2, carriedTables); err != nil {
		t.Fatalf("页表随备份携带时锁内复核不适用: %v", err)
	}
}

// 导入窗口写门：用户/API 密钥写端点（users 与 api_keys 均在导入全量替代表清单内）
// 在导入会话窗口内必须 409 fast-fail——窗口内写入要么被全量替换静默覆盖，
// 要么阻塞至 busy_timeout 后 500。与节点写族同口径。
func TestUserAndAPIKeyWrites409DuringImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/users", h.CreateUser)
	router.PUT("/users/:id", h.UpdateUser)
	router.DELETE("/users/:id", h.DeleteUser)
	router.PUT("/users/:id/status", h.ToggleUserStatus)
	router.POST("/users/:id/reset-password", h.ResetUserPassword)
	// 创建路径的认证上下文守卫先于导入窗口门（与删除路径同形）——本用例的
	// 主题是导入窗口 fast-fail，故模拟认证中间件注入 user_id。
	router.POST("/api-keys", func(c *gin.Context) {
		c.Set("user_id", 1)
		h.CreateCurrentUserAPIKey(c)
	})
	router.DELETE("/api-keys/:id", h.DeleteAPIKey)
	router.PUT("/api-keys/:id/status", h.UpdateAPIKeyStatus)
	router.PUT("/users/current", h.UpdateCurrentUser)

	// 模拟导入会话进行中（configImportBusy 的事实源：窗口计数）。
	beginImportWindowForTest(t)

	calls := []struct{ method, path, body string }{
		{"POST", "/users", `{"username":"winuser","password":"Passw0rd!x","role":"user"}`},
		{"PUT", "/users/2", `{"display_name":"x"}`},
		{"DELETE", "/users/2", ""},
		{"PUT", "/users/2/status", `{"is_enabled":false}`},
		{"POST", "/users/2/reset-password", `{"password":"Passw0rd!x"}`},
		{"POST", "/api-keys", `{"name":"win-key"}`},
		{"DELETE", "/api-keys/1", ""},
		{"PUT", "/api-keys/1/status", `{"is_enabled":false}`},
		{"PUT", "/users/current", `{"display_name":"x"}`},
	}
	for _, call := range calls {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s %s status=%d body=%s, want 409（导入窗口内用户/密钥写端点必须 fast-fail）",
				call.method, call.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "配置导入进行中") {
			t.Fatalf("%s %s body=%s, want 配置导入进行中 文案", call.method, call.path, rec.Body.String())
		}
	}
}

// 导入窗口写门同族覆盖：MFA 五个写端点操作的 users 表 MFA 列同样在导入全量
// 替换清单内——窗口内写入会被静默覆盖（用户以为 MFA 已启用实被回滚）或阻塞至
// busy_timeout。与 users/apikeys 写端点同口径 409 fast-fail，且门须先于
// 参数解析与身份判定（MFAResetByAdmin 带路径参数也不例外）。
func TestMFAWrites409DuringImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/mfa/setup", h.MFASetup)
	router.POST("/auth/mfa/activate", h.MFAActivate)
	router.POST("/auth/mfa/disable", h.MFADisable)
	router.POST("/auth/mfa/recovery-codes", h.MFARecoveryCodes)
	router.POST("/users/:id/mfa/reset", h.MFAResetByAdmin)

	// 模拟导入会话进行中（configImportBusy 的事实源：窗口计数）。
	beginImportWindowForTest(t)

	calls := []struct{ method, path, body string }{
		{"POST", "/auth/mfa/setup", `{}`},
		{"POST", "/auth/mfa/activate", `{"code":"123456"}`},
		{"POST", "/auth/mfa/disable", `{"code":"123456"}`},
		{"POST", "/auth/mfa/recovery-codes", `{}`},
		{"POST", "/users/2/mfa/reset", `{}`},
	}
	for _, call := range calls {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s %s status=%d body=%s, want 409（导入窗口内 MFA 写端点必须 fast-fail）",
				call.method, call.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "配置导入进行中") {
			t.Fatalf("%s %s body=%s, want 配置导入进行中 文案", call.method, call.path, rec.Body.String())
		}
	}
}

// 对照：导入窗口外用户写端点照常处理（409 门不得做成恒拒）。
func TestUserWritesAllowedOutsideImportWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/users", h.CreateUser)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/users",
		strings.NewReader(`{"username":"outsideuser","password":"Passw0rd!x","role":"user"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusConflict {
		t.Fatalf("status=409, want 非冲突（导入窗口外必须放行）: %s", rec.Body.String())
	}
}

// 导入窗口写门同族覆盖（规则×5 与原始配置逃生口/手动重载/校验）：这些端点
// 只在 caddyOpMu 上排队，导入期间（可达分钟级）请求悬挂并在导入后按「导入后的
// 库」重新校验落库——客户端早已超时，语义漂移。与 settings/users 写端点同口径
// 409 fast-fail，且门先于请求体读取与取锁。
func TestRuleAndRawConfigWrites409DuringImport(t *testing.T) {
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", h.CreateRule)
	router.PUT("/rules/:caddy_id", h.UpdateRule)
	router.DELETE("/rules/:caddy_id", h.DeleteRule)
	router.POST("/rules/:caddy_id/enable", h.EnableRule)
	router.POST("/rules/:caddy_id/disable", h.DisableRule)
	router.POST("/rules/:caddy_id/duplicate", h.DuplicateRule)
	router.POST("/rules/batch-block-pages", h.BatchRuleBlockPages)
	router.POST("/config/reload", h.ReloadCaddy)
	router.POST("/config/validate", h.ValidateConfig)
	router.PUT("/caddy/config", h.PutCaddyConfig)

	beginImportWindowForTest(t)

	calls := []struct{ method, path, body string }{
		{"POST", "/rules", `{"name":"r","protocol":"http","listen_port":8080}`},
		{"PUT", "/rules/lb_x", `{"name":"r"}`},
		{"DELETE", "/rules/lb_x", ""},
		{"POST", "/rules/lb_x/enable", ""},
		{"POST", "/rules/lb_x/disable", ""},
		{"POST", "/rules/lb_x/duplicate", ""},
		{"POST", "/rules/batch-block-pages", `{"rule_ids":["lb_x"],"block_page_stage1_id":0,"block_page_stage1_status":0}`},
		{"POST", "/config/reload", ""},
		{"POST", "/config/validate", `{}`},
		{"PUT", "/caddy/config", `{"content":"{}"}`},
	}
	for _, call := range calls {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s %s status=%d body=%s, want 409（导入窗口内规则/原始配置写必须 fast-fail）",
				call.method, call.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "配置导入进行中") {
			t.Fatalf("%s %s body=%s, want 配置导入进行中 文案", call.method, call.path, rec.Body.String())
		}
	}
}

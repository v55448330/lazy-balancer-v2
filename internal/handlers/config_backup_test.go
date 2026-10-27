package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// adminAuthForTest 注入管理员认证上下文：UpdateUser 的管理语义门按
// 「role != admin」fail-closed，handler 级用例必须显式模拟已过认证中间件的
// 管理员请求，否则会命中非管理员自助限制。
func adminAuthForTest(router *gin.Engine) {
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "99")
		c.Set("role", "admin")
	})
}

func TestUpdateUser_rejects_invalid_id_and_body(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "invalid id", path: "/users/not-a-number", body: `{}`},
		{name: "invalid body", path: "/users/1", body: `{"role":`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name'), (99, 'backup-admin', 'x', 'admin', '')"); err != nil {
				t.Fatalf("seed user: %v", err)
			}
			router := gin.New()
			adminAuthForTest(router)
			router.PUT("/users/:id", h.UpdateUser)
			request := httptest.NewRequest(http.MethodPut, tt.path, strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")

			// When
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			assertUserState(t, "original", "admin", "Original Name", "original-hash")
		})
	}
}

func TestUpdateUser_preserves_omitted_display_name(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'setup-admin', 'x', 'admin', ''), (2, 'original', 'original-hash', 'admin', 'Original Name'), (99, 'backup-admin', 'x', 'admin', '')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	adminAuthForTest(router)
	router.PUT("/users/:id", h.UpdateUser)
	request := httptest.NewRequest(http.MethodPut, "/users/2", strings.NewReader(`{"role":"user"}`))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	assertUserStateByID(t, 2, "original", "user", "Original Name", "original-hash")
}

func TestUpdateUser_preserves_all_fields_when_password_rejected(t *testing.T) {
	// Given（bcrypt 只取前 72 字节；73 字符密码由 validatePasswordPolicy 的
	// 长度上限拒绝——绑定层只拦空值；拒绝路径不得产生任何部分写入）
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name'), (99, 'backup-admin', 'x', 'admin', '')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	adminAuthForTest(router)
	router.PUT("/users/:id", h.UpdateUser)
	body := `{"username":"changed","role":"user","display_name":"Changed Name","password":"` + strings.Repeat("p", 73) + `"}`
	request := httptest.NewRequest(http.MethodPut, "/users/1", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then（400 来自 validatePasswordPolicy 的长度上限；绑定层只拦空值，
	// 故此断言验证的是拒绝发生在写库之前）
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	assertUserState(t, "original", "admin", "Original Name", "original-hash")
}

func TestUpdateUser_preserves_all_fields_when_update_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name'), (99, 'backup-admin', 'x', 'admin', '')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (2, 'original2', 'original-hash', 'admin', 'Original Name') ON CONFLICT(id) DO NOTHING"); err != nil {
		t.Fatalf("seed target user: %v", err)
	}
	if _, err := db.DB.Exec("CREATE TRIGGER fail_user_role_update BEFORE UPDATE ON users WHEN NEW.role='user' BEGIN SELECT RAISE(ABORT,'role update failed'); END"); err != nil {
		t.Fatalf("create update failure trigger: %v", err)
	}
	router := gin.New()
	adminAuthForTest(router)
	router.PUT("/users/:id", h.UpdateUser)
	request := httptest.NewRequest(http.MethodPut, "/users/2", strings.NewReader(`{"username":"changed","role":"user","display_name":"Changed Name"}`))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	assertUserStateByID(t, 2, "original2", "admin", "Original Name", "original-hash")
}

func assertUserState(t *testing.T, username, role, displayName, passwordHash string) {
	t.Helper()
	assertUserStateByID(t, 1, username, role, displayName, passwordHash)
}

func assertUserStateByID(t *testing.T, id int, username, role, displayName, passwordHash string) {
	t.Helper()
	var gotUsername, gotRole, gotDisplayName, gotPasswordHash string
	if err := db.DB.QueryRow("SELECT username, role, COALESCE(display_name,''), password_hash FROM users WHERE id=?", id).Scan(&gotUsername, &gotRole, &gotDisplayName, &gotPasswordHash); err != nil {
		t.Fatalf("query user state: %v", err)
	}
	if gotUsername != username || gotRole != role || gotDisplayName != displayName || gotPasswordHash != passwordHash {
		t.Fatalf("user state=(%q,%q,%q,%q), want (%q,%q,%q,%q)", gotUsername, gotRole, gotDisplayName, gotPasswordHash, username, role, displayName, passwordHash)
	}
}

func newBackupTestHandlers(t *testing.T) *Handlers {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		// 提交后产物清理异步执行：先等在途清理结束，避免其访问已关闭的测试库
		// 或把审计写进下一个用例的库。
		waitImportCleanup()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 直换包级句柄必须同步复位 currentDB（SetDB
		// 契约见其注释）——否则后台循环/GetDB 继续持有已关闭的测试库句柄。
		db.SetDB(oldDB)
	})
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(fakeCaddy.Close)
	cfg := &config.Config{CaddyAdminURL: fakeCaddy.URL}
	return &Handlers{
		cfg:            cfg,
		caddyService:   services.NewCaddyService(fakeCaddy.URL),
		clusterService: services.NewClusterService(db.DB, ""),
	}
}

func TestImportConfigBackup_rejects_backup_without_enabled_admin_and_preserves_current_admin(t *testing.T) {
	tests := []struct {
		name  string
		users []map[string]any
	}{
		{name: "empty users", users: []map[string]any{}},
		{name: "users only", users: []map[string]any{{"id": 2, "username": "reader", "password_hash": "hash", "role": "user", "is_enabled": 1}}},
		{name: "all admins disabled", users: []map[string]any{{"id": 2, "username": "disabled-admin", "password_hash": "hash", "role": "admin", "is_enabled": false}}},
		// is_enabled 为 null 的管理员在归一（NULL→1，对齐 migrateUsersIsEnabledNotNull）
		// 后视为启用，不再属于「无启用管理员」拒绝场景——见
		// TestImportConfigBackup_normalizes_null_boolean_rows。
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)"); err != nil {
				t.Fatalf("seed current admin: %v", err)
			}
			router := gin.New()
			router.POST("/config/import", h.ImportConfigBackup)
			request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{"users": tt.users}, EmptyConfigIfNil: true})))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			var count int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='current-admin' AND role='admin' AND is_enabled=1").Scan(&count); err != nil {
				t.Fatalf("read current admin: %v", err)
			}
			if count != 1 {
				t.Fatalf("current enabled admin count=%d, want 1", count)
			}
		})
	}
}

func TestImportConfigBackup_accepts_enabled_admin_and_increments_password_version(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"users": {{"id": 7, "username": "enabled-admin", "password_hash": "hash", "role": "admin", "is_enabled": true, "password_version": 12}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var passwordVersion int
	if err := db.DB.QueryRow("SELECT password_version FROM users WHERE username='enabled-admin'").Scan(&passwordVersion); err != nil {
		t.Fatalf("read imported password version: %v", err)
	}
	if passwordVersion != 13 {
		t.Fatalf("password_version=%d, want 13", passwordVersion)
	}
}

func TestImportConfigBackup_normalizes_null_boolean_rows(t *testing.T) {
	// 库导出的全 null 管理员备份此前被
	// backupBooleanEnabled(nil)=false 先行 400 拦截，归一不可达；归一须在
	// checksum 之后、管理员校验之前执行：用户 is_enabled null→1、规则/上游
	// enabled null→0，导入成功且落库值正确。
	// Given
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"users":     {{"id": 2, "username": "null-admin", "password_hash": "hash", "role": "admin", "is_enabled": nil}},
		"lb_rules":  {{"caddy_id": "lb_nullnorm", "name": "null-rule", "protocol": "http", "domain": "nullnorm.example.test", "listen_port": 8080, "enabled": nil}},
		"upstreams": {{"rule_id": "lb_nullnorm", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": nil}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功且三表布尔列全部归一（用户→1、规则/上游→0）
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var userEnabled, ruleEnabled, upstreamEnabled int
	if err := db.DB.QueryRow("SELECT is_enabled FROM users WHERE username='null-admin'").Scan(&userEnabled); err != nil {
		t.Fatalf("read normalized user: %v", err)
	}
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_nullnorm'").Scan(&ruleEnabled); err != nil {
		t.Fatalf("read normalized rule: %v", err)
	}
	if err := db.DB.QueryRow("SELECT enabled FROM upstreams WHERE rule_id='lb_nullnorm'").Scan(&upstreamEnabled); err != nil {
		t.Fatalf("read normalized upstream: %v", err)
	}
	if userEnabled != 1 || ruleEnabled != 0 || upstreamEnabled != 0 {
		t.Fatalf("normalized booleans: user=%d rule=%d upstream=%d, want 1/0/0", userEnabled, ruleEnabled, upstreamEnabled)
	}
}

// v2 备份导入通道对三张安全表的可空列零归一——带校验和的备份
// 携带 content/action/score/description/custom_rules 等 NULL 时，restoreTable 原样
// 落库（下游 raw 消费方：caddy.go 拦截页 content 扫描、自定义规则生成扫描），而
// 集群快照 dump 侧（snapshotSecurityPolicies/snapshotSecurityCustomRules/
// snapshotSecurityBlockPages）已全量 COALESCE 硬化——两条
// 「全量替换」通道容忍度背离。导入必须成功（无 400/500），且落库值为 dump 侧对齐
// 默认值而非 NULL；NULL 布尔列（enabled/is_default）落 schema/dump 默认而非布尔强转。
// 自此 content NULL/空行被 skipEmptyBlockPages 软跳过（不再落库），
// content 归一断言相应改为非空内容原样落库。
func TestImportConfigBackup_normalizes_null_security_rows(t *testing.T) {
	// Given：三张安全表各携带一行 NULL 毒化可空列（content 给非空值以越过
	// 空内容软跳过门，保留 description/is_default NULL 归一覆盖）
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"security_block_pages": {{"id": 2, "name": "null-poison-page", "description": nil, "content": "<html>poison</html>", "is_default": nil}},
		"security_custom_rules": {{"id": 1, "name": "null-poison-rule",
			"conditions":  `[{"target":"uri","operator":"contains","pattern":"/nullpoison"}]`,
			"description": nil, "condition_logic": nil, "action": nil, "score": nil, "enabled": nil}},
		"security_policies": {{"id": 1, "name": "null-poison-policy", "description": nil, "custom_rules": nil}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功，三表落库值均为 dump 侧对齐默认值（非空 content 原样、
	// 'block' action、5 score、1 enabled、'' description、'[]' custom_rules、
	// 0 is_default），而非 NULL
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var pageContent, pageDesc string
	var pageDefault int
	if err := db.DB.QueryRow("SELECT content, description, is_default FROM security_block_pages WHERE id=2").Scan(&pageContent, &pageDesc, &pageDefault); err != nil {
		t.Fatalf("read restored block page: %v", err)
	}
	if pageContent != "<html>poison</html>" || pageDesc != "" || pageDefault != 0 {
		t.Fatalf("block page=(content:%q desc:%q is_default:%d), want (<html>poison</html> '' 0)", pageContent, pageDesc, pageDefault)
	}
	var ruleAction, ruleDesc, ruleLogic string
	var ruleScore, ruleEnabled int
	if err := db.DB.QueryRow("SELECT action, score, enabled, description, condition_logic FROM security_custom_rules WHERE id=1").Scan(&ruleAction, &ruleScore, &ruleEnabled, &ruleDesc, &ruleLogic); err != nil {
		t.Fatalf("read restored custom rule: %v", err)
	}
	if ruleAction != "block" || ruleScore != 5 || ruleEnabled != 1 || ruleDesc != "" || ruleLogic != "and" {
		t.Fatalf("custom rule=(action:%q score:%d enabled:%d desc:%q logic:%q), want ('block' 5 1 '' 'and')", ruleAction, ruleScore, ruleEnabled, ruleDesc, ruleLogic)
	}
	var policyDesc, policyCustomRules string
	if err := db.DB.QueryRow("SELECT description, custom_rules FROM security_policies WHERE id=1").Scan(&policyDesc, &policyCustomRules); err != nil {
		t.Fatalf("read restored policy: %v", err)
	}
	if policyDesc != "" || policyCustomRules != "[]" {
		t.Fatalf("policy=(description:%q custom_rules:%q), want ('' '[]')", policyDesc, policyCustomRules)
	}
}

// 空内容拦截页行软跳过——手造备份 content:""/纯空白 落库后，
// 引用该页的 WAF/GeoIP/限流拦截渲染空响应体，静默退化为 Caddy 原生 403。
// 校验期按 skipEmptyDomainHTTPRules 同款口径跳过该行并告警，其余行正常导入。
func TestImportConfigBackup_skips_empty_content_block_pages(t *testing.T) {
	// Given：两行空内容拦截页 + 一行正常页 + 一行无关表数据
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"security_block_pages": {
			{"id": 2, "name": "empty-page", "content": "", "is_default": 0},
			{"id": 3, "name": "blank-page", "content": "   ", "is_default": 0},
			{"id": 4, "name": "good-page", "content": "<html>blocked</html>", "is_default": 0},
		},
		"security_custom_rules": {
			{"id": 9, "name": "other-row", "conditions": `[{"target":"uri","operator":"contains","pattern":"/x"}]`, "enabled": 1},
		},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：导入成功，空内容页跳过、正常页与无关行落库，警告点名跳过行
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var keptContent string
	if err := db.DB.QueryRow("SELECT content FROM security_block_pages WHERE id=4").Scan(&keptContent); err != nil {
		t.Fatalf("read kept block page: %v", err)
	}
	if keptContent != "<html>blocked</html>" {
		t.Fatalf("kept page content=%q, want fixture content", keptContent)
	}
	var skippedCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE id IN (2,3)").Scan(&skippedCount); err != nil {
		t.Fatalf("count skipped pages: %v", err)
	}
	if skippedCount != 0 {
		t.Fatalf("empty-content pages imported: %d rows, want 0", skippedCount)
	}
	var otherRows int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_custom_rules WHERE id=9").Scan(&otherRows); err != nil {
		t.Fatalf("count unrelated rows: %v", err)
	}
	if otherRows != 1 {
		t.Fatal("unrelated rows must still be imported")
	}
	var envelope struct {
		Data struct {
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	joined := strings.Join(envelope.Data.Warnings, "；")
	if !strings.Contains(joined, "empty-page") || !strings.Contains(joined, "blank-page") {
		t.Fatalf("warnings=%v, want skips for empty-page and blank-page", envelope.Data.Warnings)
	}
}

func TestSkipEmptyBlockPages_clearsDanglingReferences(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_block_pages": {{"id": 2, "name": "empty-page", "content": ""}},
		"lb_rules":             {{"caddy_id": "lb_x", "block_page_stage1_id": 2, "block_page_stage1_status": 403, "block_page_stage3_id": 2, "block_page_stage3_status": 418}},
		"security_policies":    {{"id": 5, "block_page_id": 2}},
	}
	warnings := skipEmptyBlockPages(tables)
	if len(warnings) != 1 {
		t.Fatalf("warnings=%v, want one skip", warnings)
	}
	rule := tables["lb_rules"][0]
	if rule["block_page_stage1_id"] != 0 || rule["block_page_stage1_status"] != 0 || rule["block_page_stage3_id"] != 0 || rule["block_page_stage3_status"] != 0 {
		t.Fatalf("rule refs=%v, want cleared", rule)
	}
	if tables["security_policies"][0]["block_page_id"] != 0 {
		t.Fatalf("policy ref=%v, want cleared", tables["security_policies"][0])
	}
}

// 预览端与导入端同序软跳过——空内容拦截页在预览即告警，
// summary 计数反映跳后行集，不得预览静默、导入才跳。
func TestValidateConfigImport_reports_empty_content_block_page_skips(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"security_block_pages": {
			{"id": 2, "name": "empty-page", "content": "", "is_default": 0},
			{"id": 4, "name": "good-page", "content": "<html>blocked</html>", "is_default": 0},
		},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	var envelope struct {
		Data importValidateResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !envelope.Data.Valid {
		t.Fatalf("valid=%v error=%q, want valid backup", envelope.Data.Valid, envelope.Data.Error)
	}
	if len(envelope.Data.Warnings) == 0 || !strings.Contains(strings.Join(envelope.Data.Warnings, "；"), "empty-page") {
		t.Fatalf("warnings=%v, want empty-page skip warning", envelope.Data.Warnings)
	}
	if got := envelope.Data.Summary["security_block_pages"]; got != 1 {
		t.Fatalf("summary[security_block_pages]=%d, want 1（跳后行集）", got)
	}
}

func TestValidateConfigImport_rejects_dangling_rule_references(t *testing.T) {
	// 预览接口须与实际导入同序校验 upstreams/path_rules 引用存在性，
	// 否则悬挂引用备份在预览显示可导入、实际导入才 400。
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"upstreams": {{"rule_id": "lb_ghost_ref", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": 1}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：预览返回 Valid=false 且错误与导入路径一致
	var envelope struct {
		Data importValidateResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode validation response: %v", err)
	}
	if envelope.Data.Valid {
		t.Fatalf("validation accepted dangling reference: %s", response.Body.String())
	}
	if envelope.Data.Type != "v2" {
		t.Fatalf("validation type=%q, want v2", envelope.Data.Type)
	}
	if !strings.Contains(envelope.Data.Error, "引用了不存在的规则") {
		t.Fatalf("validation error=%q, want contains 引用了不存在的规则", envelope.Data.Error)
	}
}

func TestImportConfigBackup_rejects_invalid_certificate_job_status(t *testing.T) {
	tests := []struct {
		name   string
		status any
		want   string
	}{
		{name: "NULL status", status: nil, want: "证书任务状态不能为空"},
		{name: "status outside allowed set", status: "unknown", want: "无效的证书任务状态"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
				"cert_jobs": {{"id": 1, "rule_id": "lb_invalid", "domain": "invalid.example", "status": test.status}},
			}, EmptyConfigIfNil: true})

			router := gin.New()
			router.POST("/config/import", h.ImportConfigBackup)
			request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			// 仅断言 400 会被前置门（管理员门等）
			// 的 400 假通过——必须点名证书任务状态门。
			if !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("body=%s, want contains %q（不得被其他前置门假通过）", response.Body.String(), test.want)
			}
		})
	}
}

func TestConfigBackup_export_import_roundtrip(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES ('keep', 'hash', 'admin')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enabled) VALUES ('lb_bak1', 'backup-rule', 'http', 'backup.example.test', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO upstreams (rule_id, host, port, weight, enabled) VALUES ('lb_bak1', '127.0.0.1', 9000, 1, 1)"); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO api_keys (name, key_hash, key_prefix, created_by) VALUES ('ci', 'kh', 'lb_sk_x', 1)"); err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET log_level='debug', sync_interval=45 WHERE id=1"); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)

	// When: export
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))

	// Then(v2.3.0:导出恒 lbbak tar.gz)
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d", exportResponse.Code)
	}
	for header, expected := range map[string]string{
		"Cache-Control":          "no-store, private",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := exportResponse.Header().Get(header); got != expected {
			t.Fatalf("%s=%q, want %q", header, got, expected)
		}
	}
	if got := exportResponse.Header().Get("Content-Type"); got != "application/gzip" {
		t.Fatalf("Content-Type=%q, want application/gzip", got)
	}
	backupBytes := exportResponse.Body.Bytes()
	unpacked, err := parseLbbak(backupBytes)
	if err != nil || !strings.Contains(string(unpacked.ConfigJSON), "lazy-balancer-v2") {
		t.Fatalf("export lbbak unpack: %v", err)
	}
	backup := string(unpacked.ConfigJSON)

	// Given: destructive change
	if _, err := db.DB.Exec("DELETE FROM lb_rules; DELETE FROM users; UPDATE global_config SET log_level='error', sync_interval=10, cluster_version=99 WHERE id=1"); err != nil {
		t.Fatalf("destructive change: %v", err)
	}

	// When: import
	importResponse := httptest.NewRecorder()
	importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	importRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResponse, importRequest)

	// Then
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%.300s", importResponse.Code, importResponse.Body.String())
	}
	var userCount, ruleCount, keyCount int
	var logLevel string
	var syncInterval, clusterVersion int
	if err := db.DB.QueryRow("SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM lb_rules), (SELECT COUNT(*) FROM api_keys), log_level, sync_interval, cluster_version FROM global_config WHERE id=1").Scan(&userCount, &ruleCount, &keyCount, &logLevel, &syncInterval, &clusterVersion); err != nil {
		t.Fatalf("verify restored data: %v", err)
	}
	if userCount != 1 || ruleCount != 1 || keyCount != 1 {
		t.Fatalf("restored counts users=%d rules=%d keys=%d", userCount, ruleCount, keyCount)
	}
	if logLevel != "debug" || syncInterval != 45 {
		t.Fatalf("restored config log_level=%q sync_interval=%d", logLevel, syncInterval)
	}
	if clusterVersion == 99 {
		t.Fatal("cluster_version was overwritten by import")
	}
}

func TestConfigBackup_export_preserves_sensitive_columns(t *testing.T) {
	// Given：备份以完整恢复为目标——机器凭证与 TLS 私钥必须随导出走（用户裁决：
	// 导出即完整恢复，剥离会破坏备份意义），与密码/密钥哈希一并完整保留。
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	// 导入完整恢复会物化证书文件，certDir 指向临时目录
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	if _, err := db.DB.Exec(`INSERT INTO users (username, password_hash, role) VALUES ('keep', 'hash', 'admin')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// 完整导出的 tls_cert/tls_key 必须是合法 PEM：导入阶段 Caddy 会校验证书对，
	// 假 PEM 会在导入时被拒（此前剥离测试靠置空跳过校验才不需要真证书）。
	testCertPEM, testKeyPEM := selfSignedTestPair(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enabled, tls_cert, tls_key) VALUES ('lb_redact', 'redact', 'http', 'redact.example.test', 8080, 1, ?, ?)`, testCertPEM, testKeyPEM); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, enabled) VALUES ('lb_redact', '127.0.0.1', 9000, 1, 1)`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name, key_hash, key_prefix, created_by) VALUES ('ci', 'kh-secret', 'lb_sk_x', 1)`); err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO ca_providers (name, provider, directory_url, credentials) VALUES ('le2', 'zerossl', 'https://acme.test/dir2', '{"eab_kid":"ca-cred"}')`); err != nil {
		t.Fatalf("seed ca provider: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (name, dns_credentials) VALUES ('dnspod', '{"secret_id":"dns-cred","secret_key":"k"}')`); err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_cert='admin-cert', admin_tls_key='admin-key' WHERE id=1`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)

	// When: export
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))

	// Then：全部敏感列完整导出（备份 = 完整恢复）
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportResponse.Code, exportResponse.Body.String())
	}
	var backup configBackup
	if err := json.Unmarshal(unpackExportBody(t, exportResponse.Body.Bytes()), &backup); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	// ca_providers 含 Initialize 播种的默认行，按 name 定位种入行
	var seededCA map[string]any
	for _, row := range backup.Tables["ca_providers"] {
		if backupString(row["name"]) == "le2" {
			seededCA = row
		}
	}
	if seededCA == nil {
		t.Fatal("seeded ca_providers row not found in export")
	}
	// global_config.dns_credentials 是退役列（启动迁移删除该列）：读路径不回显、
	// 写路径已移除——导出必须不含该键（旧备份导入时同样跳过），否则不可见凭证
	// 会随每次备份外带。
	if _, present := backup.Config["dns_credentials"]; present {
		t.Fatal("export 携带遗留 global_config.dns_credentials（应剔除）")
	}
	intactChecks := []struct {
		got  string
		want string
		name string
	}{
		{backupString(backup.Config["admin_tls_cert"]), "admin-cert", "global_config.admin_tls_cert"},
		{backupString(backup.Config["admin_tls_key"]), "admin-key", "global_config.admin_tls_key"},
		{backupString(seededCA["credentials"]), `{"eab_kid":"ca-cred"}`, "ca_providers.credentials"},
		{backupString(backup.Tables["certificate_configs"][0]["dns_credentials"]), `{"secret_id":"dns-cred","secret_key":"k"}`, "certificate_configs.dns_credentials"},
		{backupString(backup.Tables["lb_rules"][0]["tls_cert"]), testCertPEM, "lb_rules.tls_cert"},
		{backupString(backup.Tables["lb_rules"][0]["tls_key"]), testKeyPEM, "lb_rules.tls_key"},
		{backupString(backup.Tables["users"][0]["password_hash"]), "hash", "users.password_hash"},
		{backupString(backup.Tables["api_keys"][0]["key_hash"]), "kh-secret", "api_keys.key_hash"},
	}
	for _, check := range intactChecks {
		if check.got != check.want {
			t.Fatalf("%s=%q, want %q (export must be complete)", check.name, check.got, check.want)
		}
	}

	// Given: destructive change, then import round-trip must fully restore
	if _, err := db.DB.Exec("DELETE FROM lb_rules; DELETE FROM users; DELETE FROM ca_providers; DELETE FROM certificate_configs; DELETE FROM api_keys"); err != nil {
		t.Fatalf("destructive change: %v", err)
	}
	importResponse := httptest.NewRecorder()
	importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(exportResponse.Body.String()))
	importRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResponse, importRequest)
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%.300s", importResponse.Code, importResponse.Body.String())
	}
	var restored string
	if err := db.DB.QueryRow(`SELECT tls_key FROM lb_rules WHERE caddy_id='lb_redact'`).Scan(&restored); err != nil || restored != testKeyPEM {
		t.Fatalf("tls_key after import=%q err=%v, want seeded key PEM restored", restored, err)
	}
}

// 导出携带版本表、导入跳过不落库（警告 + 0 行），与纯 JSON 导入跳过版本表同口径。
func TestConfigBackup_exportsVersionTablesAndImportSkips(t *testing.T) {
	// Given：CRS/IP2Region 版本表含 auto_update 偏好，导出前先写入非默认值
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES ('keep', 'hash', 'admin')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("INSERT OR REPLACE INTO security_crs_version (id, version, auto_update, update_status, next_update) VALUES (1, 'v4.14.0', 1, 'checking', '2099-01-01 00:00:00')"); err != nil {
		t.Fatalf("seed crs version: %v", err)
	}
	if _, err := db.DB.Exec("INSERT OR REPLACE INTO security_ip2region_version (id, version, auto_update, update_status, next_update) VALUES (1, 'v3.17.0', 0, 'downloading', '2099-06-06 06:06:06')"); err != nil {
		t.Fatalf("seed ip2region version: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)

	// When: export（默认全量 JSON，不含规则库数据文件）
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportResponse.Code, exportResponse.Body.String())
	}
	backup := string(unpackExportBody(t, exportResponse.Body.Bytes()))
	if !strings.Contains(backup, "v4.14.0") || !strings.Contains(backup, "v3.17.0") {
		t.Fatalf("exported backup must still carry version rows (for lbbak consumers)")
	}

	// Given: 清空两张版本表(证明导入不回填)
	if _, err := db.DB.Exec("DELETE FROM security_crs_version; DELETE FROM security_ip2region_version"); err != nil {
		t.Fatalf("wipe version tables: %v", err)
	}

	// When: import
	importResponse := httptest.NewRecorder()
	importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	importRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResponse, importRequest)

	// Then（2026-09-18 用户裁定改契约）：纯 JSON 备份不含规则库数据文件——
	// 版本表不落库（防记录与本地文件分叉），导入成功且响应带跳过警告。
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importResponse.Code, importResponse.Body.String())
	}
	var crsRows, ip2Rows int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_crs_version").Scan(&crsRows); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip2region_version").Scan(&ip2Rows); err != nil {
		t.Fatal(err)
	}
	if crsRows != 0 || ip2Rows != 0 {
		t.Fatalf("json import must skip waf version tables (crs=%d ip2=%d, want 0/0)", crsRows, ip2Rows)
	}
	if !strings.Contains(importResponse.Body.String(), "规则库数据文件") {
		t.Fatalf("body=%s, want skip warning", importResponse.Body.String())
	}
}

func TestImportConfigBackup_clamps_excessive_jwt_expiration(t *testing.T) {
	h := newBackupTestHandlers(t)
	completeTables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		completeTables[table] = []map[string]any{}
	}
	completeTables["users"] = []map[string]any{{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	importCfg := map[string]any{"jwt_expire_minutes": 999999}
	backupPayload := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-19T00:00:00Z"},
		Config: importCfg,
		Tables: completeTables,
	}
	backupPayload.Meta.Checksum = checksumBackupPayload(t, completeTables, importCfg)
	body, err := json.Marshal(backupPayload)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var expireMinutes int
	if err := db.DB.QueryRow("SELECT jwt_expire_minutes FROM global_config WHERE id=1").Scan(&expireMinutes); err != nil {
		t.Fatalf("read imported JWT expiration: %v", err)
	}
	if expireMinutes != 20 {
		t.Fatalf("jwt_expire_minutes=%d, want 20", expireMinutes)
	}
}

// 裁定：指标保留随日志保留，该键已迁移删除，旧备份含该键被忽略。
func TestImportConfigBackup_ignoresDeadMetricsRetentionDaysKey(t *testing.T) {
	for _, item := range []struct {
		name  string
		value any
	}{
		{name: "int value ignored", value: 100000000},
		{name: "zero value ignored", value: 0},
		{name: "invalid form ignored", value: "bogus"},
	} {
		t.Run(item.name, func(t *testing.T) {
			preserveApplicationLogLevel(t, "")
			// Given
			h := newBackupTestHandlers(t)
			completeTables := make(map[string][]map[string]any, len(configBackupTables))
			for _, table := range configBackupTables {
				completeTables[table] = []map[string]any{}
			}
			completeTables["users"] = []map[string]any{{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
			// 死键旁带一个真实键：导入被死键卡住时该键不会落库，断言才有判别力。
			importCfg := map[string]any{"metrics_retention_days": item.value, "log_level": "warn"}
			backupPayload := configBackup{
				Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-19T00:00:00Z"},
				Config: importCfg,
				Tables: completeTables,
			}
			backupPayload.Meta.Checksum = checksumBackupPayload(t, completeTables, importCfg)
			body, err := json.Marshal(backupPayload)
			if err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			router.POST("/config/import", h.ImportConfigBackup)

			// When
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(body)))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, request)

			// Then：导入成功（死键静默跳过，任何形态值不致导入失败）
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
			}
			// 死键被静默跳过，同包的正常键照常落库（表的列集合是 schema 事实，
			// 查 PRAGMA 恒真、无法发现导入路径回归）。
			var logLevel string
			if err := db.DB.QueryRow("SELECT COALESCE(log_level,'') FROM global_config WHERE id=1").Scan(&logLevel); err != nil {
				t.Fatalf("read imported log_level: %v", err)
			}
			if logLevel != "warn" {
				t.Fatalf("log_level=%q, want warn（死键不得阻断同包正常配置）", logLevel)
			}
		})
	}
}

func TestImportConfigBackup_remaps_rule_updated_by_to_restored_user(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"users":      {{"id": 7, "username": "importer", "password_hash": "hash", "role": "admin", "is_enabled": true, "password_version": 0}},
		"lb_rules":   {{"caddy_id": "lb_remap", "name": "remap", "protocol": "http", "domain": "remap.example.test", "listen_port": 8080, "enabled": true}},
		"upstreams":  {{"rule_id": "lb_remap", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": true}},
		"cert_jobs":  {},
		"api_keys":   {},
		"path_rules": {},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("username", "importer"); c.Next() })
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var updatedBy sql.NullInt64
	if err := db.DB.QueryRow("SELECT updated_by FROM lb_rules WHERE caddy_id='lb_remap'").Scan(&updatedBy); err != nil {
		t.Fatalf("read updated_by: %v", err)
	}
	if !updatedBy.Valid || updatedBy.Int64 != 7 {
		t.Fatalf("updated_by=%+v, want 7 (restored user id)", updatedBy)
	}
}

func TestImportConfigBackup_missingOperatorAccount_respectsChoice(t *testing.T) {
	// 2026-09-18 用户裁定:分类导入落地后,「备份不含操作者账户」不再是硬阻断
	// ——①用户可能只导入负载规则(users 表不动,操作者仍在);②即使勾了系统数据
	// 导致操作者被替换,也尊重用户选择——降级为响应 warning + 审计警告,导入照常。
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'operator-admin','hash','admin',1);
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,updated_by) VALUES ('lb_pre','pre','http','pre.example.test',8080,1,1);
		INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_pre','127.0.0.1',9000,1,1)`); err != nil {
		t.Fatalf("seed operator and rule: %v", err)
	}
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"users":     {{"id": 50, "username": "otheradmin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		"lb_rules":  {{"caddy_id": "lb_selflock", "name": "selflock", "protocol": "http", "domain": "selflock.example.test", "listen_port": 8082, "enabled": true, "updated_by": 50}},
		"upstreams": {{"rule_id": "lb_selflock", "host": "127.0.0.1", "port": 9001, "weight": 1, "enabled": true}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("username", "operator-admin"); c.Next() })
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功 + warning 提示操作者将被替换；备份数据照常入库
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "当前操作账户") {
		t.Fatalf("body=%s, want operator-account warning", response.Body.String())
	}
	var operatorCount, otherAdminCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='operator-admin'").Scan(&operatorCount); err != nil {
		t.Fatalf("read operator: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='otheradmin'").Scan(&otherAdminCount); err != nil {
		t.Fatalf("read backup admin: %v", err)
	}
	if operatorCount != 0 || otherAdminCount != 1 {
		t.Fatalf("users after import: operator=%d otheradmin=%d, want 0/1（已按备份替换）", operatorCount, otherAdminCount)
	}
	var selflockCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_selflock'").Scan(&selflockCount); err != nil {
		t.Fatalf("read imported rule: %v", err)
	}
	if selflockCount != 1 {
		t.Fatalf("lb_rules after import: selflock=%d, want 1（导入已应用）", selflockCount)
	}
}

func TestImportConfigBackup_preserves_backup_rule_attribution_without_operator_context(t *testing.T) {
	// 归属重映射仅在操作者存在时执行——无操作者上下文时，备份行自带的
	// updated_by 必须原样保留，不得写 NULL 抹掉全部规则归属（操作者非空但
	// 缺席备份的场景按 2026-09-18 裁定为 200 + warning，见上一用例）。
	// Given
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules":  {{"caddy_id": "lb_attr", "name": "attr", "protocol": "http", "domain": "attr.example.test", "listen_port": 8083, "enabled": true, "updated_by": 7}},
		"upstreams": {{"rule_id": "lb_attr", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": true}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功且备份归属保留（非 NULL）
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var updatedBy sql.NullInt64
	if err := db.DB.QueryRow("SELECT updated_by FROM lb_rules WHERE caddy_id='lb_attr'").Scan(&updatedBy); err != nil {
		t.Fatalf("read updated_by: %v", err)
	}
	if !updatedBy.Valid || updatedBy.Int64 != 7 {
		t.Fatalf("updated_by=%+v, want 7（备份归属保留，无 NULL 重映射）", updatedBy)
	}
}

func TestImportConfigBackup_accepts_historical_v1_core_tables(t *testing.T) {
	h := newBackupTestHandlers(t)
	body, err := json.Marshal(configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 1},
		Config: map[string]any{},
		Tables: map[string][]map[string]any{
			"lb_rules": {}, "upstreams": {}, "users": {{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}, "api_keys": {},
			"ca_providers": {}, "certificate_configs": {}, "cert_jobs": {},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want historical v1 import success", response.Code, response.Body.String())
	}
	// 落库终态（200 只证明请求被接受）：管理员行必须生效，空表不产生行。
	var admins, rules, keys int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username='admin' AND role='admin' AND COALESCE(is_enabled,0)=1`).Scan(&admins); err != nil {
		t.Fatal(err)
	}
	if admins != 1 {
		t.Fatalf("v1 导入后启用管理员数=%d, want 1", admins)
	}
	if err := db.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM lb_rules), (SELECT COUNT(*) FROM api_keys)`).Scan(&rules, &keys); err != nil {
		t.Fatal(err)
	}
	if rules != 0 || keys != 0 {
		t.Fatalf("v1 空表导入不得产生规则/密钥行: rules=%d keys=%d", rules, keys)
	}
	// 完整性披露：完全不含校验和的 v1 备份比「仅数据表校验和」的旧格式更弱，
	// 导入必须留审计警告（此前只有后者有披露）。
	var integrityWarnings int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='导入警告' AND resource='配置备份' AND detail LIKE '%不含完整性校验和%'`).Scan(&integrityWarnings); err != nil {
		t.Fatalf("read integrity audit: %v", err)
	}
	if integrityWarnings != 1 {
		t.Fatalf("无校验和 v1 备份的完整性警告=%d, want 1（导入须披露内容未经摘要校验）", integrityWarnings)
	}
	// 预览同一事实必须可见（只读路径不落审计，改由 warnings 披露）。
	preview := postValidateBytes(t, h, []byte(string(body)))
	if !preview.Valid {
		t.Fatalf("preview valid=false err=%s", preview.Error)
	}
	found := false
	for _, warning := range preview.Warnings {
		if strings.Contains(warning, "不含完整性校验和") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("preview warnings=%v, want 含「不含完整性校验和」披露", preview.Warnings)
	}
}

func TestImportConfigBackup_requeues_imported_non_terminal_certificate_jobs(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_requeue_v2','requeue','http','requeue.example.test',8080,1,1,'acme_dns');
		INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('admin','hash','admin',1);
		INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_requeue_v2','127.0.0.1',9000,1,1);
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES ('lb_requeue_v2','requeue.example.test','creating_order',999999)`); err != nil {
		t.Fatalf("seed non-terminal job: %v", err)
	}
	// 自此启用 acme_dns 规则须引用有效证书配置（备份内可解析），
	// 夹具补种子行并绑定，保持本用例的 requeue 语义不变。
	dnsResult, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('requeue-dns','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	dnsConfigID, err := dnsResult.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate config ID: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=? WHERE caddy_id='lb_requeue_v2'", dnsConfigID); err != nil {
		t.Fatalf("bind certificate config: %v", err)
	}
	block := make(chan struct{})
	acmeMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-block }))
	t.Cleanup(func() { close(block); services.GetCAQueueManager().PauseAndDrain(); acmeMock.Close() })
	// acme_email 与 CA 目录必须在导出之前配置：导入会用备份里的 global_config 覆盖
	// 当前值（f6977115 起 acme_email 随备份迁移），导出后再改会被旧值清掉。
	if _, err := db.DB.Exec("UPDATE ca_providers SET provider='letsencrypt', directory_url=? WHERE enabled=1", acmeMock.URL); err != nil {
		t.Fatalf("redirect ACME directory: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET acme_email='acme@example.test' WHERE id=1"); err != nil {
		t.Fatalf("set ACME email: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportResponse.Code, exportResponse.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(exportResponse.Body.String()))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_requeue_v2'").Scan(&status); err != nil {
		t.Fatalf("read recovered certificate job: %v", err)
	}
	if status != "queued" && status != "creating_account" {
		t.Fatalf("recovered certificate job status=%q, want queued or creating_account (pipeline active)", status)
	}
}

func TestImportConfigBackup_reports_partial_failure_when_certificate_job_recovery_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	if _, err := db.DB.Exec("INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('admin','hash','admin',1)"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(exportResponse.Body.String()))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then： 起配置已提交的部分失败回 200 + partial=true（不再是 500
	// ——前端按「已回滚」处理且不刷新会诱发重复导入）。
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "证书任务恢复失败") || !strings.Contains(response.Body.String(), "requeue failed") || !strings.Contains(response.Body.String(), `"partial":true`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// 部分成功响应里阶段描述只出现一次：协调器 Error() 自带
// 「导入部分失败（数据库已提交，证书任务恢复失败）：」前缀，直接拼 Error() 会让
// message 出现两遍同一句、warnings 再重复一遍——读者会当成两起失败。
func TestImportConfigBackup_partialFailureDescribesPhaseOnce(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	if _, err := db.DB.Exec("INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('admin','hash','admin',1)"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(exportResponse.Body.String()))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Message string `json:"message"`
		Data    struct {
			Warnings []string `json:"warnings"`
			Partial  bool     `json:"partial"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode partial response: %v", err)
	}
	if !payload.Data.Partial {
		t.Fatal("队列恢复失败必须标记 partial=true")
	}
	if got := strings.Count(payload.Message, "证书任务恢复失败"); got != 1 {
		t.Fatalf("message 阶段描述出现 %d 次, want 1: %s", got, payload.Message)
	}
	if strings.Contains(payload.Message, "导入部分失败") {
		t.Fatalf("message 残留协调器动作前缀（双前缀）: %s", payload.Message)
	}
	phaseWarnings := 0
	for _, warning := range payload.Data.Warnings {
		if !strings.Contains(warning, "证书任务恢复失败") {
			continue
		}
		phaseWarnings++
		if got := strings.Count(warning, "证书任务恢复失败"); got != 1 {
			t.Fatalf("warning 阶段描述出现 %d 次, want 1: %s", got, warning)
		}
		if strings.Contains(warning, "导入部分失败") {
			t.Fatalf("warning 残留协调器动作前缀（双前缀）: %s", warning)
		}
	}
	if phaseWarnings != 1 {
		t.Fatalf("携带阶段描述的 warning 条数=%d, want 1（不得重复说明同一失败面）", phaseWarnings)
	}
}

// 导入提交失败=结果不可判定：必须 500 + 「提交结果不确定」口径（不得宣称
// 已回滚），且操作审计留痕。提交入口经 commitTx 缝注入后该分支才可钉。
func TestImportConfigBackup_commitFailureReportsIndeterminate(t *testing.T) {
	h := newBackupTestHandlers(t)
	forceCommitFailure(t)
	rec := importBackupShared(h, t, buildBackup(t, backupFixtureOptions{FillAll: true, Tables: nil, Config: nil, Sections: nil, EmptyConfigIfNil: true}))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "提交结果不确定") {
		t.Fatalf("响应未表述提交结果不确定: %s", body)
	}
	if strings.Contains(body, "已回滚") {
		t.Fatalf("提交结果不可判定时不得宣称已回滚: %s", body)
	}
	var rows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='导入失败' AND resource='配置备份' AND detail LIKE '%提交结果不确定%'`).Scan(&rows); err != nil {
		t.Fatalf("统计导入失败审计: %v", err)
	}
	if rows == 0 {
		t.Fatal("提交不确定性必须落操作审计（否则用户只能看到一次失败响应）")
	}
}

// 提交成功后 queue 阶段失败不得跳过提交后收敛；响应仍报部分失败，
// 但任务日志缓存失效、哨兵清理等必须执行。
func TestImportConfigBackup_queueFailureStillRunsPostCommitConvergence(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	oldInvalidate := invalidateImportTaskLogCache
	invalidations := 0
	invalidateImportTaskLogCache = func() { invalidations++ }
	t.Cleanup(func() { invalidateImportTaskLogCache = oldInvalidate })

	rec := importBackupShared(h, t, buildBackup(t, backupFixtureOptions{FillAll: true, Tables: nil, Config: nil, Sections: nil, EmptyConfigIfNil: true}))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "证书任务恢复失败") || !strings.Contains(rec.Body.String(), `"partial":true`) {
		t.Fatalf("status=%d body=%s, want partial success (200+partial)", rec.Code, rec.Body.String())
	}
	if invalidations != 1 {
		t.Fatalf("post-commit convergence invalidations=%d, want 1 after queue failure", invalidations)
	}
}

func TestImportConfigBackup_joins_import_and_certificate_job_recovery_failures(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_bad_recovery", "name": "bad", "protocol": "http", "domain": "bad-recovery.example.test", "listen_port": 8443, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "invalid certificate") || !strings.Contains(response.Body.String(), "requeue failed") {
		t.Fatalf("status=%d body=%s, want joined failures", response.Code, response.Body.String())
	}
}

func TestConfigBackup_slave_mode_forbidden(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config/export", nil))

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("export on slave status = %d, want 403", response.Code)
	}
}

func TestDumpTable_uses_one_transaction_snapshot_across_tables(t *testing.T) {
	// Given
	_ = newBackupTestHandlers(t)
	if _, err := db.DB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatalf("enable WAL: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port) VALUES ('lb_snapshot', 'before', 'http', 8080); INSERT INTO upstreams (rule_id, host, port) VALUES ('lb_snapshot', 'old-host', 9000)"); err != nil {
		t.Fatalf("seed snapshot data: %v", err)
	}
	tx, err := db.DB.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer tx.Rollback()
	if _, err := dumpTable(context.Background(), tx, "lb_rules"); err != nil {
		t.Fatalf("read first table: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE upstreams SET host='new-host' WHERE rule_id='lb_snapshot'"); err != nil {
		t.Fatalf("concurrent update: %v", err)
	}

	// When
	upstreams, err := dumpTable(context.Background(), tx, "upstreams")

	// Then
	if err != nil {
		t.Fatalf("read second table: %v", err)
	}
	if len(upstreams) != 1 || upstreams[0]["host"] != "old-host" {
		t.Fatalf("upstream snapshot=%v, want old-host", upstreams)
	}
}

func TestConfigBackup_import_rejects_invalid_file(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(`{"meta":{"app":"other-app"},"tables":{}}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid backup status = %d, want 400", response.Code)
	}
	var body models.APIResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse error response: %v", err)
	}
	if body.Message == "" || !strings.Contains(body.Message, "Lazy Balancer") {
		t.Fatalf("error message = %q, want explicit v2 backup identity rejection", body.Message)
	}
}

// v2BackupBody 构造指定 meta/tables/config 的 v2 备份体并按 {tables,config}
// 重算 checksum（此前子例 body 缺 exported_at/checksum，全部在
// 完整性校验门首段早退，断言只看到「非 true」而未命中目标错误文案）。
func v2BackupBody(t *testing.T, version int, tables map[string][]map[string]any, cfg map[string]any) string {
	t.Helper()
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: version, ExportedAt: "2026-10-18T00:00:00Z"},
		Config: cfg,
		Tables: tables,
	}
	if tables != nil {
		backup.Meta.Checksum = checksumBackupPayload(t, tables, cfg)
	}
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal v2 backup: %v", err)
	}
	return string(data)
}

func v2FullTables() map[string][]map[string]any {
	tables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		tables[table] = []map[string]any{}
	}
	tables["users"] = []map[string]any{{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	return tables
}

func TestValidateConfigImport_rejects_v2_backup_missing_required_contract(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	tests := []struct {
		name       string
		body       string
		wantValid  bool
		wantErrSub string
	}{
		{name: "unsupported version", body: v2BackupBody(t, 4, map[string][]map[string]any{"lb_rules": {}}, nil), wantErrSub: "不支持的备份版本"},
		{name: "missing tables", body: v2BackupBody(t, 2, nil, nil), wantErrSub: "不是有效的 Lazy Balancer 备份文件"},
		// 分类导出（无 users 键）合法：本地用户保留，管理员门跳过。
		{name: "missing users 分类形态合法", body: v2BackupBody(t, 2, map[string][]map[string]any{"lb_rules": {}}, nil), wantValid: true},
		// users 键存在且为空数组=导入将清空全部账户 —— 硬拒。
		{name: "empty users", body: v2BackupBody(t, 2, map[string][]map[string]any{"users": {}}, nil), wantErrSub: "备份 users 表为空"},
		{name: "missing global config 分类形态合法", body: v2BackupBody(t, 2, v2FullTables(), nil), wantValid: true},
	}
	missingTable := v2FullTables()
	delete(missingTable, "cert_jobs")
	tests = append(tests, struct {
		name       string
		body       string
		wantValid  bool
		wantErrSub string
	}{name: "missing required table in full form", body: v2BackupBody(t, 2, missingTable, nil), wantErrSub: "备份缺少必需的数据表: cert_jobs"})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			validateRouterShared(h).ServeHTTP(response, request)

			// Then
			var envelope struct {
				Data importValidateResponse `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode validation response: %v", err)
			}
			if envelope.Data.Type != "v2" {
				t.Fatalf("validation type=%q, want v2", envelope.Data.Type)
			}
			if envelope.Data.Valid != tt.wantValid {
				t.Fatalf("validation valid=%v err=%q, want %v", envelope.Data.Valid, envelope.Data.Error, tt.wantValid)
			}
			if tt.wantErrSub != "" && !strings.Contains(envelope.Data.Error, tt.wantErrSub) {
				t.Fatalf("validation error=%q, want contains %q", envelope.Data.Error, tt.wantErrSub)
			}
		})
	}
}

func TestValidateV2Backup_credentials_must_be_json_object(t *testing.T) {
	tests := []struct {
		name        string
		caProvider  string
		caCred      string
		dnsCred     string
		dnsCase     bool
		wantErrText string
	}{
		{name: "ca_providers invalid", caProvider: "zerossl", caCred: "not-json", wantErrText: "凭证格式"},
		{name: "ca_providers valid object", caProvider: "zerossl", caCred: `{"eab_kid":"x"}`},
		{name: "letsencrypt credentials must be empty", caCred: `{"eab_kid":"x"}`, wantErrText: "凭证必须为空"},
		{name: "ca_providers empty object", caCred: `{}`},
		{name: "ca_providers empty string", caCred: ""},
		{name: "ca_providers array rejected", caProvider: "zerossl", caCred: `["a"]`, wantErrText: "凭证格式"},
		{name: "certificate_configs invalid", dnsCred: "not-json", dnsCase: true, wantErrText: "凭证格式"},
		{name: "certificate_configs valid object", dnsCred: `{"mode":"tencent","secret_id":"id","secret_key":"key"}`, dnsCase: true},
		{name: "certificate_configs empty object rejected by provider", dnsCred: `{}`, dnsCase: true, wantErrText: "凭证"},
		{name: "certificate_configs empty string legacy allowed", dnsCred: "", dnsCase: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caProvider := tt.caProvider
			if caProvider == "" {
				caProvider = "letsencrypt"
			}
			dnsCredentials := `{"mode":"tencent","secret_id":"id","secret_key":"key"}`
			if tt.dnsCase {
				dnsCredentials = tt.dnsCred
			}
			backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
				"ca_providers":        {{"credentials": tt.caCred, "provider": caProvider}},
				"certificate_configs": {{"dns_provider": "dnspod", "dns_credentials": dnsCredentials}},
			}, EmptyConfigIfNil: true})

			var b configBackup
			if err := json.Unmarshal([]byte(backup), &b); err != nil {
				t.Fatalf("unmarshal backup: %v", err)
			}

			_, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &b, importValidationOptions{})
			if tt.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("校验链 err=%v, want contains %q", err, tt.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("校验链 unexpected error: %v", err)
			}
		})
	}
}

// 备份行必须与保存侧同门——CA 并发/间隔上界及 DNS
// provider/专属凭证均不得绕过；合法上界与有效凭证保持回归。
func TestValidateV2Backup_caProviderLimitsAndDNSProviderContracts(t *testing.T) {
	validCA := func() map[string]any {
		return map[string]any{"provider": "letsencrypt", "credentials": "", "max_concurrent": 100, "min_interval_ms": 60000}
	}
	validDNS := func() map[string]any {
		return map[string]any{"dns_provider": "dnspod", "dns_credentials": `{"mode":"tencent","secret_id":"id","secret_key":"key"}`}
	}
	tests := []struct {
		name        string
		mutateCA    func(map[string]any)
		mutateDNS   func(map[string]any)
		wantErrText string
	}{
		{name: "valid upper boundaries"},
		{name: "max concurrent too high", mutateCA: func(row map[string]any) { row["max_concurrent"] = 101 }, wantErrText: "max_concurrent"},
		{name: "max concurrent malformed", mutateCA: func(row map[string]any) { row["max_concurrent"] = "100.5" }, wantErrText: "max_concurrent"},
		{name: "min interval too high", mutateCA: func(row map[string]any) { row["min_interval_ms"] = 60001 }, wantErrText: "min_interval_ms"},
		{name: "min interval negative", mutateCA: func(row map[string]any) { row["min_interval_ms"] = -1 }, wantErrText: "min_interval_ms"},
		{name: "max concurrent negative", mutateCA: func(row map[string]any) { row["max_concurrent"] = -1 }, wantErrText: "max_concurrent"},
		{name: "unknown DNS provider", mutateDNS: func(row map[string]any) { row["dns_provider"] = "evil" }, wantErrText: "DNS 提供商"},
		{name: "DNS provider credentials missing", mutateDNS: func(row map[string]any) { row["dns_credentials"] = `{}` }, wantErrText: "凭证"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caRow, dnsRow := validCA(), validDNS()
			if tt.mutateCA != nil {
				tt.mutateCA(caRow)
			}
			if tt.mutateDNS != nil {
				tt.mutateDNS(dnsRow)
			}
			backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
				"ca_providers":        {caRow},
				"certificate_configs": {dnsRow},
			}, EmptyConfigIfNil: true})

			var b configBackup
			if err := json.Unmarshal([]byte(backup), &b); err != nil {
				t.Fatal(err)
			}
			_, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &b, importValidationOptions{})
			if tt.wantErrText == "" && err != nil {
				t.Fatalf("valid backup rejected: %v", err)
			}
			if tt.wantErrText != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrText)) {
				t.Fatalf("err=%v, want contains %q", err, tt.wantErrText)
			}
		})
	}
}

// 导入的「未设置」口径必须与写侧（UpdateCAProvider）同源：max_concurrent=0 /
// min_interval_ms=0 在写侧归一为默认值，导入若原样落库，列表/集群快照会显示 0
// 而队列闸门按默认值执行——同一行两种口径。
func TestImportConfigBackup_normalizesCAProviderBounds(t *testing.T) {
	// Given：备份携带 0 值边界（等价「未设置」）
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"ca_providers": {{"id": 77, "name": "zero-bounds", "provider": "letsencrypt", "credentials": "",
			"max_concurrent": 0, "min_interval_ms": 0, "enabled": 1}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：落库值即默认值（与 DDL 默认/读侧归一同一数字）
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var maxConcurrent, minInterval int
	if err := db.DB.QueryRow("SELECT max_concurrent, min_interval_ms FROM ca_providers WHERE id=77").Scan(&maxConcurrent, &minInterval); err != nil {
		t.Fatalf("read imported provider: %v", err)
	}
	if maxConcurrent != 1 || minInterval != 2000 {
		t.Fatalf("imported bounds=(%d,%d), want (1,2000)——0 值必须在导入落库前归一", maxConcurrent, minInterval)
	}
}

// 收窄：legacy 空 provider/空凭证行保持放行；只有非空且
// 未知或必填缺失的形态才拒绝。
func TestValidateV2Backup_legacyEmptyProviderRowsAllowed(t *testing.T) {
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"ca_providers":        {{"id": 1, "provider": "", "credentials": ""}},
		"certificate_configs": {{"id": 1, "dns_provider": "", "dns_credentials": ""}},
	}, EmptyConfigIfNil: true})

	var b configBackup
	if err := json.Unmarshal([]byte(backup), &b); err != nil {
		t.Fatal(err)
	}
	if _, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &b, importValidationOptions{}); err != nil {
		t.Fatalf("legacy empty provider rows rejected: %v", err)
	}
}

func TestValidateV2Backup_rejects_self_loop_80_tls_redirect_rule(t *testing.T) {
	tests := []struct {
		name        string
		rule        map[string]any
		wantErrText string
	}{
		{
			name:        "80 端口 + TLS 跳转自环规则被拒",
			rule:        map[string]any{"caddy_id": "lb_backup_loop", "name": "备份自环", "protocol": "http", "domain": "loop.test", "listen_port": 80, "enable_tls": 1, "tls_http_redirect": 1, "tls_source": "manual", "tls_cert": "pem", "tls_key": "key"},
			wantErrText: "80 端口开启 TLS 跳转无意义",
		},
		{
			// 禁用规则不参与渲染（caddy.go WHERE enabled=1），
			// 自环组合无运行时影响；导出→导入往返不应因存量禁用行失败。
			name: "禁用状态的 80 端口 + TLS 跳转自环规则可导入",
			rule: map[string]any{"caddy_id": "lb_backup_loop_disabled", "name": "备份禁用自环", "protocol": "http", "domain": "loop.test", "listen_port": 80, "enable_tls": 1, "tls_http_redirect": 1, "enabled": 0},
		},
		{
			name: "443 端口 + TLS 跳转规则正常",
			rule: map[string]any{"caddy_id": "lb_backup_ok", "name": "备份正常", "protocol": "http", "domain": "ok.test", "listen_port": 443, "enable_tls": 1, "tls_http_redirect": 1, "tls_source": "manual", "tls_cert": "pem", "tls_key": "key"},
		},
		{
			name: "80 端口普通规则正常",
			rule: map[string]any{"caddy_id": "lb_backup_plain", "name": "备份普通", "protocol": "http", "domain": "plain.test", "listen_port": 80},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{"lb_rules": {tt.rule}}, EmptyConfigIfNil: true})
			var b configBackup
			if err := json.Unmarshal([]byte(backup), &b); err != nil {
				t.Fatalf("unmarshal backup: %v", err)
			}
			// 逐行/端口/特性门与 TLS 形态校验都在生产链内，无需测试侧串联。
			_, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &b, importValidationOptions{})
			if tt.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("validateV2Backup err=%v, want contains %q", err, tt.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateV2Backup unexpected error: %v", err)
			}
		})
	}
}

// v2 导入域名规范化门——通配/非法域名整包 400（用户裁决：系统
// 不支持通配符域名），合法域名钳回规范形式。
func TestValidateV2Backup_rejects_wildcard_domain(t *testing.T) {
	tests := []struct {
		name          string
		rule          map[string]any
		wantErrText   string
		wantCanonical string
	}{
		{
			name:        "通配域名被拒",
			rule:        map[string]any{"caddy_id": "lb_backup_wild", "name": "通配规则", "protocol": "http", "domain": "*.example.com", "listen_port": 80},
			wantErrText: "系统不支持通配符域名",
		},
		{
			name:        "多域名规则中单个通配条目使整行被拒",
			rule:        map[string]any{"caddy_id": "lb_backup_mix", "name": "混合规则", "protocol": "http", "domain": "a.test,*.b.test", "listen_port": 80},
			wantErrText: "系统不支持通配符域名",
		},
		{
			name:        "空 protocol 的通配域名同被拒（同口径）",
			rule:        map[string]any{"caddy_id": "lb_backup_noproto", "name": "空协议", "protocol": "", "domain": "*.c.test", "listen_port": 80},
			wantErrText: "系统不支持通配符域名",
		},
		{
			name:        "IP 形态域名被拒（CanonicalDomains 同门）",
			rule:        map[string]any{"caddy_id": "lb_backup_ip", "name": "IP域名", "protocol": "http", "domain": "127.0.0.1", "listen_port": 80},
			wantErrText: "系统不支持通配符域名",
		},
		{
			name:          "合法大写域名钳回规范形式",
			rule:          map[string]any{"caddy_id": "lb_backup_norm", "name": "规范化", "protocol": "http", "domain": " UPPER.test , upper.test ", "listen_port": 80},
			wantCanonical: "upper.test",
		},
		{
			name: "TCP 规则不受域名门影响",
			rule: map[string]any{"caddy_id": "lb_backup_tcp", "name": "TCP规则", "protocol": "tcp", "domain": "*.ignored.test", "listen_port": 3306},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{"lb_rules": {tt.rule}}, EmptyConfigIfNil: true})
			var b configBackup
			if err := json.Unmarshal([]byte(backup), &b); err != nil {
				t.Fatalf("unmarshal backup: %v", err)
			}
			// 同款链序：空域名 http 行先软跳过（返回跳过警告，非 error）。
			_ = skipEmptyDomainHTTPRules(b.Tables)
			err := validateV2BackupRules(b.Tables)
			if tt.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("validateV2BackupRules err=%v, want contains %q", err, tt.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateV2BackupRules unexpected error: %v", err)
			}
			if tt.wantCanonical != "" {
				got, _ := b.Tables["lb_rules"][0]["domain"].(string)
				if got != tt.wantCanonical {
					t.Fatalf("domain=%q, want canonical %q", got, tt.wantCanonical)
				}
			}
		})
	}
}

// v2 导入 ruleFeatureInput 补 EnableDnsServer/DnsServer——
// 此前两字面量恒零值，TCP 规则携带 dns_server/enable_dns_server 的脏行绕过
// validateRuleFeatures 的 门（保存侧 自此拒绝、协议切换零值化、
// 存量迁移已清空）原样落库成「永不生效且无告警」死配置。与保存侧同门禁：
// TCP+DNS 脏行整包 400；HTTP 规则携带合法 dns 字段（老备份正常形态）不受影响。
func TestValidateV2Backup_rejects_tcp_rule_with_dns_server(t *testing.T) {
	tests := []struct {
		name        string
		rule        map[string]any
		wantErrText string
	}{
		{
			name:        "TCP 规则携带 dns_server 脏行被拒",
			rule:        map[string]any{"caddy_id": "lb_backup_tcpdns", "name": "TCP-DNS", "protocol": "tcp", "listen_port": 3306, "dns_server": "8.8.8.8"},
			wantErrText: "TCP 规则不支持 DNS 服务发现配置",
		},
		{
			name:        "TCP 规则携带 enable_dns_server 脏行被拒",
			rule:        map[string]any{"caddy_id": "lb_backup_tcpdns2", "name": "TCP-DNS2", "protocol": "tcp", "listen_port": 3306, "enable_dns_server": 1},
			wantErrText: "TCP 规则不支持 DNS 服务发现配置",
		},
		{
			name: "TCP 规则无 DNS 字段正常导入（老备份口径）",
			rule: map[string]any{"caddy_id": "lb_backup_tcpplain", "name": "TCP", "protocol": "tcp", "listen_port": 3306},
		},
		{
			name: "HTTP 规则携带合法 dns_server 不受影响（老备份口径）",
			rule: map[string]any{"caddy_id": "lb_backup_httpdns", "name": "HTTP-DNS", "protocol": "http", "domain": "dns.test", "listen_port": 80, "enable_dns_server": 1, "dns_server": "8.8.8.8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{"lb_rules": {tt.rule}}, EmptyConfigIfNil: true})
			var b configBackup
			if err := json.Unmarshal([]byte(backup), &b); err != nil {
				t.Fatalf("unmarshal backup: %v", err)
			}
			// 与 TestValidateV2Backup_rejects_wildcard_domain 同链序。
			_ = skipEmptyDomainHTTPRules(b.Tables)
			err := validateV2BackupRules(b.Tables)
			if tt.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("validateV2BackupRules err=%v, want contains %q", err, tt.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateV2BackupRules unexpected error: %v", err)
			}
		})
	}
}

// v2 导入 upstreams.protocol 白名单——与保存侧 validateUpstreams 同口径，
// 防手造备份带入 http 规则 + 上游 "tls"（渲染侧明文 HTTP 打 TLS 端口，静默 502）。
func TestValidateBackupRuleReferences_rejects_bad_upstream_protocol(t *testing.T) {
	base := func(ruleProtocol string) map[string][]map[string]any {
		return map[string][]map[string]any{
			"lb_rules": {{"caddy_id": "lb_f2proto", "protocol": ruleProtocol}},
		}
	}
	tests := []struct {
		name        string
		ruleProto   string
		upstreamAny map[string]any
		wantErr     string
	}{
		{name: "http 规则上游 tls 被拒", ruleProto: "http", upstreamAny: map[string]any{"rule_id": "lb_f2proto", "protocol": "tls"}, wantErr: "HTTP 规则仅支持 http/https"},
		{name: "http 规则上游 tcp 被拒", ruleProto: "http", upstreamAny: map[string]any{"rule_id": "lb_f2proto", "protocol": "tcp"}, wantErr: "HTTP 规则仅支持 http/https"},
		{name: "http 规则上游 https 放行", ruleProto: "http", upstreamAny: map[string]any{"rule_id": "lb_f2proto", "protocol": "https"}},
		{name: "http 规则上游空协议放行", ruleProto: "http", upstreamAny: map[string]any{"rule_id": "lb_f2proto"}},
		{name: "tcp 规则上游 https 被拒", ruleProto: "tcp", upstreamAny: map[string]any{"rule_id": "lb_f2proto", "protocol": "https"}, wantErr: "TCP 规则仅支持 tcp/tls"},
		{name: "tcp 规则上游 http 被拒", ruleProto: "tcp", upstreamAny: map[string]any{"rule_id": "lb_f2proto", "protocol": "http"}, wantErr: "TCP 规则仅支持 tcp/tls"},
		{name: "tcp 规则上游 tls 放行", ruleProto: "tcp", upstreamAny: map[string]any{"rule_id": "lb_f2proto", "protocol": "tls"}},
		{name: "空 protocol 规则按保存侧口径走 tcp 白名单", ruleProto: "", upstreamAny: map[string]any{"rule_id": "lb_f2proto", "protocol": "http"}, wantErr: "TCP 规则仅支持 tcp/tls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tables := base(tt.ruleProto)
			tables["upstreams"] = []map[string]any{tt.upstreamAny}
			for _, row := range tables["upstreams"] {
				if _, ok := row["host"]; !ok {
					row["host"] = "127.0.0.1"
				}
				if _, ok := row["port"]; !ok {
					row["port"] = 9000
				}
				if _, ok := row["weight"]; !ok {
					row["weight"] = 1
				}
			}
			err := validateBackupRuleReferences(tables)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validateBackupRuleReferences err=%v, want contains %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateBackupRuleReferences unexpected error: %v", err)
			}
		})
	}
}

// 逐上游回源域名 + 健康检查域名（2026-10-10）备份侧形状校验——与保存侧
// validateRulePayloadBeforeSave 同口径：手造备份可经 restoreTable 直写绕过
// 保存侧校验，坏形状（CRLF/端口越界/模式错配）会原样落库进入渲染。
func TestValidateBackupRuleReferences_rejects_bad_origin_domain_and_health_check_host(t *testing.T) {
	base := func(rule map[string]any) map[string][]map[string]any {
		return map[string][]map[string]any{"lb_rules": {rule}}
	}
	rule := func(extra map[string]any) map[string]any {
		r := map[string]any{"caddy_id": "lb_origchk", "protocol": "http"}
		for k, v := range extra {
			r[k] = v
		}
		return r
	}
	tests := []struct {
		name        string
		rule        map[string]any
		upstreamAny map[string]any
		wantErr     string
	}{
		{name: "合法回源域名放行", rule: rule(nil), upstreamAny: map[string]any{"rule_id": "lb_origchk", "origin_domain": "origin.example.com"}},
		{name: "回源域名带端口被拒", rule: rule(nil), upstreamAny: map[string]any{"rule_id": "lb_origchk", "origin_domain": "origin.example.com:8443"}, wantErr: "回源域名"},
		{name: "空回源域名放行", rule: rule(nil), upstreamAny: map[string]any{"rule_id": "lb_origchk"}},
		{name: "回源域名端口越界被拒", rule: rule(nil), upstreamAny: map[string]any{"rule_id": "lb_origchk", "origin_domain": "origin.example.com:99999"}, wantErr: "回源域名"},
		{name: "回源域名 CRLF 被拒", rule: rule(nil), upstreamAny: map[string]any{"rule_id": "lb_origchk", "origin_domain": "evil.com\r\nX-Evil: 1"}, wantErr: "回源域名"},
		// TCP 规则的回源域名是死值：导入按「归一」处理（校验侧按清零后形态
		// 评估、写侧 normalizeRuleRowsForTransport 清零），而非整包拒收——
		// 否则带外残留会让实例自己导出的备份无法再次导入（备份自毒）。
		{name: "TCP 规则回源域名归一放行", rule: rule(map[string]any{"protocol": "tcp"}), upstreamAny: map[string]any{"rule_id": "lb_origchk", "origin_domain": "origin.example.com"}},
		{name: "动态上游规则回源域名被拒", rule: rule(map[string]any{"dynamic_dns": true}), upstreamAny: map[string]any{"rule_id": "lb_origchk", "origin_domain": "origin.example.com"}, wantErr: "动态上游"},
		{name: "合法健康检查域名放行", rule: rule(map[string]any{"health_check_host": "probe.example.com"})},
		{name: "健康检查域名带端口被拒", rule: rule(map[string]any{"health_check_host": "probe.example.com:8443"}), wantErr: "健康检查域名"},
		{name: "TCP 规则健康检查域名被拒", rule: rule(map[string]any{"protocol": "tcp", "health_check_host": "probe.example.com"}), wantErr: "仅 HTTP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tables := base(tt.rule)
			if tt.upstreamAny != nil {
				tables["upstreams"] = []map[string]any{tt.upstreamAny}
			}
			for _, row := range tables["upstreams"] {
				if _, ok := row["host"]; !ok {
					row["host"] = "127.0.0.1"
				}
				if _, ok := row["port"]; !ok {
					row["port"] = 9000
				}
				if _, ok := row["weight"]; !ok {
					row["weight"] = 1
				}
			}
			err := validateBackupRuleReferences(tables)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validateBackupRuleReferences err=%v, want contains %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateBackupRuleReferences unexpected error: %v", err)
			}
		})
	}
}

// （传播通道钳制）: v2 备份中 TCP + enable_tls=1 + 空证书的行被静默钳制
// 为关闭 TLS（不因存量形态拒绝整包导入）。
func TestValidateV2BackupTLSShape_clamps_tcp_stale_tls(t *testing.T) {
	rule := map[string]any{
		"caddy_id": "lb_tcp_stale", "name": "tcp-stale", "protocol": "tcp",
		"listen_port": 8465, "enabled": 1, "enable_tls": 1, "tls_source": "manual",
	}
	tables := map[string][]map[string]any{"lb_rules": {rule}}

	if err := validateV2BackupTLSShape(tables); err != nil {
		t.Fatalf("validateV2BackupTLSShape unexpected error: %v", err)
	}
	if v, ok := rule["enable_tls"].(int); !ok || v != 0 {
		t.Fatalf("enable_tls=%v (type %T), want clamped int 0", rule["enable_tls"], rule["enable_tls"])
	}
	if rule["tls_cert"] != "" || rule["tls_key"] != "" {
		t.Fatalf("tls_cert=%v tls_key=%v, want cleared", rule["tls_cert"], rule["tls_key"])
	}
}

func TestImportConfigBackup_rejects_invalid_credentials_json(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"ca_providers": {{"credentials": "not-json"}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "凭证格式") {
		t.Fatalf("import response missing credentials error: %s", response.Body.String())
	}
}

func TestImportConfigBackup_rolls_back_when_certificate_materialization_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES ('old-user', 'hash', 'admin')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_old', 'old-rule', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"users":    {{"id": 2, "username": "new-user", "password_hash": "hash", "role": "admin"}},
		"lb_rules": {{"caddy_id": "lb_badcert", "name": "new-rule", "protocol": "http", "listen_port": 8443, "enabled": 1, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var oldRules, newRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_old'").Scan(&oldRules); err != nil {
		t.Fatalf("count old rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_badcert'").Scan(&newRules); err != nil {
		t.Fatalf("count new rules: %v", err)
	}
	if oldRules != 1 || newRules != 0 {
		t.Fatalf("rules after failed import: old=%d new=%d", oldRules, newRules)
	}
}

func TestImportConfigBackup_skips_empty_domain_HTTP_rules(t *testing.T) {
	// Given：v2 备份中一条 HTTP 规则域名为空，一条 HTTP 规则正常，一条 TCP 规则无域名
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_empty_domain", "name": "empty-domain", "protocol": "http", "domain": "", "listen_port": 8441, "enabled": 1},
			{"caddy_id": "lb_valid", "name": "valid", "protocol": "http", "domain": "valid.example.test", "listen_port": 8442, "enabled": 1},
			{"caddy_id": "lb_tcp", "name": "tcp", "protocol": "tcp", "listen_port": 8443, "enabled": 1},
		},
		"upstreams": {
			{"rule_id": "lb_empty_domain", "host": "127.0.0.1", "port": 9001, "weight": 1, "enabled": 1},
			{"rule_id": "lb_valid", "host": "127.0.0.1", "port": 9002, "weight": 1, "enabled": 1},
			{"rule_id": "lb_tcp", "host": "127.0.0.1", "port": 9003, "weight": 1, "enabled": 1},
		},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：空域名 HTTP 规则及其上游跳过并告警，其余规则正常导入
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "域名为空") {
		t.Fatalf("import response missing skip warning: %s", response.Body.String())
	}
	var skippedRules, importedRules, orphanUpstreams int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_empty_domain'").Scan(&skippedRules); err != nil {
		t.Fatalf("count skipped rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id IN ('lb_valid','lb_tcp')").Scan(&importedRules); err != nil {
		t.Fatalf("count imported rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM upstreams WHERE rule_id='lb_empty_domain'").Scan(&orphanUpstreams); err != nil {
		t.Fatalf("count orphan upstreams: %v", err)
	}
	if skippedRules != 0 || importedRules != 2 || orphanUpstreams != 0 {
		t.Fatalf("after import: skipped=%d imported=%d orphan-upstreams=%d, want 0/2/0", skippedRules, importedRules, orphanUpstreams)
	}
}

func TestImportConfigBackup_restores_partial_certificate_materialization(t *testing.T) {
	// Given
	harness := newImportRollbackHarness(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES ('old-user', 'hash', 'admin')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_old_partial', 'old-rule', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	const firstRuleID = "lb_partial_valid"
	const oldCert = "certificate-before-import"
	const oldKey = "key-before-import"
	if err := services.WriteCertFiles(firstRuleID, oldCert, oldKey); err != nil {
		t.Fatalf("seed certificate files: %v", err)
	}
	validCert, validKey, err := generateTestCert("partial.example.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("generate valid certificate: %v", err)
	}
	backup, err := json.Marshal(configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 1},
		Config: map[string]any{},
		Tables: map[string][]map[string]any{
			"upstreams": {}, "path_rules": {}, "api_keys": {}, "ca_providers": {}, "certificate_configs": {}, "cert_jobs": {},
			"users": {{"id": 2, "username": "new-user", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
			"lb_rules": {
				{"caddy_id": firstRuleID, "name": "first-rule", "protocol": "http", "domain": "partial.example.test", "listen_port": 8443, "enabled": 1, "enable_tls": 1, "tls_source": "manual", "tls_cert": validCert, "tls_key": validKey},
				{"caddy_id": "lb_partial_invalid", "name": "second-rule", "protocol": "http", "domain": "invalid.example.test", "listen_port": 9443, "enabled": 1, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	router := gin.New()
	router.POST("/config/import", harness.handler.ImportConfigBackup)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(backup)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var oldRules, importedRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_old_partial'").Scan(&oldRules); err != nil {
		t.Fatalf("count old rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id IN ('lb_partial_valid','lb_partial_invalid')").Scan(&importedRules); err != nil {
		t.Fatalf("count imported rules: %v", err)
	}
	if oldRules != 1 || importedRules != 0 {
		t.Fatalf("rules after failed import: old=%d imported=%d", oldRules, importedRules)
	}
	certPath, keyPath := services.CertFilePaths(firstRuleID)
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read restored certificate: %v", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read restored key: %v", err)
	}
	if string(cert) != oldCert || string(key) != oldKey {
		t.Fatalf("restored certificate pair=(%q,%q), want (%q,%q)", cert, key, oldCert, oldKey)
	}
	// loads=0：restore 目标=导入前快照=当前运行配置（导入在证书验证阶段失败、
	// 从未触达 /load）——同字节短路跳过恢复 /load（2026-09-25 审计真实性改造），
	// 运行态本就在 before-import，恢复为成功空操作。
	if harness.loadCalls() != 0 || harness.currentConfig() != `{"marker":"before-import"}` {
		t.Fatalf("Caddy loads=%d config=%s, want 恢复为空操作（同字节短路）且运行态保持 before-import", harness.loadCalls(), harness.currentConfig())
	}
}

func TestImportConfigBackup_reports_import_and_runtime_restore_failures(t *testing.T) {
	// Given
	harness := newImportRollbackHarness(t)
	harness.failRestore()
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_bad_restore", "name": "bad-cert", "protocol": "http", "domain": "bad-restore.example.test", "listen_port": 8443, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"}},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", harness.handler.ImportConfigBackup)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	body := response.Body.String()
	if response.Code != http.StatusInternalServerError || !strings.Contains(body, "invalid certificate") || !strings.Contains(body, "restore rejected") {
		t.Fatalf("status=%d body=%s, want joined import and restore errors", response.Code, body)
	}
	if strings.Contains(body, "已回滚") {
		t.Fatalf("response falsely claims rollback success: %s", body)
	}
}

// selfSignedTestPair 生成一对合法自签证书 PEM，供需要通过 Caddy 证书校验的测试种子使用。
func selfSignedTestPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"redact.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certBuf := &bytes.Buffer{}
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyBuf := &bytes.Buffer{}
	if err := pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatal(err)
	}
	return certBuf.String(), keyBuf.String()
}

func TestImportConfigBackup_normalizesNullEnabled(t *testing.T) {
	// Given：库导出的备份含 "enabled":null 的行（自此两表 NOT NULL，
	// 原值插入会触发约束失败整包回滚）
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)"); err != nil {
		t.Fatalf("seed current admin: %v", err)
	}
	ruleRow := map[string]any{
		"caddy_id": "lb_null_enabled", "name": "null-enabled", "protocol": "http",
		"domain": "null.example.test", "listen_port": 8080, "strategy": "weighted_round_robin", "enabled": nil,
	}
	upstreamRow := map[string]any{
		"rule_id": "lb_null_enabled", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": nil, "protocol": "http",
	}
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules":  {ruleRow},
		"upstreams": {upstreamRow},
	}, EmptyConfigIfNil: true})))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功且 NULL 归一为 0
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var ruleEnabled, upstreamEnabled int
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_null_enabled'").Scan(&ruleEnabled); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if err := db.DB.QueryRow("SELECT enabled FROM upstreams WHERE rule_id='lb_null_enabled'").Scan(&upstreamEnabled); err != nil {
		t.Fatalf("read upstream: %v", err)
	}
	if ruleEnabled != 0 || upstreamEnabled != 0 {
		t.Fatalf("rule.enabled=%d upstream.enabled=%d, want both 0 (null normalized)", ruleEnabled, upstreamEnabled)
	}
}

// 库的 users.is_enabled 为可空列，旧实例导出的
// "is_enabled":null 行导入 + 库会触发约束失败整包回滚；归一为 1（与
// lb_rules/upstreams 的 NULL→0 不同，对齐 migrateUsersIsEnabledNotNull 口径）。
func TestImportConfigBackup_normalizesNullUserIsEnabled(t *testing.T) {
	// Given：备份含一个 is_enabled:null 用户行+ 一个启用 admin
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"users": {
			{"id": 2, "username": "legacy-null", "password_hash": "hash", "role": "user", "is_enabled": nil},
			{"id": 3, "username": "enabled-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1},
		},
	}, EmptyConfigIfNil: true})))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功且 NULL 行落 1
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var isEnabled int
	if err := db.DB.QueryRow("SELECT is_enabled FROM users WHERE username='legacy-null'").Scan(&isEnabled); err != nil {
		t.Fatalf("read legacy user: %v", err)
	}
	if isEnabled != 1 {
		t.Fatalf("legacy user is_enabled=%d, want 1 (null normalized)", isEnabled)
	}
}

// skipEmptyDomainHTTPRules 必须先于逐行校验——空域名行无论端口是否非法
// 都一律软跳过并告警；非空域名+非法端口行仍整包 400。
func TestImportConfigBackup_skips_empty_domain_rule_before_row_validation(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	importFn := func(backup string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	t.Run("空域名+非法端口行软跳过并告警", func(t *testing.T) {
		backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
			"lb_rules": {
				{"caddy_id": "lb_empty_badport", "name": "empty-bad-port", "protocol": "http", "domain": "", "listen_port": 0, "enabled": 1},
				{"caddy_id": "lb_valid", "name": "valid", "protocol": "http", "domain": "valid.example.test", "listen_port": 8442, "enabled": 1},
			},
			"upstreams": {
				{"rule_id": "lb_empty_badport", "host": "127.0.0.1", "port": 9001, "weight": 1, "enabled": 1},
				{"rule_id": "lb_valid", "host": "127.0.0.1", "port": 9002, "weight": 1, "enabled": 1},
			},
		}, EmptyConfigIfNil: true})

		response := importFn(backup)
		if response.Code != http.StatusOK {
			t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), "域名为空") {
			t.Fatalf("import response missing skip warning: %s", response.Body.String())
		}
		var skipped, imported int
		if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_empty_badport'").Scan(&skipped); err != nil {
			t.Fatalf("count skipped rules: %v", err)
		}
		if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_valid'").Scan(&imported); err != nil {
			t.Fatalf("count imported rules: %v", err)
		}
		if skipped != 0 || imported != 1 {
			t.Fatalf("rules after import: skipped=%d imported=%d, want skipped=0 imported=1", skipped, imported)
		}
	})

	t.Run("非空域名+非法端口行仍整包 400", func(t *testing.T) {
		backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
			"lb_rules": {{"caddy_id": "lb_badport", "name": "bad-port", "protocol": "http", "domain": "badport.example.test", "listen_port": 0, "enabled": 1}},
		}, EmptyConfigIfNil: true})

		response := importFn(backup)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "1-65535") {
			t.Fatalf("status=%d body=%s, want 400 invalid port", response.Code, response.Body.String())
		}
	})
}

// 空域名 HTTP 规则的关联 cert_jobs 必须先随规则软跳过，
// 再执行状态门；非跳过规则的非法状态仍必须拒绝。
func TestConfigBackup_emptyDomainRuleSkipsCertJobBeforeStatusGate(t *testing.T) {
	backupWithJob := func(ruleDomain, status string) string {
		return buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
			"lb_rules":  {{"caddy_id": "lb_job_skip", "name": "job-skip", "protocol": "http", "domain": ruleDomain, "listen_port": 8442, "enabled": 1}},
			"cert_jobs": {{"rule_id": "lb_job_skip", "domain": ruleDomain, "status": status}},
		}, EmptyConfigIfNil: true})

	}
	t.Run("preview skips associated invalid job", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		result := postValidateBytes(t, h, []byte(backupWithJob("", "not-a-status")))
		if !result.Valid {
			t.Fatalf("preview valid=false error=%q, want soft skip", result.Error)
		}
	})
	t.Run("import skips associated invalid job", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		router := gin.New()
		router.POST("/config/import", h.ImportConfigBackup)
		request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backupWithJob("", "not-a-status")))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200 soft skip", response.Code, response.Body.String())
		}
		var jobs int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_job_skip'`).Scan(&jobs); err != nil {
			t.Fatal(err)
		}
		if jobs != 0 {
			t.Fatalf("skipped rule left %d cert jobs", jobs)
		}
	})
	t.Run("invalid status on retained rule still rejected", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		result := postValidateBytes(t, h, []byte(backupWithJob("valid.example.test", "not-a-status")))
		if result.Valid || !strings.Contains(result.Error, "无效的证书任务状态") {
			t.Fatalf("preview=%+v, want invalid status rejection", result)
		}
	})
}

// Config backup export → import round-trip preserves multi-row
// security_policy_bindings (one rule → multiple policies).
// validation passes and policy_id ordering is queryable via the same SELECT
// the runtime uses (ORDER BY policy_id ASC).
func TestConfigBackup_multiRowBindingsRoundTrip(t *testing.T) {
	// Given: a primary with policies 1-5, three rules, and multi-row bindings:
	//   lb_multi → policies {1, 3, 5}
	//   lb_single → policy {1}
	//   lb_none → no bindings
	// Policies 2 and 4 exist but are unbound.
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO users (username, password_hash, role) VALUES ('keep', 'hash', 'admin')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES
		('lb_multi','multi','http','multi.example.com',80,1),
		('lb_single','single','http','single.example.com',81,1),
		('lb_none','none','http','none.example.com',82,1)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES
		('lb_multi','127.0.0.1',9000,1),
		('lb_single','127.0.0.1',9001,1),
		('lb_none','127.0.0.1',9002,1)`); err != nil {
		t.Fatalf("seed upstreams: %v", err)
	}
	for _, id := range []int{1, 2, 3, 4, 5} {
		if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (?,?,'blocking',1)`, id, fmt.Sprintf("policy-%d", id)); err != nil {
			t.Fatalf("seed policy %d: %v", id, err)
		}
	}
	for _, pid := range []int{1, 3, 5} {
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_multi',?)`, pid); err != nil {
			t.Fatalf("seed multi binding %d: %v", pid, err)
		}
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_single',1)`); err != nil {
		t.Fatalf("seed single binding: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)

	// When: export
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%.200s", exportResponse.Code, exportResponse.Body.String())
	}
	backup := exportResponse.Body.String() // lbbak 原字节——导入端按魔数识别

	// Given: destructive change — wipe all security tables
	if _, err := db.DB.Exec("DELETE FROM security_policy_bindings; DELETE FROM security_policies"); err != nil {
		t.Fatalf("destructive change: %v", err)
	}

	// When: import
	importResponse := httptest.NewRecorder()
	importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	importRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResponse, importRequest)

	// Then: import succeeded
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%.300s", importResponse.Code, importResponse.Body.String())
	}
	// Exact row set per rule, ordered by policy_id ASC (same SELECT as runtime)
	multiBindings := queryBackupBindingRows(t, "lb_multi")
	if !reflect.DeepEqual(multiBindings, []int{1, 3, 5}) {
		t.Fatalf("lb_multi bindings=%v, want [1 3 5]", multiBindings)
	}
	singleBindings := queryBackupBindingRows(t, "lb_single")
	if !reflect.DeepEqual(singleBindings, []int{1}) {
		t.Fatalf("lb_single bindings=%v, want [1]", singleBindings)
	}
	noneBindings := queryBackupBindingRows(t, "lb_none")
	if len(noneBindings) != 0 {
		t.Fatalf("lb_none bindings=%v, want empty", noneBindings)
	}
	var totalBindings int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings").Scan(&totalBindings); err != nil {
		t.Fatal(err)
	}
	if totalBindings != 4 {
		t.Fatalf("total bindings=%d, want 4 (3 multi + 1 single)", totalBindings)
	}
}

// (dangling): Backup import validates binding references and rejects
// rows pointing to non-existent policies. Pin this behavior.
func TestConfigBackup_danglingBindingRejected(t *testing.T) {
	// Given: a backup where lb_dangle binds to policy 1 (valid) and policy 99
	// (no such row in security_policies).
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_dangle", "name": "dangle", "protocol": "http", "domain": "dangle.example.com", "listen_port": 80, "enabled": 1},
		},
		"upstreams": {
			{"rule_id": "lb_dangle", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": 1},
		},
		"security_policies": {
			{"id": 1, "name": "real", "mode": "blocking", "enabled": 1},
		},
		"security_policy_bindings": {
			{"rule_caddy_id": "lb_dangle", "policy_id": 1},
			{"rule_caddy_id": "lb_dangle", "policy_id": 99},
		},
	}, EmptyConfigIfNil: true})

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then: import rejected with 400 due to dangling policy reference
	if response.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400 (dangling binding rejected)", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "不存在的安全策略") {
		t.Fatalf("import error=%s, want contains 不存在的安全策略", response.Body.String())
	}
}

// audit：restoreTable 的 NULL→默认值归一此前三张安全表专属，
// 其余 11 张备份表的可空列携带 JSON null 时原样落库，直接命中各 raw-scan 消费点：
// users.created_at NULL → auth.go Login 的 time.Time 扫描 500 → 永久锁死；
// api_keys.created_at/布尔列 NULL → scanAPIKeys 500；ca_providers 数值列 NULL →
// caproviders.go 查询 500 → ACME 签发链断裂；cert_jobs.ca_provider_id 等 NULL →
// certificates.go 补偿扫描硬失败/续签扫描静默跳行；path_rules.created_at NULL →
// 集群快照 dump 扫描失败 → 整集群同步中断；版本表 NULL → 自动更新静默失效。
// 导入必须成功且落库值为 dump 侧对齐默认值；生命周期合法可空列（cert_jobs
// key_pem/message/ca_available_after、users.last_login、api_keys.expires_at、
// path_rules.upstreams_json）必须保持 NULL，不得过度归一。
func TestImportConfigBackup_normalizes_null_rows_for_all_backup_tables(t *testing.T) {
	// Given：11 张非安全表各携带一行 NULL 毒化可空列
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"users": {{"id": 2, "username": "null-user", "password_hash": "hash", "role": "admin", "is_enabled": nil,
			"display_name": nil, "created_at": nil, "last_login": nil,
			"mfa_enabled": nil, "mfa_secret": nil, "mfa_recovery_codes": nil}},

		"lb_rules": {
			{"caddy_id": "lb_nulldump", "name": "null-cols", "protocol": "http", "domain": "nulldump.example.test",
				"listen_port": 8461, "enabled": nil, "description": nil, "strategy": nil, "dns_server": nil, "dns_family": nil,
				"health_check_path": nil, "host_header": nil, "tls_source": nil, "compress_types": nil, "enable_compress": nil,
				"server_tokens_hidden": nil, "tcp_try_interval": nil, "health_check_interval": nil,
				"created_by": nil, "updated_by": nil, "enable_tls": 0, "custom_routes_enabled": 1,
				"created_at": nil, "updated_at": nil},
			{"caddy_id": "lb_nullacme", "name": "null-acme", "protocol": "http", "domain": "nullacme.example.test",
				"listen_port": 8462, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 92}},
		"upstreams": {{"rule_id": "lb_nulldump", "host": "127.0.0.1", "port": 9461, "weight": nil, "enabled": nil,
			"protocol": nil, "max_connections": nil, "dynamic_dns": nil}},
		"path_rules": {{"id": 1, "rule_id": "lb_nulldump", "sort_order": 1, "match_type": "prefix", "path": "/null",
			"upstreams_json": nil, "created_at": nil, "updated_at": nil}},
		"api_keys": {{"id": 1, "name": "null-key", "key_hash": "kh", "key_prefix": "lb_sk_null", "created_by": 2,
			"is_enabled": nil, "mcp_enabled": nil, "read_only": nil, "mcp_ip_whitelist": nil,
			"expires_at": nil, "created_at": nil, "last_used": nil}},
		"ca_providers": {{"id": 90, "name": "null-ca", "provider": "zerossl", "directory_url": "https://ca.null/dir",
			"credentials": nil, "max_concurrent": nil, "min_interval_ms": nil, "enabled": nil,
			"created_at": nil, "updated_at": nil}},
		"certificate_configs": {
			{"id": 91, "name": "null-dns", "dns_provider": nil, "dns_credentials": nil, "enabled": nil,
				"created_at": nil, "updated_at": nil},
			{"id": 92, "name": "null-dns-live", "dns_provider": "dnspod", "enabled": 1},
		},
		"cert_jobs": {{"id": 1, "rule_id": "lb_nullacme", "domain": "nullacme.example.test", "status": "queued",
			"ca_provider_id": nil, "renewal_attempts": nil, "deployment_attempts": nil, "created_at": nil,
			"message": nil, "expires_at": nil, "key_pem": nil, "ca_available_after": nil,
			"last_error_code": nil, "deployment_available_after": nil, "updated_at": nil},
			{"id": 2, "rule_id": "lb_nulldump", "domain": "nulldump.example.test", "status": "queued",
				"ca_provider_id": nil, "renewal_attempts": nil, "deployment_attempts": nil, "created_at": nil,
				"message": nil, "expires_at": nil, "key_pem": nil, "ca_available_after": nil,
				"last_error_code": nil, "deployment_available_after": nil, "updated_at": nil}},
		"security_policies":          {{"id": 1, "name": "null-bind-policy"}},
		"security_policy_bindings":   {{"rule_caddy_id": "lb_nulldump", "policy_id": 1}},
		"security_crs_version":       {{"id": 1, "version": "v4.99.0", "updated_at": nil, "auto_update": nil, "update_status": nil, "message": nil, "last_checked": nil, "next_update": nil, "trigger": nil, "started_at": nil, "finished_at": nil, "consecutive_failures": nil}},
		"security_ip2region_version": {{"id": 1, "version": "v3.99.0", "updated_at": nil, "auto_update": nil, "update_status": nil, "message": nil, "last_checked": nil, "next_update": nil, "trigger": nil, "started_at": nil, "finished_at": nil, "consecutive_failures": nil}},
	}, EmptyConfigIfNil: true})
	// 夹具自检：非 ACME 清理断言必须有真实种子行，否则 COUNT=0 恒真
	// （下方「lb_nulldump cert_jobs rows=0」将不再能发现清理谓词被删/写错）。
	var fixture configBackup
	if err := json.Unmarshal([]byte(backup), &fixture); err != nil {
		t.Fatalf("parse backup fixture: %v", err)
	}
	if got := len(fixture.Tables["cert_jobs"]); got != 2 {
		t.Fatalf("fixture cert_jobs rows=%d, want 2（含将被清理的 lb_nulldump 行）", got)
	}

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功（NULL 不再原样毒化落库）
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	// 消费点 1（auth.go Login 同形查询）：users.created_at NULL 会使 time.Time
	// 扫描失败 → 500 → 永久锁死；归一为可解析 epoch 后扫描必须成功。
	var loginID int
	var loginUsername, loginHash, loginRole string
	var loginDisplayName sql.NullString
	var loginEnabled bool
	var loginCreatedAt time.Time
	var loginLastLogin sql.NullTime
	var loginPasswordVersion int64
	if err := db.DB.QueryRow("SELECT id, username, password_hash, role, display_name, is_enabled, created_at, last_login, password_version FROM users WHERE username = ?", "null-user").
		Scan(&loginID, &loginUsername, &loginHash, &loginRole, &loginDisplayName, &loginEnabled, &loginCreatedAt, &loginLastLogin, &loginPasswordVersion); err != nil {
		t.Fatalf("login-shaped users scan must survive normalized restore: %v", err)
	}
	if want := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC); !loginCreatedAt.Equal(want) {
		t.Fatalf("users.created_at=%v, want epoch %v", loginCreatedAt, want)
	}
	if !loginEnabled || loginPasswordVersion != 1 || (loginDisplayName.Valid && loginDisplayName.String != "") {
		t.Fatalf("users normalized: is_enabled=%v password_version=%d display_name=%+v, want true/1(0 归一后导入强制的 +1 吊销)/''", loginEnabled, loginPasswordVersion, loginDisplayName)
	}
	if loginLastLogin.Valid {
		t.Fatalf("users.last_login must stay NULL (lifecycle), got %v", loginLastLogin.Time)
	}
	var mfaSecret, mfaRecovery sql.NullString
	if err := db.DB.QueryRow("SELECT mfa_secret, mfa_recovery_codes FROM users WHERE username='null-user'").Scan(&mfaSecret, &mfaRecovery); err != nil {
		t.Fatalf("read normalized mfa columns: %v", err)
	}
	if !mfaSecret.Valid || mfaSecret.String != "" || !mfaRecovery.Valid || mfaRecovery.String != "[]" {
		t.Fatalf("users mfa normalized: secret=%+v recovery=%+v, want ''/'[]'", mfaSecret, mfaRecovery)
	}

	// 消费点 2（apikeys.go scanAPIKeys 同形查询）：created_at/布尔列 raw 扫描。
	var keyUsername, whitelistJSON string
	var scanKey struct {
		id         int
		name       string
		prefix     string
		createdBy  int
		lastUsed   sql.NullTime
		expiresAt  sql.NullTime
		isEnabled  bool
		mcpEnabled bool
		readOnly   bool
		createdAt  time.Time
	}
	if err := db.DB.QueryRow(`SELECT k.id, k.name, k.key_prefix, k.created_by, k.last_used, k.expires_at, k.is_enabled,
		k.mcp_enabled, k.read_only, COALESCE(k.mcp_ip_whitelist,''), k.created_at, u.username
		FROM api_keys k JOIN users u ON k.created_by = u.id WHERE k.created_by = ? ORDER BY k.id`, 2).
		Scan(&scanKey.id, &scanKey.name, &scanKey.prefix, &scanKey.createdBy, &scanKey.lastUsed, &scanKey.expiresAt,
			&scanKey.isEnabled, &scanKey.mcpEnabled, &scanKey.readOnly, &whitelistJSON, &scanKey.createdAt, &keyUsername); err != nil {
		t.Fatalf("api_keys list-shaped scan must survive normalized restore: %v", err)
	}
	if !scanKey.isEnabled || scanKey.mcpEnabled || scanKey.readOnly || whitelistJSON != "" {
		t.Fatalf("api_keys normalized: is_enabled=%v mcp=%v read_only=%v whitelist=%q, want true/false/false/''", scanKey.isEnabled, scanKey.mcpEnabled, scanKey.readOnly, whitelistJSON)
	}
	if want := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC); !scanKey.createdAt.Equal(want) {
		t.Fatalf("api_keys.created_at=%v, want epoch %v", scanKey.createdAt, want)
	}
	if scanKey.expiresAt.Valid {
		t.Fatalf("api_keys.expires_at must stay NULL (lifecycle), got %v", scanKey.expiresAt.Time)
	}

	// 消费点 3（caproviders.go 同形查询）：数值/布尔列 raw 扫描（NULL→500→ACME 链断裂）。
	var caName, caProvider, caDir, caCred string
	var caMaxConcurrent, caMinInterval int
	var caEnabled bool
	if err := db.DB.QueryRow("SELECT name, provider, directory_url, COALESCE(credentials,''), max_concurrent, min_interval_ms, enabled FROM ca_providers WHERE id=90").
		Scan(&caName, &caProvider, &caDir, &caCred, &caMaxConcurrent, &caMinInterval, &caEnabled); err != nil {
		t.Fatalf("ca_providers scan must survive normalized restore: %v", err)
	}
	if caCred != "" || caMaxConcurrent != 1 || caMinInterval != 2000 || !caEnabled {
		t.Fatalf("ca_providers normalized: cred=%q max=%d min=%d enabled=%v, want ''/1/2000/true", caCred, caMaxConcurrent, caMinInterval, caEnabled)
	}

	// 消费点 4（certificates.go SnapshotCertJobsForRule 同形扫描）：ca_provider_id/
	// renewal_attempts/deployment_attempts 为 raw int 扫描（NULL→UpdateRule 补偿硬失败）。
	certRows, err := db.DB.Query(`SELECT id,rule_id,domain,status,message,expires_at,cert_pem,key_pem,ca_provider_id,
		renewal_attempts,ca_available_after,last_error_code,deployment_attempts,deployment_available_after,created_at,updated_at
		FROM cert_jobs WHERE rule_id=? ORDER BY id`, "lb_nullacme")
	if err != nil {
		t.Fatalf("query cert jobs: %v", err)
	}
	type certScan struct {
		id, caProviderID, renewalAttempts, deploymentAttempts int
		ruleID, domain, status                                string
		message, certPEM, keyPEM, lastErrorCode               sql.NullString
		expiresAt, caAvailableAfter, deploymentAfter          sql.NullTime
		createdAt, updatedAt                                  sql.NullTime
	}
	scanned := 0
	for certRows.Next() {
		var job certScan
		if err := certRows.Scan(&job.id, &job.ruleID, &job.domain, &job.status, &job.message, &job.expiresAt, &job.certPEM, &job.keyPEM,
			&job.caProviderID, &job.renewalAttempts, &job.caAvailableAfter, &job.lastErrorCode, &job.deploymentAttempts,
			&job.deploymentAfter, &job.createdAt, &job.updatedAt); err != nil {
			certRows.Close()
			t.Fatalf("cert_jobs snapshot-shaped scan must survive normalized restore: %v", err)
		}
		if job.caProviderID != 0 || job.renewalAttempts != 0 || job.deploymentAttempts != 0 {
			t.Fatalf("cert_jobs normalized: ca_provider_id=%d renewal=%d deployment=%d, want 0/0/0", job.caProviderID, job.renewalAttempts, job.deploymentAttempts)
		}
		if job.keyPEM.Valid || job.message.Valid || job.caAvailableAfter.Valid || job.lastErrorCode.Valid || job.deploymentAfter.Valid {
			t.Fatalf("cert_jobs lifecycle NULLs must stay NULL: key_pem=%+v message=%+v ca_after=%+v last_err=%+v deploy_after=%+v", job.keyPEM, job.message, job.caAvailableAfter, job.lastErrorCode, job.deploymentAfter)
		}
		scanned++
	}
	certRows.Close()
	if scanned != 1 {
		t.Fatalf("cert_jobs scanned=%d, want 1", scanned)
	}
	// 非 ACME 态规则（lb_nulldump: enable_tls=0）的 cert_jobs
	// 行随导入失效任务清理删除——此前只清孤儿行（rule_id 不在 lb_rules），此类
	// 「规则仍在但已非 ACME」的残留会被续签扫描/任务列表当作活任务。
	var orphanJobs int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_nulldump'`).Scan(&orphanJobs); err != nil {
		t.Fatalf("count lb_nulldump cert jobs: %v", err)
	}
	if orphanJobs != 0 {
		t.Fatalf("lb_nulldump cert_jobs rows=%d, want 0（非 ACME 规则的失效任务须清理）", orphanJobs)
	}
	// 消费点 4b（certjobs.go 列表同形）：j.created_at 为 raw time.Time 扫描。
	var jobCreatedAt time.Time
	if err := db.DB.QueryRow("SELECT j.created_at FROM cert_jobs j WHERE j.rule_id=?", "lb_nullacme").Scan(&jobCreatedAt); err != nil {
		t.Fatalf("cert_jobs list-shaped created_at scan must survive normalized restore: %v", err)
	}

	// 消费点 5（cluster_snapshot.go snapshotAllPathRules 同形扫描）：created_at 为
	// raw time.Time 扫描（NULL→主节点快照 dump 失败→整集群同步中断）。
	var prSort int
	var prRuleID, prMatchType, prPath string
	var prUpstreams sql.NullString
	var prCreatedAt time.Time
	var prUpdatedAt sql.NullTime
	if err := db.DB.QueryRow("SELECT id, rule_id, sort_order, match_type, path, upstreams_json, created_at, updated_at FROM path_rules WHERE rule_id=? ORDER BY rule_id, sort_order, id", "lb_nulldump").
		Scan(new(int), &prRuleID, &prSort, &prMatchType, &prPath, &prUpstreams, &prCreatedAt, &prUpdatedAt); err != nil {
		t.Fatalf("path_rules snapshot-shaped scan must survive normalized restore: %v", err)
	}
	if want := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC); !prCreatedAt.Equal(want) {
		t.Fatalf("path_rules.created_at=%v, want epoch %v", prCreatedAt, want)
	}
	if prUpstreams.Valid {
		t.Fatalf("path_rules.upstreams_json must stay NULL (lifecycle), got %q", prUpstreams.String)
	}

	// 落库值断言：lb_rules/upstreams/certificate_configs/版本表归一为 dump 侧对齐默认值。
	var ruleDesc, ruleStrategy, ruleDNSFamily, ruleHostHeader, ruleTLSSource, ruleCompressTypes sql.NullString
	var ruleEnableCompress, ruleServerTokensHidden, ruleTCPTryInterval, ruleHealthCheckInterval sql.NullInt64
	var ruleCreatedBy, ruleUpdatedBy sql.NullInt64
	if err := db.DB.QueryRow(`SELECT description, strategy, dns_family, host_header, tls_source, compress_types,
		enable_compress, server_tokens_hidden, tcp_try_interval, health_check_interval, created_by, updated_by
		FROM lb_rules WHERE caddy_id='lb_nulldump'`).
		Scan(&ruleDesc, &ruleStrategy, &ruleDNSFamily, &ruleHostHeader, &ruleTLSSource, &ruleCompressTypes,
			&ruleEnableCompress, &ruleServerTokensHidden, &ruleTCPTryInterval, &ruleHealthCheckInterval, &ruleCreatedBy, &ruleUpdatedBy); err != nil {
		t.Fatalf("read normalized lb_rules: %v", err)
	}
	if !ruleDesc.Valid || ruleDesc.String != "" || !ruleStrategy.Valid || ruleStrategy.String != "weighted_round_robin" ||
		!ruleDNSFamily.Valid || ruleDNSFamily.String != "ipv4" || !ruleHostHeader.Valid || ruleHostHeader.String != "" ||
		!ruleTLSSource.Valid || ruleTLSSource.String != "manual" || !ruleCompressTypes.Valid || ruleCompressTypes.String != "gzip" {
		t.Fatalf("lb_rules text defaults: desc=%+v strategy=%+v dns_family=%+v host=%+v tls_source=%+v compress=%+v", ruleDesc, ruleStrategy, ruleDNSFamily, ruleHostHeader, ruleTLSSource, ruleCompressTypes)
	}
	if !ruleEnableCompress.Valid || ruleEnableCompress.Int64 != 1 || !ruleServerTokensHidden.Valid || ruleServerTokensHidden.Int64 != 0 ||
		!ruleTCPTryInterval.Valid || ruleTCPTryInterval.Int64 != 250 || !ruleHealthCheckInterval.Valid || ruleHealthCheckInterval.Int64 != 10 ||
		!ruleCreatedBy.Valid || ruleCreatedBy.Int64 != 0 || !ruleUpdatedBy.Valid || ruleUpdatedBy.Int64 != 0 {
		t.Fatalf("lb_rules numeric defaults: enable_compress=%+v server_tokens=%+v tcp_try_interval=%+v hc_interval=%+v created_by=%+v updated_by=%+v", ruleEnableCompress, ruleServerTokensHidden, ruleTCPTryInterval, ruleHealthCheckInterval, ruleCreatedBy, ruleUpdatedBy)
	}
	var upWeight, upMaxConns sql.NullInt64
	var upProtocol sql.NullString
	if err := db.DB.QueryRow("SELECT weight, protocol, max_connections FROM upstreams WHERE rule_id='lb_nulldump'").Scan(&upWeight, &upProtocol, &upMaxConns); err != nil {
		t.Fatalf("read normalized upstreams: %v", err)
	}
	if !upWeight.Valid || upWeight.Int64 != 1 || !upProtocol.Valid || upProtocol.String != "http" || !upMaxConns.Valid || upMaxConns.Int64 != 0 {
		t.Fatalf("upstreams defaults: weight=%+v protocol=%+v max_connections=%+v, want 1/'http'/0", upWeight, upProtocol, upMaxConns)
	}
	var dnsProvider sql.NullString
	var dnsCred sql.NullString
	var dnsEnabled sql.NullInt64
	if err := db.DB.QueryRow("SELECT dns_provider, dns_credentials, enabled FROM certificate_configs WHERE id=91").Scan(&dnsProvider, &dnsCred, &dnsEnabled); err != nil {
		t.Fatalf("read normalized certificate_configs: %v", err)
	}
	if !dnsProvider.Valid || dnsProvider.String != "dnspod" || !dnsCred.Valid || dnsCred.String != "" || !dnsEnabled.Valid || dnsEnabled.Int64 != 1 {
		t.Fatalf("certificate_configs defaults: provider=%+v cred=%+v enabled=%+v, want 'dnspod'/''/1", dnsProvider, dnsCred, dnsEnabled)
	}
	// 2026-09-18 用户裁定改契约:纯 JSON 备份规则库版本表不落库(防记录与
	// 文件分叉)。security_crs_version 空;security_ip2region_version 保留
	// schema 种子行(id=1 'unknown',db.go:569)——导入不得写入备份行。
	var crsRows int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_crs_version").Scan(&crsRows); err != nil {
		t.Fatal(err)
	}
	if crsRows != 0 {
		t.Fatalf("security_crs_version rows=%d, want 0 (json import must skip)", crsRows)
	}
	var ip2Version string
	if err := db.DB.QueryRow("SELECT version FROM security_ip2region_version WHERE id=1").Scan(&ip2Version); err != nil {
		t.Fatalf("read ip2region seed: %v", err)
	}
	if ip2Version != "unknown" {
		t.Fatalf("security_ip2region_version version=%q, want 'unknown' (seed preserved, backup row skipped)", ip2Version)
	}

	// 消费点 6（cluster_snapshot.go snapshotRules 尾列同形）：created_at 为
	// raw time.Time 扫描、updated_at 为 JSONNullTime（NULL 安全，保持 NULL）。
	// audit 修正：lb_rules.created_at NULL 此前原样落库，dump 扫描失败会中断
	// 整集群同步，故归一 epoch（与 users/api_keys/cert_jobs/path_rules 同口径）。
	var ruleCreatedAt time.Time
	var ruleUpdatedAt sql.NullTime
	if err := db.DB.QueryRow("SELECT created_at, updated_at FROM lb_rules WHERE caddy_id='lb_nulldump'").
		Scan(&ruleCreatedAt, &ruleUpdatedAt); err != nil {
		t.Fatalf("lb_rules snapshot-shaped time scan must survive normalized restore: %v", err)
	}
	if want := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC); !ruleCreatedAt.Equal(want) {
		t.Fatalf("lb_rules.created_at=%v, want epoch %v", ruleCreatedAt, want)
	}
	if ruleUpdatedAt.Valid {
		t.Fatalf("lb_rules.updated_at must stay NULL (JSONNullTime lifecycle), got %v", ruleUpdatedAt.Time)
	}

	// 消费点 7（cluster_snapshot.go snapshotACME :537 同形）：ca_providers 的
	// created_at/updated_at 均为 raw time.Time 扫描，双列归一 epoch。
	var caCreatedAt, caUpdatedAt time.Time
	if err := db.DB.QueryRow("SELECT created_at, updated_at FROM ca_providers WHERE id=90").
		Scan(&caCreatedAt, &caUpdatedAt); err != nil {
		t.Fatalf("ca_providers snapshot-shaped time scan must survive normalized restore: %v", err)
	}
	if want := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC); !caCreatedAt.Equal(want) || !caUpdatedAt.Equal(want) {
		t.Fatalf("ca_providers created_at=%v updated_at=%v, want epoch %v both", caCreatedAt, caUpdatedAt, want)
	}

	// 消费点 8（cluster_snapshot.go snapshotACME :553 同形）：certificate_configs
	// 的 created_at 为 raw time.Time 扫描（归一 epoch），updated_at 为
	// JSONNullTime 扫描（NULL 安全，保持 NULL）。
	var certCfgCreatedAt time.Time
	var certCfgUpdatedAt sql.NullTime
	if err := db.DB.QueryRow("SELECT created_at, updated_at FROM certificate_configs WHERE id=91").
		Scan(&certCfgCreatedAt, &certCfgUpdatedAt); err != nil {
		t.Fatalf("certificate_configs snapshot-shaped time scan must survive normalized restore: %v", err)
	}
	if want := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC); !certCfgCreatedAt.Equal(want) {
		t.Fatalf("certificate_configs.created_at=%v, want epoch %v", certCfgCreatedAt, want)
	}
	if certCfgUpdatedAt.Valid {
		t.Fatalf("certificate_configs.updated_at must stay NULL (JSONNullTime lifecycle), got %v", certCfgUpdatedAt.Time)
	}
}

// audit 同构回归：dump→restore→dump 往返必须逐字节稳定（fresh backup 的
// 表区语义相等）——归一只替换显式 NULL，不得改变任何非 NULL 值。种子库先经
// 一次导入「愈合并」（对齐集群通道/恢复后库的规范形态），随后 A=export →
// import(A) → B=export 必须语义相等（唯一豁免：导入固定递增 users.password_version
// 吊销旧 JWT，A 侧 +1 后比较）。
func TestConfigBackup_restore_dump_isomorphism_roundtrip(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,created_at,last_login,password_version,
		mfa_enabled,mfa_secret,mfa_recovery_codes,mfa_last_timestep)
		VALUES (1,'iso-admin','hash','admin','Iso Admin',1,'2026-01-02 03:04:05',NULL,5,0,'','[]',0)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,dynamic_dns,enable_dns_server,
		dns_server,dns_family,health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,
		enable_active_health_check,tcp_health_check_port,tcp_try_duration,tcp_try_interval,request_body_max_size_mb,upstream_keepalive_timeout,
		server_tokens_hidden,custom_routes_enabled,proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,
		proxy_stream_timeout,proxy_flush_interval,proxy_stream_close_delay,host_header,enable_tls,tls_source,acme_config_id,ca_provider_id,
		tls_http_redirect,enable_compress,compress_types,enabled,log_enabled,created_by,created_at,updated_at,updated_by)
		VALUES ('lb_iso','iso','iso-desc','http','iso.example.test',8462,'least_conn',0,0,'','both','/health',15,4,3,2,
		0,0,0,300,0,0,1,1,0,0,0,0,0,0,0,'hh.example.test',0,'manual',0,0,
		0,1,'zstd',1,0,1,'2026-01-02 03:04:05','2026-01-02 03:04:06',1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (id,rule_id,host,port,weight,dynamic_dns,enabled,protocol,max_connections)
		VALUES (1,'lb_iso','10.0.0.1',9462,3,1,1,'https',7)`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO path_rules (id,rule_id,sort_order,match_type,path,upstreams_json,created_at,updated_at)
		VALUES (1,'lb_iso',2,'prefix','/iso','[{"address":"10.0.0.9","port":9463,"weight":2,"protocol":"http"}]','2026-01-02 03:04:05',NULL)`); err != nil {
		t.Fatalf("seed path rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,last_used,expires_at,is_enabled,mcp_enabled,read_only,mcp_ip_whitelist,created_at)
		VALUES (1,'iso-key','kh','lb_sk_iso',1,NULL,NULL,1,1,1,'["1.2.3.4"]','2026-01-02 03:04:05')`); err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled,created_at,updated_at)
		VALUES (95,'iso-ca','zerossl','` + services.ZeroSSLDirectoryURL + `','{"eab_kid":"k"}',4,1500,1,'2026-01-02 03:04:05','2026-01-02 03:04:05')`); err != nil {
		t.Fatalf("seed ca provider: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled,created_at,updated_at)
		VALUES (96,'iso-dns','dnspod','{"secret_id":"s"}',1,'2026-01-02 03:04:05',NULL)`); err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,message,expires_at,cert_pem,key_pem,ca_provider_id,renewal_attempts,
		ca_available_after,last_error_code,deployment_attempts,deployment_available_after,created_at,updated_at)
		VALUES (1,'lb_iso','iso.example.test','issued','ok','2027-01-01 00:00:00','','',95,2,NULL,NULL,1,NULL,'2026-01-02 03:04:05',NULL)`); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,
		ip_whitelist,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,crs_rule_groups,crs_excluded_rules,custom_rules,
		block_page_id,block_status_code,enabled,updated_by,created_at,updated_at,geoip_countries,geoip_mode,waf_check_response)
		VALUES (1,'iso-policy','d','blocking',5,'deny','[]',0,'[]','[]',0,0,0,'[]','[]','[]',0,0,1,0,'2026-01-02 03:04:05','2026-01-02 03:04:05','[]','deny',0)`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_iso',1)`); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_crs_version (id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at)
		VALUES (1,'v4.28.0','2026-01-02 03:04:05',1,'idle','m','2026-01-02 03:04:05','2026-01-03 03:04:05','manual','','')`); err != nil {
		t.Fatalf("seed crs version: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_ip2region_version (id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at)
		VALUES (1,'v3.17.0','2026-01-02 03:04:05',0,'idle','','2026-01-02 03:04:05','','','','')`); err != nil {
		t.Fatalf("seed ip2region version: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET log_level='debug', sync_interval=45 WHERE id=1"); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	// 配套夹具：导入提交后会重装四族首槽（armCrawlerFirstSlots 经
	// ensureCrawlerSources 补种子行，其时间列为 NULL）；生产库在首次生命
	// 周期调用后恒有这四行。这里按生产形态预置（时间列 '' 而非 NULL），否则
	// 「导入后首次补种」与「restore 的 NULL→'' 归一」会让 A/B 在 last_checked
	// 形态上分叉，干扰本测试的 dump/restore 不动点断言。
	for _, name := range []string{"googlebot", "gptbot", "bingbot", "so360spider"} {
		if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_crawler_sources
			(name,display_name,url,format,update_enabled,entry_count,version,update_status,message,last_checked,next_update,trigger,started_at,finished_at,consecutive_failures,created_at,updated_at)
			VALUES (?,?,?,'json',1,0,'','idle','','','','','','',0,'','')`, name, name, "https://example.test/"+name); err != nil {
			t.Fatalf("seed crawler source %s: %v", name, err)
		}
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)
	doExport := func() map[string]any {
		t.Helper()
		waitImportCleanup()
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config/export", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("export status=%d body=%.300s", response.Code, response.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(unpackExportBody(t, response.Body.Bytes()), &payload); err != nil {
			t.Fatalf("decode export: %v", err)
		}
		return payload
	}
	doImport := func(body string) {
		t.Helper()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("import status=%d body=%.400s", response.Code, response.Body.String())
		}
	}
	rawExport := func() string {
		t.Helper()
		// 导入会话窗口现在保持到后台清理结束：导出前等待清理收尾，
		// 否则同进程立即导出会拿到 409（真实用户窗口为毫秒级）。
		waitImportCleanup()
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config/export", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("export status=%d body=%.300s", response.Code, response.Body.String())
		}
		return string(unpackExportBody(t, response.Body.Bytes()))
	}

	// 愈合并：初始库可含 Initialize 播种行的 NULL（如版本表 last_checked），
	// 先走一轮 export→import 把库对齐到归一后形态，后续往返即不动点。
	doImport(rawExport())

	// When：A = dump → restore(A) → B = dump
	rawA := rawExport()
	doImport(rawA)
	backupB := doExport()

	// Then：A 与 B 表区语义相等（仅 password_version 每次导入 +1 属既定吊销语义）
	var backupA map[string]any
	if err := json.Unmarshal([]byte(rawA), &backupA); err != nil {
		t.Fatalf("decode export A: %v", err)
	}
	bumpPasswordVersions(backupA)
	if !reflect.DeepEqual(backupA["tables"], backupB["tables"]) {
		aJSON, _ := json.Marshal(backupA["tables"])
		bJSON, _ := json.Marshal(backupB["tables"])
		t.Fatalf("dump→restore→dump isomorphism broken:\nA(after +1): %s\nB:          %s", truncateForDiff(aJSON), truncateForDiff(bJSON))
	}
	if !reflect.DeepEqual(backupA["config"], backupB["config"]) {
		aJSON, _ := json.Marshal(backupA["config"])
		bJSON, _ := json.Marshal(backupB["config"])
		t.Fatalf("config section isomorphism broken:\nA: %s\nB: %s", aJSON, bJSON)
	}
}

// bumpPasswordVersions 把导出载荷 users 表每行 password_version +1，
// 对齐 ImportConfigBackup 提交前的全量 JWT 吊销递增（config_backup.go
// UPDATE users SET password_version=COALESCE(password_version,0)+1）。
func bumpPasswordVersions(payload map[string]any) {
	tables, ok := payload["tables"].(map[string]any)
	if !ok {
		return
	}
	users, ok := tables["users"].([]any)
	if !ok {
		return
	}
	for _, rowAny := range users {
		row, ok := rowAny.(map[string]any)
		if !ok {
			continue
		}
		switch version := row["password_version"].(type) {
		case float64:
			row["password_version"] = version + 1
		case nil:
			row["password_version"] = float64(1)
		}
	}
}

func truncateForDiff(data []byte) string {
	const limit = 3000
	if len(data) <= limit {
		return string(data)
	}
	return string(data[:limit]) + "...(truncated)"
}

func queryBackupBindingRows(t *testing.T, ruleCaddyID string) []int {
	t.Helper()
	rows, err := db.DB.Query("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id ASC", ruleCaddyID)
	if err != nil {
		t.Fatalf("query bindings for %s: %v", ruleCaddyID, err)
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan binding: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate bindings: %v", err)
	}
	return ids
}

// 补充:此前测试用内联 SQL 而非 handler 生产路径。
// 本测试走 ImportConfigBackup 端到端,验证含顶层字符串 custom_rules 的备份
// 导入不 500。
func TestImportConfigBackup_toleratesTopLevelStringCustomRules(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// 旧夹具缺 meta.app，在完整性校验门首行 400 早退，只断言
	// 「非 500」等于没测。改用完整 v2 夹具注入顶层字符串 custom_rules，断言
	// 200 且策略行真实落库（若转红即暴露真实归一缺口）。
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"security_policies": {{"id": 1, "name": "top-str", "mode": "off", "custom_rules": `"str"`, "enabled": 1}},
	}, EmptyConfigIfNil: true})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("导入含顶层字符串 custom_rules 的备份应 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(custom_rules,'') FROM security_policies WHERE name='top-str'`).Scan(&stored); err != nil {
		t.Fatalf("策略未落库: %v", err)
	}
	if stored != `"str"` {
		t.Fatalf("custom_rules=%q, want 原样 \"str\"", stored)
	}
}

// 导入路径不校验 IP 条目值——zone 形态
// (fe80::1%eth0)经备份导入落库后 coraza @ipMatch 静默丢弃(零留痕)。
// validateV2BackupSecurityPolicies 必须按 validIPOrCIDR 口径拒绝。
func TestValidateV2Backup_rejectsZoneFormIPEntries(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_ip_lists": {
			{"name": "zone-list", "entries": `[{"value":"fe80::1%eth0","remark":"zone"}]`},
		},
	}
	err := validateV2BackupSecurityPolicies(tables, false)
	if err == nil {
		t.Fatal("zone-form IP entry in backup must be rejected (coraza @ipMatch silently drops)")
	}
	if !strings.Contains(err.Error(), "zone") && !strings.Contains(err.Error(), "fe80") {
		t.Fatalf("error=%q, want mention of zone/invalid entry", err)
	}
}

// 对偶:正常条目不受影响
func TestValidateV2Backup_acceptsNormalIPEntries(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_ip_lists": {
			{"name": "normal", "entries": `[{"value":"192.168.1.1"},{"value":"10.0.0.0/8"},{"value":"fe80::1"}]`},
		},
	}
	if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
		t.Fatalf("normal entries must be accepted: %v", err)
	}
}

// 导入路径策略内联 IP 三字段
// (ip_acl_list/ip_whitelist/ip_blacklist)未按保存侧 validateIPCIDRList 口径
// 校验——zone 形态经备份导入落库后 coraza 静默丢弃。列表条目非对象成员
// 被 continue 放行(应拒,同保存侧口径)。
func TestValidateV2Backup_rejectsZoneFormInPolicyInlineFields(t *testing.T) {
	for _, field := range []string{"ip_acl_list", "ip_whitelist", "ip_blacklist"} {
		tables := map[string][]map[string]any{
			"security_policies": {
				{"name": "zone-policy", field: `["fe80::1%eth0"]`},
			},
		}
		err := validateV2BackupSecurityPolicies(tables, false)
		if err == nil {
			t.Fatalf("zone-form entry in policy.%s must be rejected", field)
		}
	}
}

func TestValidateV2Backup_rejectsNonObjectIPListEntries(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_ip_lists": {
			{"name": "bare-string-list", "entries": `["192.168.1.1","fe80::1%eth0"]`},
		},
	}
	err := validateV2BackupSecurityPolicies(tables, false)
	if err == nil {
		t.Fatal("non-object entry (bare string) in IP list must be rejected (zone form hidden inside)")
	}
}

// 备份布尔门枚举漏 trust_detection——security_policies
// 的阶段 0 信任检测开关（BOOLEAN NOT NULL DEFAULT 0）不在 backupBooleanTableColumns，
// 字符串 "true" 形态经导入落库后由布尔门漏过：校验期读 false、存储期 SQLite 亲和性
// 保留文本，同一值两期含义相反。畸形形态整包 400；布尔/0-1 数值放行且落库正确。
func TestValidateV2BackupBooleanTypes_rejectsMalformedTrustDetection(t *testing.T) {
	rejects := []struct {
		name string
		raw  any
	}{
		{"string true", "true"},
		{"string 1", "1"},
		{"number 2", 2},
	}
	for _, tt := range rejects {
		t.Run("rejects_"+tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
				"security_policies": {{"id": 1, "name": "p", "trust_detection": tt.raw}},
			}, EmptyConfigIfNil: true})

			router := gin.New()
			router.POST("/config/import", h.ImportConfigBackup)
			request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("trust_detection=%v(%T): status=%d body=%s, want 400", tt.raw, tt.raw, response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "trust_detection") {
				t.Fatalf("rejection must name the column, body=%s", response.Body.String())
			}
		})
	}
	accepts := []struct {
		name string
		raw  any
		want int
	}{
		{"bool true", true, 1},
		{"bool false", false, 0},
		{"numeric 1", 1, 1},
	}
	for _, tt := range accepts {
		t.Run("accepts_"+tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
				"security_policies": {{"id": 1, "name": "p", "trust_detection": tt.raw}},
			}, EmptyConfigIfNil: true})

			router := gin.New()
			router.POST("/config/import", h.ImportConfigBackup)
			request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("trust_detection=%v: status=%d body=%s, want 200", tt.raw, response.Code, response.Body.String())
			}
			var stored int
			if err := db.DB.QueryRow("SELECT trust_detection FROM security_policies WHERE id=1").Scan(&stored); err != nil {
				t.Fatalf("read imported policy: %v", err)
			}
			if stored != tt.want {
				t.Fatalf("trust_detection=%d, want %d", stored, tt.want)
			}
		})
	}
}

// 备份校验缺 policy_type 值域门——显式未知类型
// （手编辑/带外改库导出）原样落库后策略页分组与阶段外字段归一判定漂移；
// 非字符串形态与三枚举门同口径拒绝（同型，backupString 不得静默
// 归一）。空串/null/缺省放行——导入侧 restoreTable 对空行按内容重推断。
func TestValidateV2BackupSecurityPolicies_rejectsUnknownPolicyType(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  any
	}{
		{"unknown value", "bogus"},
		{"non-string", 2},
	} {
		t.Run("rejects_"+tt.name, func(t *testing.T) {
			tables := map[string][]map[string]any{
				"security_policies": {{"id": 1, "name": "p", "policy_type": tt.raw}},
			}
			err := validateV2BackupSecurityPolicies(tables, false)
			if err == nil {
				t.Fatalf("policy_type=%v(%T) must be rejected", tt.raw, tt.raw)
			}
			if !strings.Contains(err.Error(), "policy_type") {
				t.Fatalf("error=%q, want mention of policy_type", err)
			}
		})
	}
	legal := []string{"", "stage0", "stage1", "stage2", "stage3", "mixed"}
	for _, value := range legal {
		t.Run("accepts_"+value, func(t *testing.T) {
			tables := map[string][]map[string]any{
				"security_policies": {{"id": 1, "name": "p", "policy_type": value}},
			}
			if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
				t.Fatalf("policy_type=%q must pass (empty is re-inferred at restore; explicit five enums pass through): %v", value, err)
			}
		})
	}
}

// 库值唯一真相（批 3）：安全策略值列导入门归一——旧备份可携带治理前形态
// （anomaly_threshold=0/NULL、burst 负值、block_status_code 枚举外如 429/418），
// 在导入门写回归一值后 restoreTable 直写，库恒有效（渲染层已零兜底/fail-
// visible）；缺失键由 backupTableNullDefaults 的 NULL→默认通道承担。
// rate_limit_rps 不归一：enabled=1 时 rps<1 保持 400 拒绝（写侧同口径）。
func TestValidateV2BackupSecurityPolicies_normalizesLegacyValueColumns(t *testing.T) {
	t.Run("dirty-row-normalized", func(t *testing.T) {
		tables := map[string][]map[string]any{
			"security_policies": {{
				"name":              "legacy",
				"anomaly_threshold": int64(0),
				"rate_limit_burst":  int64(-5),
				"block_status_code": int64(451),
			}},
		}
		if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
			t.Fatalf("normalize-on-import must not reject: %v", err)
		}
		row := tables["security_policies"][0]
		if got := row["anomaly_threshold"]; got != int64(5) {
			t.Fatalf("anomaly_threshold=%v (%T), want 5", got, got)
		}
		if got := row["rate_limit_burst"]; got != int64(0) {
			t.Fatalf("rate_limit_burst=%v (%T), want 0", got, got)
		}
		if got := row["block_status_code"]; got != int64(403) {
			t.Fatalf("block_status_code=%v (%T), want 403（451 非写侧白名单，枚举外归一默认；429 同）", got, got)
		}
	})
	t.Run("null-anomaly-normalized", func(t *testing.T) {
		tables := map[string][]map[string]any{
			"security_policies": {{"name": "nullish", "anomaly_threshold": nil}},
		}
		if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if got := tables["security_policies"][0]["anomaly_threshold"]; got != int64(5) {
			t.Fatalf("anomaly_threshold=%v (%T), want 5", got, got)
		}
	})
	t.Run("valid-values-untouched", func(t *testing.T) {
		tables := map[string][]map[string]any{
			"security_policies": {{
				"name":              "valid",
				"anomaly_threshold": int64(10),
				"rate_limit_burst":  int64(50),
				"block_status_code": int64(503),
			}},
		}
		if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
			t.Fatalf("validate: %v", err)
		}
		row := tables["security_policies"][0]
		if row["anomaly_threshold"] != int64(10) || row["rate_limit_burst"] != int64(50) || row["block_status_code"] != int64(503) {
			t.Fatalf("valid values must pass through: %v", row)
		}
	})
	t.Run("garbage-anomaly-normalized", func(t *testing.T) {
		tables := map[string][]map[string]any{
			"security_policies": {{"name": "garbage", "anomaly_threshold": "abc"}},
		}
		if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
			t.Fatalf("non-integer anomaly must normalize, not reject (渲染层 fail-visible 语义归属 services): %v", err)
		}
		if got := tables["security_policies"][0]["anomaly_threshold"]; got != int64(5) {
			t.Fatalf("anomaly_threshold=%v (%T), want 5", got, got)
		}
	})
	t.Run("enabled-rps-zero-still-rejected", func(t *testing.T) {
		tables := map[string][]map[string]any{
			"security_policies": {{
				"name":               "rl",
				"rate_limit_enabled": true,
				"rate_limit_rps":     int64(0),
			}},
		}
		if err := validateV2BackupSecurityPolicies(tables, false); err == nil {
			t.Fatal("enabled=1 + rps=0 must stay rejected (写侧同口径), not normalized")
		}
	})
}

// 导入前 auto_backup_enabled 的读取必须把错误如实
// 上抛——旧形态 `_ = ...Scan()` 吞错使变量保持 0，会把「原本已启用」误判为
// off→on，导入提交后可能重置自动备份水位线（推迟下一次自动备份一个周期）。
func TestReadImportOldAutoBackupEnabled_surfacesReadError(t *testing.T) {
	newBackupTestHandlers(t)
	ctx := context.Background()

	// 正常形态：读到库值（先写再开事务——SQLite 单写连接下事务外 Exec 会等锁）。
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	enabled, err := readImportOldAutoBackupEnabled(ctx, tx)
	if err != nil {
		t.Fatalf("正常读取失败: %v", err)
	}
	if enabled != 1 {
		t.Fatalf("enabled=%d, want 1", enabled)
	}

	// 失败形态：同事务内 global_config 行不可见（等价单行读失败）→ 必须返回
	// 错误而不是 (0, nil)。
	if _, err := tx.Exec(`DELETE FROM global_config WHERE id=1`); err != nil {
		t.Fatalf("drop global_config row: %v", err)
	}
	if _, err := readImportOldAutoBackupEnabled(ctx, tx); err == nil {
		t.Fatal("读取失败必须上抛错误（吞成 0 会把已启用误判为 off）")
	}
}

// off→on 水位重置判定——读取失败（未知）时不重置。
func TestImportAutoBackupResetNeeded(t *testing.T) {
	cases := []struct {
		name    string
		known   bool
		old     int
		want    bool
		comment string
	}{
		{"已知 off → 重置（off→on）", true, 0, true, "原语义保持"},
		{"已知 on → 不重置", true, 1, false, "非 off→on 转换"},
		{"未知（读失败）→ 不重置", false, 0, false, "不得把未知当 off 重置水位"},
		{"未知且旧值 1 → 不重置", false, 1, false, "同上"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := importAutoBackupResetNeeded(tc.known, tc.old); got != tc.want {
				t.Fatalf("reset=%v, want %v（%s）", got, tc.want, tc.comment)
			}
		})
	}
}

// ── v2 备份 JSON 夹具 ──
//
// 这是全包唯一的 v2 备份 JSON 构造器。此前并存 9 个各自命名的 *BackupJSON
// 构造器（全表回填 / 精确表集 / 缺席集合 / sections 注入 / nil 视同缺席等），
// 语义各不相同；新用例选错构造器会静默绕过目标门（事故：缺
// exported_at/checksum 导致全部早退，断言只命中「非 true」的假绿——见
// v2BackupBody 上方注释）。
//
// 现在所有形态都由 backupFixtureOptions 显式表达：
//   - 精确表集（真实分类导出/迟到表形态）：只给 Tables，FillAll=false；
//   - 全表回填（users 恒含 backup-admin 管理员行）：FillAll=true；
//   - 「表未携带」形态：FillAll=true + Omit；
//   - 分类导出产物把 nil 行集视同缺席：DropNil=true；
//   - sections/全局配置区按需注入；Config 的 nil 与 {} 语义不同（null 全局
//     配置区与空对象在导入侧分支不同），EmptyConfigIfNil 保留历史夹具的
//     「nil→空对象」形态，其余调用方原样透传。
//
// checksum 恒按真实导出形态（{tables,config} 摘要）计算——「缺 checksum」这类
// 畸形 meta 形态由下方 v2BackupBody 专门构造（它覆盖 version 越界与缺席校验和，
// 属于故意畸形的契约用例，不进本构造器）。

type backupFixtureOptions struct {
	// Tables 显式表行（覆盖 FillAll 回填的空表集）。
	Tables map[string][]map[string]any
	// FillAll 回填 configBackupTables 全键为空表，并为 users 补一个启用管理员
	// 行（过导入侧管理员门）。
	FillAll bool
	// Omit FillAll 时不回填（缺席）的表集合。
	Omit map[string]struct{}
	// DropNil Tables 中值为 nil 的行集视同缺席（分类导出产物形态）。
	DropNil bool
	// Sections 备份声明的分类（导入侧按此过滤表集）。
	Sections []string
	// Config 全局配置区；nil 原样序列化为 null（与平台真实导出一致）。
	Config map[string]any
	// EmptyConfigIfNil 把 nil Config 归一为空对象（夹具默认形态）。
	EmptyConfigIfNil bool
}

// buildBackup 序列化一份 V2 备份 JSON（checksum 与真实导出口径一致）。
func buildBackup(t *testing.T, options backupFixtureOptions) string {
	t.Helper()
	tables := make(map[string][]map[string]any, len(configBackupTables))
	if options.FillAll {
		for _, table := range configBackupTables {
			if _, skip := options.Omit[table]; skip {
				continue
			}
			tables[table] = []map[string]any{}
		}
		tables["users"] = []map[string]any{{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	}
	for table, rows := range options.Tables {
		if options.DropNil && rows == nil {
			continue
		}
		tables[table] = rows
	}
	config := options.Config
	if config == nil && options.EmptyConfigIfNil {
		config = map[string]any{}
	}
	backup := configBackup{
		Sections: options.Sections,
		Meta: configBackupMeta{
			App:        "lazy-balancer-v2",
			Version:    2,
			ExportedAt: "2026-10-20T00:00:00Z",
			Checksum:   checksumBackupPayload(t, tables, config),
		},
		Config: config,
		Tables: tables,
	}
	return marshalJSONForTest(t, backup)
}

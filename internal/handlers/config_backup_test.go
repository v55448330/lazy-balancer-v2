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
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name'), (99, 'backup-admin', 'x', 'admin', '')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	router.PUT("/users/:id", h.UpdateUser)
	request := httptest.NewRequest(http.MethodPut, "/users/1", strings.NewReader(`{"role":"user"}`))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	assertUserState(t, "original", "user", "Original Name", "original-hash")
}

func TestUpdateUser_preserves_all_fields_when_password_rejected(t *testing.T) {
	// Given（bcrypt 只取前 72 字节，73 字符密码在绑定层被 400 拒绝；
	// 拒绝路径不得产生任何部分写入）
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name'), (99, 'backup-admin', 'x', 'admin', '')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	router.PUT("/users/:id", h.UpdateUser)
	body := `{"username":"changed","role":"user","display_name":"Changed Name","password":"` + strings.Repeat("p", 73) + `"}`
	request := httptest.NewRequest(http.MethodPut, "/users/1", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then（原断言 500：超长密码以前只能在 bcrypt 阶段失败，现在绑定层提前拦截）
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
	if _, err := db.DB.Exec("CREATE TRIGGER fail_user_role_update BEFORE UPDATE ON users WHEN NEW.role='user' BEGIN SELECT RAISE(ABORT,'role update failed'); END"); err != nil {
		t.Fatalf("create update failure trigger: %v", err)
	}
	router := gin.New()
	router.PUT("/users/:id", h.UpdateUser)
	request := httptest.NewRequest(http.MethodPut, "/users/1", strings.NewReader(`{"username":"changed","role":"user","display_name":"Changed Name"}`))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	assertUserState(t, "original", "admin", "Original Name", "original-hash")
}

func assertUserState(t *testing.T, username, role, displayName, passwordHash string) {
	t.Helper()
	var gotUsername, gotRole, gotDisplayName, gotPasswordHash string
	if err := db.DB.QueryRow("SELECT username, role, COALESCE(display_name,''), password_hash FROM users WHERE id=1").Scan(&gotUsername, &gotRole, &gotDisplayName, &gotPasswordHash); err != nil {
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
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
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
		clusterService: services.NewClusterService(db.DB, nil),
	}
}

func completeBackupJSON(t *testing.T, tables map[string][]map[string]any) string {
	t.Helper()
	completeTables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		completeTables[table] = []map[string]any{}
	}
	completeTables["users"] = []map[string]any{{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	for table, rows := range tables {
		completeTables[table] = rows
	}
	cfg := map[string]any{}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-19T00:00:00Z"},
		Config: cfg,
		Tables: completeTables,
	}
	// R45 F-3 起 v2 备份必带校验和，夹具按真实导出形态计算。
	backup.Meta.Checksum = checksumBackupPayload(t, completeTables, cfg)
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal complete backup: %v", err)
	}
	return string(data)
}

func TestImportConfigBackup_rejects_backup_without_enabled_admin_and_preserves_current_admin(t *testing.T) {
	tests := []struct {
		name  string
		users []map[string]any
	}{
		{name: "empty users", users: []map[string]any{}},
		{name: "users only", users: []map[string]any{{"id": 2, "username": "reader", "password_hash": "hash", "role": "user", "is_enabled": 1}}},
		{name: "all admins disabled", users: []map[string]any{{"id": 2, "username": "disabled-admin", "password_hash": "hash", "role": "admin", "is_enabled": false}}},
		// R39 C-1: is_enabled 为 null 的管理员在归一（NULL→1，对齐 migrateUsersIsEnabledNotNull）
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
			request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(completeBackupJSON(t, map[string][]map[string]any{"users": tt.users})))
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
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 7, "username": "enabled-admin", "password_hash": "hash", "role": "admin", "is_enabled": true, "password_version": 12}},
	})
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
	// R39 C-1: pre-R24/R36 库导出的全 null 管理员备份此前被
	// backupBooleanEnabled(nil)=false 先行 400 拦截，归一不可达；归一须在
	// checksum 之后、管理员校验之前执行：用户 is_enabled null→1、规则/上游
	// enabled null→0，导入成功且落库值正确。
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users":     {{"id": 2, "username": "null-admin", "password_hash": "hash", "role": "admin", "is_enabled": nil}},
		"lb_rules":  {{"caddy_id": "lb_nullnorm", "name": "null-rule", "protocol": "http", "domain": "nullnorm.example.test", "listen_port": 8080, "enabled": nil}},
		"upstreams": {{"rule_id": "lb_nullnorm", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": nil}},
	})
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

// C5 KNOWN-GAP-1：v2 备份导入通道对三张安全表的可空列零归一——带校验和的备份
// 携带 content/action/score/description/custom_rules 等 NULL 时，restoreTable 原样
// 落库（下游 raw 消费方：caddy.go 拦截页 content 扫描、自定义规则生成扫描），而
// 集群快照 dump 侧（cluster_snapshot.go:420/428/449）已全量 COALESCE 硬化——两条
// 「全量替换」通道容忍度背离。导入必须成功（无 400/500），且落库值为 dump 侧对齐
// 默认值而非 NULL；NULL 布尔列（enabled/is_default）落 schema/dump 默认而非布尔强转。
func TestImportConfigBackup_normalizes_null_security_rows(t *testing.T) {
	// Given：三张安全表各携带一行 NULL 毒化可空列
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_block_pages": {{"id": 2, "name": "null-poison-page", "description": nil, "content": nil, "is_default": nil}},
		"security_custom_rules": {{"id": 1, "name": "null-poison-rule",
			"conditions":  `[{"target":"uri","operator":"contains","pattern":"/nullpoison"}]`,
			"description": nil, "action": nil, "score": nil, "enabled": nil}},
		"security_policies": {{"id": 1, "name": "null-poison-policy", "description": nil, "custom_rules": nil}},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功，三表落库值均为 dump 侧对齐默认值（'' content、'block' action、
	// 5 score、1 enabled、'' description、'[]' custom_rules、0 is_default），而非 NULL
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var pageContent, pageDesc string
	var pageDefault int
	if err := db.DB.QueryRow("SELECT content, description, is_default FROM security_block_pages WHERE id=2").Scan(&pageContent, &pageDesc, &pageDefault); err != nil {
		t.Fatalf("read restored block page: %v", err)
	}
	if pageContent != "" || pageDesc != "" || pageDefault != 0 {
		t.Fatalf("block page=(content:%q desc:%q is_default:%d), want ('' '' 0)", pageContent, pageDesc, pageDefault)
	}
	var ruleAction, ruleDesc string
	var ruleScore, ruleEnabled int
	if err := db.DB.QueryRow("SELECT action, score, enabled, description FROM security_custom_rules WHERE id=1").Scan(&ruleAction, &ruleScore, &ruleEnabled, &ruleDesc); err != nil {
		t.Fatalf("read restored custom rule: %v", err)
	}
	if ruleAction != "block" || ruleScore != 5 || ruleEnabled != 1 || ruleDesc != "" {
		t.Fatalf("custom rule=(action:%q score:%d enabled:%d desc:%q), want ('block' 5 1 '')", ruleAction, ruleScore, ruleEnabled, ruleDesc)
	}
	var policyDesc, policyCustomRules string
	if err := db.DB.QueryRow("SELECT description, custom_rules FROM security_policies WHERE id=1").Scan(&policyDesc, &policyCustomRules); err != nil {
		t.Fatalf("read restored policy: %v", err)
	}
	if policyDesc != "" || policyCustomRules != "[]" {
		t.Fatalf("policy=(description:%q custom_rules:%q), want ('' '[]')", policyDesc, policyCustomRules)
	}
}

func TestValidateConfigImport_rejects_dangling_rule_references(t *testing.T) {
	// R39 C-3: 预览接口须与实际导入同序校验 upstreams/path_rules 引用存在性，
	// 否则悬挂引用备份在预览显示可导入、实际导入才 400。
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"upstreams": {{"rule_id": "lb_ghost_ref", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": 1}},
	})
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
	}{
		{name: "NULL status", status: nil},
		{name: "status outside allowed set", status: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			backup := completeBackupJSON(t, map[string][]map[string]any{
				"cert_jobs": {{"id": 1, "rule_id": "lb_invalid", "domain": "invalid.example", "status": test.status}},
			})
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

	// Then
	if exportResponse.Code != http.StatusOK || !strings.Contains(exportResponse.Body.String(), "lazy-balancer-v2") {
		t.Fatalf("export status=%d body=%.200s", exportResponse.Code, exportResponse.Body.String())
	}
	for header, expected := range map[string]string{
		"Cache-Control":          "no-store, private",
		"Pragma":                 "no-cache",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := exportResponse.Header().Get(header); got != expected {
			t.Fatalf("%s=%q, want %q", header, got, expected)
		}
	}
	backup := exportResponse.Body.String()

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
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
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
	if _, err := db.DB.Exec(`UPDATE global_config SET dns_credentials='dns-secret', admin_tls_cert='admin-cert', admin_tls_key='admin-key' WHERE id=1`); err != nil {
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
	if err := json.Unmarshal(exportResponse.Body.Bytes(), &backup); err != nil {
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
	intactChecks := []struct {
		got  string
		want string
		name string
	}{
		{backupString(backup.Config["dns_credentials"]), "dns-secret", "global_config.dns_credentials"},
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

func TestConfigBackup_roundtrips_security_version_tables(t *testing.T) {
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

	// When: export
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportResponse.Code, exportResponse.Body.String())
	}
	backup := exportResponse.Body.String()

	// Given: 清空两张版本表（含 auto_update 偏好丢失）
	if _, err := db.DB.Exec("DELETE FROM security_crs_version; DELETE FROM security_ip2region_version"); err != nil {
		t.Fatalf("wipe version tables: %v", err)
	}

	// When: import
	importResponse := httptest.NewRecorder()
	importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	importRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResponse, importRequest)

	// Then：两张表连同 auto_update 偏好一起恢复
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importResponse.Code, importResponse.Body.String())
	}
	var crsVersion string
	var crsAutoUpdate int
	var crsUpdateStatus, crsNextUpdate string
	if err := db.DB.QueryRow("SELECT version, auto_update, COALESCE(update_status,''), COALESCE(next_update,'') FROM security_crs_version WHERE id=1").Scan(&crsVersion, &crsAutoUpdate, &crsUpdateStatus, &crsNextUpdate); err != nil {
		t.Fatalf("read restored crs version: %v", err)
	}
	if crsVersion != "v4.14.0" || crsAutoUpdate != 1 || crsUpdateStatus != "checking" {
		t.Fatalf("restored crs version=%q auto_update=%d update_status=%q, want v4.14.0/1/checking", crsVersion, crsAutoUpdate, crsUpdateStatus)
	}
	assertNextUpdateRoundTrip(t, crsNextUpdate, 2099, time.January, 1, 0, 0, 0)
	var ip2regionVersion string
	var ip2regionAutoUpdate int
	var ip2regionUpdateStatus, ip2regionNextUpdate string
	if err := db.DB.QueryRow("SELECT version, auto_update, COALESCE(update_status,''), COALESCE(next_update,'') FROM security_ip2region_version WHERE id=1").Scan(&ip2regionVersion, &ip2regionAutoUpdate, &ip2regionUpdateStatus, &ip2regionNextUpdate); err != nil {
		t.Fatalf("read restored ip2region version: %v", err)
	}
	if ip2regionVersion != "v3.17.0" || ip2regionAutoUpdate != 0 || ip2regionUpdateStatus != "downloading" {
		t.Fatalf("restored ip2region version=%q auto_update=%d update_status=%q, want v3.17.0/0/downloading", ip2regionVersion, ip2regionAutoUpdate, ip2regionUpdateStatus)
	}
	assertNextUpdateRoundTrip(t, ip2regionNextUpdate, 2099, time.June, 6, 6, 6, 6)
}

func assertNextUpdateRoundTrip(t *testing.T, got string, year int, month time.Month, day, hour, minute, second int) {
	t.Helper()
	// next_update 为 DATETIME 列，导出经 JSON 序列化会被驱动规范化为 RFC3339 文本，
	// 导入后按同一 UTC 时刻做语义比对，而非逐字节比较。
	parsed, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("restored next_update %q is not RFC3339: %v", got, err)
	}
	if want := time.Date(year, month, day, hour, minute, second, 0, time.UTC); !parsed.Equal(want) {
		t.Fatalf("restored next_update=%v, want %v", parsed, want)
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
	importBackup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-19T00:00:00Z"},
		Config: importCfg,
		Tables: completeTables,
	}
	importBackup.Meta.Checksum = checksumBackupPayload(t, completeTables, importCfg)
	body, err := json.Marshal(importBackup)
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

// N+12 G4：metrics_retention_days 属导入钳制家族——cleanupHistory 仅兜底 <1，
// 越界值（如 100000000 天）会让指标历史清理窗口永远够不到任何行，
// metrics_history 无界增长（与 jwt/audit_retention/证书数值/请求体上限同族）。
func TestImportConfigBackup_clamps_metrics_retention_days(t *testing.T) {
	for _, item := range []struct {
		name  string
		value any
		want  int
	}{
		{name: "excessive clamps to 3650", value: 100000000, want: 3650},
		{name: "below range clamps to 1", value: 0, want: 1},
		{name: "invalid form resets to 7", value: "bogus", want: 7},
	} {
		t.Run(item.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			completeTables := make(map[string][]map[string]any, len(configBackupTables))
			for _, table := range configBackupTables {
				completeTables[table] = []map[string]any{}
			}
			completeTables["users"] = []map[string]any{{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
			importCfg := map[string]any{"metrics_retention_days": item.value}
			importBackup := configBackup{
				Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-19T00:00:00Z"},
				Config: importCfg,
				Tables: completeTables,
			}
			importBackup.Meta.Checksum = checksumBackupPayload(t, completeTables, importCfg)
			body, err := json.Marshal(importBackup)
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

			// Then
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
			}
			var retentionDays int
			if err := db.DB.QueryRow("SELECT metrics_retention_days FROM global_config WHERE id=1").Scan(&retentionDays); err != nil {
				t.Fatalf("read imported metrics retention: %v", err)
			}
			if retentionDays != item.want {
				t.Fatalf("metrics_retention_days=%d, want %d", retentionDays, item.want)
			}
		})
	}
}

func TestImportConfigBackup_remaps_rule_updated_by_to_restored_user(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users":      {{"id": 7, "username": "importer", "password_hash": "hash", "role": "admin", "is_enabled": true, "password_version": 0}},
		"lb_rules":   {{"caddy_id": "lb_remap", "name": "remap", "protocol": "http", "domain": "remap.example.test", "listen_port": 8080, "enabled": true}},
		"upstreams":  {{"rule_id": "lb_remap", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": true}},
		"cert_jobs":  {},
		"api_keys":   {},
		"path_rules": {},
	})
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

func TestImportConfigBackup_rejects_backup_missing_operator_account(t *testing.T) {
	// 审计 B3：备份不含操作者自身账户=永久自锁——导入全量替换 users/api_keys，
	// 操作者账户被清且 password_version 递增使其 JWT 同时失效，导入后无法登录；
	// 既有「至少一个启用管理员」门（备份内 otheradmin）拦不住操作者本人缺席。
	// 校验期前置 400 拒绝，零写入（users/lb_rules 均不被替换）。
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'operator-admin','hash','admin',1);
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,updated_by) VALUES ('lb_pre','pre','http','pre.example.test',8080,1,1);
		INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_pre','127.0.0.1',9000,1,1)`); err != nil {
		t.Fatalf("seed operator and rule: %v", err)
	}
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users":     {{"id": 50, "username": "otheradmin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		"lb_rules":  {{"caddy_id": "lb_selflock", "name": "selflock", "protocol": "http", "domain": "selflock.example.test", "listen_port": 8082, "enabled": true, "updated_by": 50}},
		"upstreams": {{"rule_id": "lb_selflock", "host": "127.0.0.1", "port": 9001, "weight": 1, "enabled": true}},
	})
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("username", "operator-admin"); c.Next() })
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：400 自锁消息，且表未被替换（操作者仍在、备份数据未入库、原规则归属保留）
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "导入的备份不包含当前操作账户") {
		t.Fatalf("body=%s, want self-lockout message", response.Body.String())
	}
	var operatorCount, otherAdminCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='operator-admin'").Scan(&operatorCount); err != nil {
		t.Fatalf("read operator: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='otheradmin'").Scan(&otherAdminCount); err != nil {
		t.Fatalf("read backup admin: %v", err)
	}
	if operatorCount != 1 || otherAdminCount != 0 {
		t.Fatalf("users after rejected import: operator=%d otheradmin=%d, want 1/0（表未替换）", operatorCount, otherAdminCount)
	}
	var preUpdatedBy sql.NullInt64
	var selflockCount int
	if err := db.DB.QueryRow("SELECT updated_by FROM lb_rules WHERE caddy_id='lb_pre'").Scan(&preUpdatedBy); err != nil {
		t.Fatalf("read pre-import rule: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_selflock'").Scan(&selflockCount); err != nil {
		t.Fatalf("read imported rule: %v", err)
	}
	if selflockCount != 0 || !preUpdatedBy.Valid || preUpdatedBy.Int64 != 1 {
		t.Fatalf("lb_rules after rejected import: selflock=%d pre updated_by=%+v, want 0/1（归属保留）", selflockCount, preUpdatedBy)
	}
}

func TestImportConfigBackup_preserves_backup_rule_attribution_without_operator_context(t *testing.T) {
	// 审计 B3：归属重映射仅在操作者存在时执行——无操作者上下文时，备份行自带的
	// updated_by 必须原样保留，不得写 NULL 抹掉全部规则归属（操作者非空但缺席
	// 备份的场景已被自锁前置门 400 拦截，见上一用例）。
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":  {{"caddy_id": "lb_attr", "name": "attr", "protocol": "http", "domain": "attr.example.test", "listen_port": 8083, "enabled": true, "updated_by": 7}},
		"upstreams": {{"rule_id": "lb_attr", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": true}},
	})
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
}

func TestImportConfigBackup_requeues_imported_non_terminal_certificate_jobs(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	services.GetCAQueueManager().PauseAndDrain()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_requeue_v2','requeue','http','requeue.example.test',8080,1,1,'acme_dns');
		INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('admin','hash','admin',1);
		INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_requeue_v2','127.0.0.1',9000,1,1);
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES ('lb_requeue_v2','requeue.example.test','creating_order',999999)`); err != nil {
		t.Fatalf("seed non-terminal job: %v", err)
	}
	// R53 发现2/A-2 起启用 acme_dns 规则须引用有效证书配置（备份内可解析），
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
	services.InitCAQueueManager(func() error { return nil })
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

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "配置已导入但证书任务恢复失败") || !strings.Contains(response.Body.String(), "requeue failed") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestImportConfigBackup_joins_import_and_certificate_job_recovery_failures(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_bad_recovery", "name": "bad", "protocol": "http", "domain": "bad-recovery.example.test", "listen_port": 8443, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"}},
	})
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

func TestValidateConfigImport_rejects_v2_backup_missing_required_contract(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	tests := []struct {
		name string
		body string
	}{
		{name: "unsupported version", body: `{"meta":{"app":"lazy-balancer-v2","version":3},"tables":{"lb_rules":[],"users":[]}}`},
		{name: "missing tables", body: `{"meta":{"app":"lazy-balancer-v2","version":2}}`},
		{name: "missing users", body: `{"meta":{"app":"lazy-balancer-v2","version":2},"tables":{"lb_rules":[]}}`},
		{name: "missing global config", body: `{"meta":{"app":"lazy-balancer-v2","version":2},"tables":{"lb_rules":[],"upstreams":[],"path_rules":[],"users":[],"api_keys":[],"ca_providers":[],"certificate_configs":[],"cert_jobs":[]}}`},
		{name: "missing exported table", body: `{"meta":{"app":"lazy-balancer-v2","version":2},"config":{},"tables":{"lb_rules":[],"upstreams":[],"path_rules":[],"users":[],"api_keys":[],"ca_providers":[],"certificate_configs":[]}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, request)

			// Then
			var envelope struct {
				Data importValidateResponse `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode validation response: %v", err)
			}
			if envelope.Data.Valid {
				t.Fatalf("validation accepted invalid v2 backup: %s", response.Body.String())
			}
			if envelope.Data.Type != "v2" {
				t.Fatalf("validation type=%q, want v2", envelope.Data.Type)
			}
		})
	}
}

func TestValidateV2Backup_credentials_must_be_json_object(t *testing.T) {
	tests := []struct {
		name        string
		caCred      string
		dnsCred     string
		wantErrText string
	}{
		{name: "ca_providers invalid", caCred: "not-json", wantErrText: "凭证格式"},
		{name: "ca_providers valid object", caCred: `{"eab_kid":"x"}`},
		{name: "ca_providers empty object", caCred: `{}`},
		{name: "ca_providers empty string", caCred: ""},
		{name: "ca_providers array rejected", caCred: `["a"]`, wantErrText: "凭证格式"},
		{name: "certificate_configs invalid", dnsCred: "not-json", wantErrText: "凭证格式"},
		{name: "certificate_configs valid object", dnsCred: `{"dns_id":"x"}`},
		{name: "certificate_configs empty object", dnsCred: `{}`},
		{name: "certificate_configs empty string", dnsCred: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backup := completeBackupJSON(t, map[string][]map[string]any{
				"ca_providers":        {{"credentials": tt.caCred}},
				"certificate_configs": {{"dns_credentials": tt.dnsCred}},
			})
			var b configBackup
			if err := json.Unmarshal([]byte(backup), &b); err != nil {
				t.Fatalf("unmarshal backup: %v", err)
			}

			_, err := validateV2Backup(b)
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
			// Round 30 F-1: 禁用规则不参与渲染（caddy.go WHERE enabled=1），
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
			backup := completeBackupJSON(t, map[string][]map[string]any{"lb_rules": {tt.rule}})
			var b configBackup
			if err := json.Unmarshal([]byte(backup), &b); err != nil {
				t.Fatalf("unmarshal backup: %v", err)
			}
			// R38 C-3 拆分后：逐行校验在 validateV2BackupRules（handler 在
			// skipEmptyDomainHTTPRules 之后调用）；直测时组合两者保持原语义。
			// R55 C-1：TLS 形态校验在 validateV2BackupTLSShape，一并串联。
			_, err := validateV2Backup(b)
			if err == nil {
				err = validateV2BackupRules(b.Tables)
			}
			if err == nil {
				err = validateV2BackupTLSShape(b.Tables)
			}
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

// R62 B-NEW-1：v2 导入域名规范化门——通配/非法域名整包 400（用户裁决：系统
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
			name:        "空 protocol 的通配域名同被拒（Round 35 I-10 同口径）",
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
			backup := completeBackupJSON(t, map[string][]map[string]any{"lb_rules": {tt.rule}})
			var b configBackup
			if err := json.Unmarshal([]byte(backup), &b); err != nil {
				t.Fatalf("unmarshal backup: %v", err)
			}
			// R38 C-3 同款链序：空域名 http 行先软跳过（返回跳过警告，非 error）。
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

// R62 C3-F2：v2 导入 upstreams.protocol 白名单——与保存侧 validateUpstreams 同口径，
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

// R62 C2-N1（传播通道钳制）: v2 备份中 TCP + enable_tls=1 + 空证书的行被静默钳制
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
	if v, _ := rule["enable_tls"].(int); v != 0 {
		t.Fatalf("enable_tls=%v, want clamped 0", rule["enable_tls"])
	}
	if rule["tls_cert"] != "" || rule["tls_key"] != "" {
		t.Fatalf("tls_cert=%v tls_key=%v, want cleared", rule["tls_cert"], rule["tls_key"])
	}
}

func TestImportConfigBackup_rejects_invalid_credentials_json(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"ca_providers": {{"credentials": "not-json"}},
	})
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
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users":    {{"id": 2, "username": "new-user", "password_hash": "hash", "role": "admin"}},
		"lb_rules": {{"caddy_id": "lb_badcert", "name": "new-rule", "protocol": "http", "listen_port": 8443, "enabled": 1, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"}},
	})
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
	backup := completeBackupJSON(t, map[string][]map[string]any{
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
	})
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
	if harness.loadCalls() != 1 || harness.currentConfig() != `{"marker":"before-import"}` {
		t.Fatalf("Caddy loads=%d config=%s, want one restore to pre-import config", harness.loadCalls(), harness.currentConfig())
	}
}

func TestImportConfigBackup_reports_import_and_runtime_restore_failures(t *testing.T) {
	// Given
	harness := newImportRollbackHarness(t)
	harness.failRestore()
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_bad_restore", "name": "bad-cert", "protocol": "http", "domain": "bad-restore.example.test", "listen_port": 8443, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"}},
	})
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
	// Given：pre-R36 库导出的备份含 "enabled":null 的行（R36 起两表 NOT NULL，
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
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":  {ruleRow},
		"upstreams": {upstreamRow},
	})))
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

// R38 C-1: pre-R24 库的 users.is_enabled 为可空列（R24 起 NOT NULL），旧实例导出的
// "is_enabled":null 行导入 R24+ 库会触发约束失败整包回滚；归一为 1（与
// lb_rules/upstreams 的 NULL→0 不同，对齐 migrateUsersIsEnabledNotNull 口径）。
func TestImportConfigBackup_normalizesNullUserIsEnabled(t *testing.T) {
	// Given：备份含一个 is_enabled:null 用户行（pre-R24 遗留）+ 一个启用 admin
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(completeBackupJSON(t, map[string][]map[string]any{
		"users": {
			{"id": 2, "username": "legacy-null", "password_hash": "hash", "role": "user", "is_enabled": nil},
			{"id": 3, "username": "enabled-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1},
		},
	})))
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

// R38 C-3: skipEmptyDomainHTTPRules 必须先于逐行校验——空域名行无论端口是否非法
// 都一律软跳过并告警；非空域名+非法端口行仍整包 400。
func TestImportConfigBackup_skips_empty_domain_rule_before_row_validation(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	importBackup := func(backup string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	t.Run("空域名+非法端口行软跳过并告警", func(t *testing.T) {
		backup := completeBackupJSON(t, map[string][]map[string]any{
			"lb_rules": {
				{"caddy_id": "lb_empty_badport", "name": "empty-bad-port", "protocol": "http", "domain": "", "listen_port": 0, "enabled": 1},
				{"caddy_id": "lb_valid", "name": "valid", "protocol": "http", "domain": "valid.example.test", "listen_port": 8442, "enabled": 1},
			},
			"upstreams": {
				{"rule_id": "lb_empty_badport", "host": "127.0.0.1", "port": 9001, "weight": 1, "enabled": 1},
				{"rule_id": "lb_valid", "host": "127.0.0.1", "port": 9002, "weight": 1, "enabled": 1},
			},
		})
		response := importBackup(backup)
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
		backup := completeBackupJSON(t, map[string][]map[string]any{
			"lb_rules": {{"caddy_id": "lb_badport", "name": "bad-port", "protocol": "http", "domain": "badport.example.test", "listen_port": 0, "enabled": 1}},
		})
		response := importBackup(backup)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "1-65535") {
			t.Fatalf("status=%d body=%s, want 400 invalid port", response.Code, response.Body.String())
		}
	})
}

// SC-BAK-01: Config backup export → import round-trip preserves multi-row
// security_policy_bindings (one rule → multiple policies). Post-import
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
	backup := exportResponse.Body.String()

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

// SC-BAK-01 (dangling): Backup import validates binding references and rejects
// rows pointing to non-existent policies (R49 C-#2). Pin this behavior.
func TestConfigBackup_danglingBindingRejected(t *testing.T) {
	// Given: a backup where lb_dangle binds to policy 1 (valid) and policy 99
	// (no such row in security_policies).
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := completeBackupJSON(t, map[string][]map[string]any{
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
	})
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

// audit I-A：restoreTable 的 NULL→默认值归一此前三张安全表专属（C5 KNOWN-GAP-1），
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
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 2, "username": "null-user", "password_hash": "hash", "role": "admin", "is_enabled": nil,
			"display_name": nil, "created_at": nil, "last_login": nil,
			"mfa_enabled": nil, "mfa_secret": nil, "mfa_recovery_codes": nil, "mfa_locked_until": nil}},
		"lb_rules": {{"caddy_id": "lb_nulldump", "name": "null-cols", "protocol": "http", "domain": "nulldump.example.test",
			"listen_port": 8461, "enabled": nil, "description": nil, "strategy": nil, "dns_server": nil, "dns_family": nil,
			"health_check_path": nil, "host_header": nil, "tls_source": nil, "compress_types": nil, "enable_compress": nil,
			"server_tokens_hidden": nil, "tcp_try_interval": nil, "health_check_interval": nil,
			"created_by": nil, "updated_by": nil, "enable_tls": 0, "custom_routes_enabled": 1,
			"created_at": nil, "updated_at": nil}},
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
		"certificate_configs": {{"id": 91, "name": "null-dns", "dns_provider": nil, "dns_credentials": nil, "enabled": nil,
			"created_at": nil, "updated_at": nil}},
		"cert_jobs": {{"id": 1, "rule_id": "lb_nulldump", "domain": "nulldump.example.test", "status": "issued",
			"ca_provider_id": nil, "renewal_attempts": nil, "deployment_attempts": nil, "created_at": nil,
			"message": nil, "expires_at": nil, "key_pem": nil, "ca_available_after": nil,
			"last_error_code": nil, "deployment_available_after": nil, "updated_at": nil}},
		"security_policies":          {{"id": 1, "name": "null-bind-policy"}},
		"security_policy_bindings":   {{"rule_caddy_id": "lb_nulldump", "policy_id": 1}},
		"security_crs_version":       {{"id": 1, "version": "v4.99.0", "updated_at": nil, "auto_update": nil, "update_status": nil, "message": nil, "last_checked": nil, "next_update": nil, "trigger": nil, "started_at": nil, "finished_at": nil, "consecutive_failures": nil}},
		"security_ip2region_version": {{"id": 1, "version": "v3.99.0", "updated_at": nil, "auto_update": nil, "update_status": nil, "message": nil, "last_checked": nil, "next_update": nil, "trigger": nil, "started_at": nil, "finished_at": nil, "consecutive_failures": nil}},
	})
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
	var mfaSecret, mfaRecovery, mfaLocked sql.NullString
	if err := db.DB.QueryRow("SELECT mfa_secret, mfa_recovery_codes, mfa_locked_until FROM users WHERE username='null-user'").Scan(&mfaSecret, &mfaRecovery, &mfaLocked); err != nil {
		t.Fatalf("read normalized mfa columns: %v", err)
	}
	if !mfaSecret.Valid || mfaSecret.String != "" || !mfaRecovery.Valid || mfaRecovery.String != "[]" || !mfaLocked.Valid || mfaLocked.String != "" {
		t.Fatalf("users mfa normalized: secret=%+v recovery=%+v locked=%+v, want ''/'[]'/''", mfaSecret, mfaRecovery, mfaLocked)
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
		FROM cert_jobs WHERE rule_id=? ORDER BY id`, "lb_nulldump")
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
	// 消费点 4b（certjobs.go 列表同形）：j.created_at 为 raw time.Time 扫描。
	var jobCreatedAt time.Time
	if err := db.DB.QueryRow("SELECT j.created_at FROM cert_jobs j WHERE j.rule_id=?", "lb_nulldump").Scan(&jobCreatedAt); err != nil {
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
	for _, versionTable := range []string{"security_crs_version", "security_ip2region_version"} {
		var autoUpdate, consecutiveFailures sql.NullInt64
		var updateStatus, versionMessage, nextUpdate sql.NullString
		if err := db.DB.QueryRow("SELECT auto_update, update_status, message, next_update, consecutive_failures FROM "+versionTable+" WHERE id=1").Scan(&autoUpdate, &updateStatus, &versionMessage, &nextUpdate, &consecutiveFailures); err != nil {
			t.Fatalf("read normalized %s: %v", versionTable, err)
		}
		if !autoUpdate.Valid || autoUpdate.Int64 != 1 || !updateStatus.Valid || updateStatus.String != "idle" ||
			!versionMessage.Valid || versionMessage.String != "" || !nextUpdate.Valid || nextUpdate.String != "" {
			t.Fatalf("%s defaults: auto_update=%+v update_status=%+v message=%+v next_update=%+v, want 1/'idle'/''/''", versionTable, autoUpdate, updateStatus, versionMessage, nextUpdate)
		}
		if !consecutiveFailures.Valid || consecutiveFailures.Int64 != 0 {
			t.Fatalf("%s consecutive_failures=%+v, want 0 (null normalized)", versionTable, consecutiveFailures)
		}
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

// audit I-A 同构回归：dump→restore→dump 往返必须逐字节稳定（fresh backup 的
// 表区语义相等）——归一只替换显式 NULL，不得改变任何非 NULL 值。种子库先经
// 一次导入「愈合并」（对齐集群通道/恢复后库的规范形态），随后 A=export →
// import(A) → B=export 必须语义相等（唯一豁免：导入固定递增 users.password_version
// 吊销旧 JWT，A 侧 +1 后比较）。
func TestConfigBackup_restore_dump_isomorphism_roundtrip(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,created_at,last_login,password_version,
		mfa_enabled,mfa_secret,mfa_recovery_codes,mfa_last_timestep,mfa_failed_attempts,mfa_locked_until)
		VALUES (1,'iso-admin','hash','admin','Iso Admin',1,'2026-01-02 03:04:05',NULL,5,0,'','[]',0,0,'')`); err != nil {
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
		VALUES (95,'iso-ca','letsencrypt','https://ca.iso/dir','{"eab_kid":"k"}',4,1500,1,'2026-01-02 03:04:05','2026-01-02 03:04:05')`); err != nil {
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
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)
	doExport := func() map[string]any {
		t.Helper()
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config/export", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("export status=%d body=%.300s", response.Code, response.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
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
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config/export", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("export status=%d body=%.300s", response.Code, response.Body.String())
		}
		return response.Body.String()
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

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func TestOIDCReturnToCap(t *testing.T) {
	if got := sanitizeOIDCReturnTo("/rules?x=1"); got == "" {
		t.Fatalf("合法站内路径不应被丢弃")
	}
	if got := sanitizeOIDCReturnTo("/" + strings.Repeat("a", oidcReturnToMaxBytes)); got != "" {
		t.Fatalf("超长 return_to 必须丢弃，got len=%d", len(got))
	}
	if got := sanitizeOIDCReturnTo("//evil.example.com"); got != "" {
		t.Fatalf("协议相对路径必须丢弃")
	}
}

func TestOIDCJWKSProbe(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA"}]}`))
	}))
	defer ok.Close()
	if err := probeOIDCJWKS(ok.URL, ok.URL); err != nil {
		t.Fatalf("合法 JWKS 应通过: %v", err)
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer empty.Close()
	if err := probeOIDCJWKS(empty.URL, empty.URL); err == nil {
		t.Fatalf("空密钥集必须失败")
	}

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer broken.Close()
	if err := probeOIDCJWKS(broken.URL, broken.URL); err == nil {
		t.Fatalf("非 200 必须失败")
	}
	if err := probeOIDCJWKS("", ""); err == nil {
		t.Fatalf("缺失 jwks_uri 必须失败")
	}
}

func TestOIDCIssuerURLPolicy(t *testing.T) {
	cases := []struct {
		url string
		ok  bool
	}{
		{"https://idp.example.com", true},
		{"http://127.0.0.1:8080", true},
		{"http://[::1]:8080", true},
		{"http://idp.example.com", false},
		{"httpxy://idp.example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		if err := validateOIDCIssuerURL(tc.url); (err == nil) != tc.ok {
			t.Fatalf("validateOIDCIssuerURL(%q) err=%v, want ok=%v", tc.url, err, tc.ok)
		}
	}
}

func TestOIDCTestEndpointRejectsPlainHTTPIssuer(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/test", strings.NewReader(`{"issuer":"http://example.com/"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非回环 http issuer 必须 400，got %d %s", rec.Code, rec.Body.String())
	}
}

func TestGetCaddyConfigRequiresAdmin(t *testing.T) {
	h := newBackupTestHandlers(t)

	call := func(role, authType string, readOnly bool) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/caddy/config", nil)
		c.Set("role", role)
		c.Set("auth_type", authType)
		c.Set("api_key_read_only", readOnly)
		h.GetCaddyConfig(c)
		return rec
	}
	if rec := call("user", "jwt", false); rec.Code != http.StatusForbidden {
		t.Fatalf("非管理员 status=%d, want 403", rec.Code)
	}
	if rec := call("admin", "api_key", true); rec.Code != http.StatusForbidden {
		t.Fatalf("只读 API Key status=%d, want 403", rec.Code)
	}
	if rec := call("admin", "jwt", false); rec.Code != http.StatusOK {
		t.Fatalf("管理员 status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
}

func TestToggleUserStatusMissingFieldRejected(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin-1", "admin", true)
	seedUserAuditTest(t, 9, "target", "user", true)

	rec := serveUserMutation(h, http.MethodPut, "/users/9", `{}`, 1, h.ToggleUserStatus)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("{} status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT is_enabled FROM users WHERE id=9").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatalf("缺字段请求不得禁用用户")
	}
}

func TestUpdateUserResponseCarriesMFA(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin-1", "admin", true)
	seedUserAuditTest(t, 9, "target", "user", true)
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1 WHERE id=9"); err != nil {
		t.Fatal(err)
	}
	rec := serveUserMutation(h, http.MethodPut, "/users/9", `{"display_name":"renamed"}`, 1, h.UpdateUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			MFAEnabled bool `json:"mfa_enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Data.MFAEnabled {
		t.Fatalf("PUT /users/:id 响应 mfa_enabled 必须与库一致（true）")
	}
}

func TestPatchCurrentUserResponseCarriesMFA(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin-1", "admin", true)
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPatch, "/users/me", strings.NewReader(`{"display_name":"nick"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user_id", float64(1))
	h.UpdateCurrentUser(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			MFAEnabled bool `json:"mfa_enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Data.MFAEnabled {
		t.Fatalf("PATCH /users/me 响应 mfa_enabled 必须为 true")
	}
}

func TestDirBytesCountsWholeFileGz(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "certjob-lb_x.log")
	if err := os.WriteFile(base, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".gz", bytes.Repeat([]byte("z"), 100), 0o600); err != nil {
		t.Fatal(err)
	}
	active, rotated, count := dirBytesWithEntries(base, nil)
	if active != 4 || rotated != 100 || count != 1 {
		t.Fatalf("active=%d rotated=%d count=%d, want 4/100/1", active, rotated, count)
	}
}

func TestAutoBackupSettingsSectionsSemantics(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec("UPDATE global_config SET auto_backup_sections=NULL WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	rec := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Sections []string `json:"sections"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	want := allBackupSectionKeys()
	if len(resp.Data.Sections) != len(want) {
		t.Fatalf("NULL sections 应展开为全量 %v，got %v", want, resp.Data.Sections)
	}
	for i := range want {
		if resp.Data.Sections[i] != want[i] {
			t.Fatalf("NULL sections=%v, want %v", resp.Data.Sections, want)
		}
	}

	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_sections='[]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	rec = serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("损坏/空数组 sections 必须显式 500，got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLbbakRequiresCoreChecksums(t *testing.T) {
	raw := craftLbbakRaw(t, map[string][]byte{
		"manifest.json": []byte(`{"format":"lbbak","checksum":{}}`),
		"config.json":   []byte(`{}`),
	})
	if _, err := parseLbbak(raw); err == nil || !strings.Contains(err.Error(), "校验和") {
		t.Fatalf("未登记 config.json 校验和必须拒绝，err=%v", err)
	}
	raw = craftLbbakRaw(t, map[string][]byte{
		"manifest.json":     []byte(`{"format":"lbbak","checksum":{"config.json":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"}}`),
		"config.json":       []byte(`{}`),
		"waf/ip2region.xdb": []byte("XDB"),
	})
	if _, err := parseLbbak(raw); err == nil {
		t.Fatalf("未登记 xdb 校验和必须拒绝")
	}
}

func TestTLSCertWarningsIncludeExpiry(t *testing.T) {
	certPEM, keyPEM, err := generateTestCert("expired.example.com", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	warnings := tlsCertificateWarnings(certPEM, keyPEM, "expired.example.com")
	if !strings.Contains(strings.Join(warnings, "；"), "已过期") {
		t.Fatalf("过期证书必须产生非阻断警告，got %v", warnings)
	}
	certPEM, keyPEM, err = generateTestCert("future.example.com", time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	warnings = tlsCertificateWarnings(certPEM, keyPEM, "future.example.com")
	if !strings.Contains(strings.Join(warnings, "；"), "尚未生效") {
		t.Fatalf("未生效证书必须产生非阻断警告，got %v", warnings)
	}
}

func TestV2ImportStageBlockPageGate(t *testing.T) {
	rule := map[string]any{
		"caddy_id": "lb_stage", "name": "stage", "protocol": "http",
		"listen_port": 8080, "domain": "stage.example.com", "enabled": 1,
		"block_page_stage1_id": 7, "block_page_stage1_status": 418,
	}
	tables := map[string][]map[string]any{
		"lb_rules":             {rule},
		"security_block_pages": {{"id": 7}},
	}
	if err := validateV2BackupRules(tables); err == nil || !strings.Contains(err.Error(), "状态码") {
		t.Fatalf("非法阶段状态码必须 400，err=%v", err)
	}

	rule["block_page_stage1_status"] = 403
	rule["block_page_stage1_id"] = 99
	if err := validateV2BackupRules(tables); err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("悬空阶段拦截页必须 400，err=%v", err)
	}

	rule["block_page_stage1_id"] = 0
	rule["block_page_stage1_status"] = 0
	if err := validateStageBlockPageRefWith(0, 403, "阶段 1", func(int) (bool, error) { return true, nil }); err == nil {
		t.Fatalf("有码无页必须 400")
	}
}

func TestV2ImportCustomRuleRefs(t *testing.T) {
	policies := []map[string]any{{
		"id": 1, "name": "p1", "custom_rules": "[999999]",
	}}
	tables := map[string][]map[string]any{
		"security_policies":     policies,
		"security_custom_rules": {},
	}
	if err := validateV2BackupSecurityPolicies(tables, false); err == nil || !strings.Contains(err.Error(), "自定义规则") {
		t.Fatalf("悬空 custom_rules 必须 400，err=%v", err)
	}
	tables["security_custom_rules"] = []map[string]any{{"id": 999999}}
	if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
		t.Fatalf("合法 custom_rules 不应被拒: %v", err)
	}
}

func TestPostLockRevalidationCatchesLiveDrift(t *testing.T) {
	h := newBackupTestHandlers(t)
	_ = h
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_frequency='weekly', auto_backup_day=9 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	backup := &configBackup{Config: map[string]any{"auto_backup_time": "03:00"}}
	if err := revalidateImportLiveDependencies(context.Background(), tx, backup, map[string]bool{}); err == nil {
		t.Fatalf("锁内合并视图 weekly/day=9 必须被拒")
	}
}

func TestConflictDisableBeforeRowValidation(t *testing.T) {
	rows := []map[string]any{
		{"caddy_id": "lb_a", "name": "a", "protocol": "http", "listen_port": 8080, "domain": "Dup.Example.com", "enabled": 1},
		{"caddy_id": "lb_b", "name": "b", "protocol": "http", "listen_port": 8080, "domain": "dup.example.com", "enabled": 1,
			"enable_tls": 1, "tls_http_redirect": 1},
	}
	canonicalizeBackupRuleDomains(rows)
	conflicts := disableV2RuleConflicts(rows)
	if len(conflicts) == 0 {
		t.Fatalf("重复域名+端口必须产生冲突")
	}
	tables := map[string][]map[string]any{
		"lb_rules":   rows,
		"upstreams":  {},
		"path_rules": {},
	}
	if err := validateV2BackupRules(tables); err != nil {
		t.Fatalf("已被冲突矩阵禁用的行不应参与 enabled-only 校验: %v", err)
	}
}

// / 05 / 07（备份枚举与形状） ----------

func TestBackupBooleanEnumsCoverCrawlerAndThreat(t *testing.T) {
	if !isBackupBooleanColumn("security_crawler_sources", "update_enabled") {
		t.Fatalf("security_crawler_sources.update_enabled 必须登记")
	}
	for _, key := range []string{"threat_auto_update", "crawler_auto_update"} {
		found := false
		for _, candidate := range backupBooleanConfigKeys {
			if candidate == key {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s 必须登记为布尔配置键", key)
		}
	}
}

func TestBackupTablesNullRejected(t *testing.T) {
	var backup configBackup
	if err := json.Unmarshal([]byte(`{"tables":{"lb_rules":null}}`), &backup); err == nil {
		t.Fatalf("tables 值为 null 必须解码失败（不得当空表清空）")
	}
	if err := json.Unmarshal([]byte(`{"tables":{"lb_rules":[null]}}`), &backup); err == nil {
		t.Fatalf("行元素 null 必须解码失败")
	}
	if err := json.Unmarshal([]byte(`{"tables":{"lb_rules":[]}}`), &backup); err != nil {
		t.Fatalf("合法空数组不应被拒: %v", err)
	}
}

func TestWafRefBookkeepingProtected(t *testing.T) {
	for _, key := range []string{"applied_waf_ref_hash", "applied_waf_ref_version"} {
		if !configBackupProtectedConfigKeys[key] {
			t.Fatalf("%s 必须为保护键（节点本地文件态记账）", key)
		}
	}
}

// （TCP 规则不物化证书） ----------

func TestCollectImportCertificatesSkipsTCP(t *testing.T) {
	certPEM, keyPEM, err := generateTestCert("tcp.example.com", time.Now(), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	rows := []map[string]any{
		{"caddy_id": "lb_tcp", "name": "tcp", "protocol": "tcp", "domain": "tcp.example.com", "enable_tls": true, "tls_cert": certPEM, "tls_key": keyPEM},
		{"caddy_id": "lb_http", "name": "http", "protocol": "http", "domain": "tcp.example.com", "enable_tls": true, "tls_cert": certPEM, "tls_key": keyPEM},
	}
	certs, warnings := collectImportCertificates(rows)
	if len(certs) != 1 || certs[0].ruleID != "lb_http" {
		t.Fatalf("仅 HTTP 规则应物化证书，got %+v", certs)
	}
	for _, warning := range warnings {
		if strings.Contains(warning, "lb_tcp") {
			t.Fatalf("TCP 行不得进入证书警告: %s", warning)
		}
	}
}

// （威胁文件与源表收敛） ----------

func TestReconcileThreatFiles(t *testing.T) {
	wafDir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(wafDir)
	t.Cleanup(restore)

	write := func(name string) {
		if err := os.WriteFile(filepath.Join(wafDir, name), []byte("1.2.3.4\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("threat-ustc.iplist")
	write("threat-ustc.iplist.fast")
	write("threat-stray.iplist")
	write("threat-kept.iplist")
	write("threat-kept.iplist.fast")

	tables := map[string][]map[string]any{
		"security_threat_sources": {
			{"name": "ustc"},
			{"name": "kept"},
		},
	}
	payload := &lbbakPayload{ThreatIplists: map[string][]byte{"kept": []byte("5.6.7.8\n")}}
	warnings, _ := reconcileImportedThreatFiles(tables, payload, nil)
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist")); !os.IsNotExist(err) {
		t.Fatalf("空源 ustc 的旧文件必须删除")
	}
	// .iplist 与 .fast 是成对文件（removePair 双删）：只断言文本删除时，
	// 二进制残留会让从节点 .fast 回退继续用已删除源的前缀集（删不掉=源表
	// 收敛假成功）。
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist.fast")); !os.IsNotExist(err) {
		t.Fatalf("空源 ustc 的 .fast 副本必须一并删除（否则从节点回退读到幽灵前缀集）")
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-stray.iplist")); !os.IsNotExist(err) {
		t.Fatalf("源表已不存在的 stray 文件必须删除")
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-kept.iplist")); err != nil {
		t.Fatalf("保留源文件被误删: %v", err)
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-kept.iplist.fast")); err != nil {
		t.Fatalf("保留源的 .fast 被误删: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatalf("删除动作必须产出可见警告")
	}
}

// （手动备份 202 原子受理） ----------

func TestRunAutoBackupNowRejectsPausedBefore202(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	wireAutoBackupEngineForTest(t, h)
	te := services.TaskEngine()
	te.PauseScheduling()
	t.Cleanup(te.ResumeScheduling)

	rec := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/run", "/auto-backup/run", "", h.RunAutoBackupNow)
	if rec.Code != http.StatusConflict {
		t.Fatalf("调度暂停时 status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "暂停") {
		t.Fatalf("body=%s, want 暂停原因", rec.Body.String())
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='触发失败'`).Scan(&auditCount); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatalf("同步拒绝必须留审计")
	}
}

func TestEngineRunAsyncReservesAtomically(t *testing.T) { // 引擎角色种子读取需要已初始化的库（测试顺序无关）。
	newAutoBackupTestHandlers(t)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	services.SetAutoBackupExecutor(func(context.Context, string, string, int64) error {
		started <- struct{}{}
		<-release
		return nil
	})
	t.Cleanup(func() { services.SetAutoBackupExecutor(nil) })
	if services.TaskEngine() == nil {
		services.InitTaskEngine("", t.TempDir()+"/app.log")
	}
	t.Cleanup(services.StopTaskEngine)
	te := services.TaskEngine()

	if err := te.RunAsync("auto-backup", "manual", "tester"); err != nil {
		t.Fatalf("首次受理失败: %v", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("后台执行未启动")
	}
	if err := te.RunAsync("auto-backup", "manual", "tester"); err == nil {
		close(release)
		t.Fatalf("在途时第二次受理必须同步失败")
	} else if !strings.Contains(err.Error(), taskengine.ErrAlreadyRunning.Error()) {
		close(release)
		t.Fatalf("第二次受理 err=%v, want ErrAlreadyRunning", err)
	}
	close(release)
}

// 安全专项复核：DB 预检仍为主节点、引擎已降级的竞态窗必须 fail-closed
// 返回 403，与自动备份同哨兵口径一致，不得落 default 503。
func TestTriggerSystemTaskMapsAdmissionRoleConflictTo403(t *testing.T) {
	newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	te.SetRole(false)
	router, _ := taskMonitorRouter()

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/system/tasks/threat/trigger", nil))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("引擎角色拒绝 status=%d body=%s, want 403", recorder.Code, recorder.Body.String())
	}
	if latest := te.LatestRun("threat"); latest != nil {
		t.Fatalf("角色拒绝不得落执行行: %+v", latest)
	}
}

func TestLibraryUpdateEndpointsRejectPausedBefore200(t *testing.T) {
	tests := []struct {
		name    string
		taskID  string
		handler func(*Handlers) gin.HandlerFunc
	}{
		{name: "crs", taskID: "crs", handler: func(h *Handlers) gin.HandlerFunc { return h.StartCRSUpdate }},
		{name: "ip2region", taskID: "ip2region", handler: func(h *Handlers) gin.HandlerFunc { return h.StartIP2RegionUpdate }},
		{name: "threat", taskID: "threat", handler: func(h *Handlers) gin.HandlerFunc { return h.StartThreatLibUpdate }},
		{name: "crawler", taskID: "crawlerbot-update", handler: func(h *Handlers) gin.HandlerFunc { return h.StartCrawlerLibUpdate }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			initTaskEngineForTest(t)
			te := services.TaskEngine()
			te.PauseScheduling()
			router := gin.New()
			router.POST("/update", tc.handler(h))

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/update", nil))

			if recorder.Code != http.StatusConflict {
				t.Fatalf("暂停时 status=%d body=%s, want 409（不得伪 200 running）", recorder.Code, recorder.Body.String())
			}
			var runs int
			if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id=?`, tc.taskID).Scan(&runs); err != nil {
				t.Fatal(err)
			}
			if runs != 0 {
				t.Fatalf("暂停拒绝后 task_runs=%d, want 0", runs)
			}
		})
	}
}

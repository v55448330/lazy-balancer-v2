package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// round44BackupJSONWithTableSet 构造「表键集合精确可控」的 V2 备份 JSON——
// 与 completeBackupJSON/r55BackupJSONWithConfig 不同,不补齐 configBackupTables
// 全键,用于还原历史版本导出形态(迟到表键整体缺席,而非空切片);校验和按
// v2.1.2+ 新格式覆盖实际 tables+config,与真实导出同构。
func round44BackupJSONWithTableSet(t *testing.T, tables map[string][]map[string]any) string {
	t.Helper()
	cfg := map[string]any{}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-21T00:00:00Z"},
		Config: cfg,
		Tables: tables,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, tables, cfg)
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	return string(data)
}

// round44FullBackupTablesMinus 构造全量形态表集(configBackupTables 去掉
// omit 列出的迟到表),users 恒含一个启用管理员(过管理员门)。
func round44FullBackupTablesMinus(omit ...string) map[string][]map[string]any {
	skip := map[string]bool{}
	for _, o := range omit {
		skip[o] = true
	}
	tables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		if skip[table] {
			continue
		}
		tables[table] = []map[string]any{}
	}
	tables["users"] = []map[string]any{{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	return tables
}

// SEM44-1(P1):v2.1.2-v2.2.13 时代的合法全量备份(Version=2+新格式校验和)
// 缺迟到表(security_crs_version/security_ip2region_version 于 v2.1.10
// (76f616a) 起入导出清单、security_ip_lists 于 v2.2.1(6bf0bf5) 起入导出
// 清单)不得被必需表门 400 硬拒;缺席表由导入链「缺席=保留本地」语义承接
// (备份未携带的表不得清空本地数据)。
func TestSEM44_1_ImportConfigBackup_accepts_pre_late_table_era_full_backups(t *testing.T) {
	eras := []struct {
		name string
		omit []string
	}{
		{name: "v2.2.0 十四表形态(缺 security_ip_lists)", omit: []string{"security_ip_lists"}},
		{name: "v2.1.5 十二表形态(缺 ip_lists 与两个版本表)", omit: []string{"security_ip_lists", "security_crs_version", "security_ip2region_version"}},
	}
	for _, era := range eras {
		t.Run(era.name, func(t *testing.T) {
			// Given 本地已有一条 IP 列表——备份未携带该表,导入后必须保留
			h := newBackupTestHandlers(t)
			r55SeedCurrentAdmin(t)
			if _, err := db.DB.Exec("INSERT INTO security_ip_lists (name, entries) VALUES ('local-list', '[\"10.0.0.1\"]')"); err != nil {
				t.Fatalf("seed security_ip_lists: %v", err)
			}
			backup := round44BackupJSONWithTableSet(t, round44FullBackupTablesMinus(era.omit...))

			// When
			response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)

			// Then
			if response.Code != http.StatusOK {
				t.Fatalf("%s 导入 status=%d body=%s, want 200(迟到表缺席不得硬拒)", era.name, response.Code, response.Body.String())
			}
			var count int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists WHERE name='local-list'").Scan(&count); err != nil {
				t.Fatalf("query security_ip_lists: %v", err)
			}
			if count != 1 {
				t.Fatalf("备份未携带的迟到表必须保留本地数据,local-list 行数=%d, want 1", count)
			}
			// users 表被备份内容替换——导入确实生效(而非静默跳过)
			var users int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='backup-admin'").Scan(&users); err != nil {
				t.Fatalf("query users: %v", err)
			}
			if users != 1 {
				t.Fatalf("导入未生效:backup-admin 行数=%d, want 1", users)
			}
		})
	}
}

// SEM44-1(P1) 预览路径确认:ValidateConfigImport(config_import_v1.go:577)
// 与导入同走 validateV2Backup 必需表门——一处修复双路径生效,预览不得再误报
// 「备份缺少必需的数据表」。
func TestSEM44_1_ValidateConfigImport_accepts_v220_era_full_backup(t *testing.T) {
	// Given v2.2.0 十四表形态备份(缺 security_ip_lists)
	h := newBackupTestHandlers(t)
	r55SeedCurrentAdmin(t)
	backup := round44BackupJSONWithTableSet(t, round44FullBackupTablesMinus("security_ip_lists"))

	// When
	response := r55Post(t, h.ValidateConfigImport, "/config/validate", backup)

	// Then 预览端点校验失败也返回 200+valid=false,须解析 data
	if response.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var parsed struct {
		Data struct {
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal validate response: %v", err)
	}
	if !parsed.Data.Valid {
		t.Fatalf("v2.2.0 形态备份预览 valid=false error=%q, want valid=true(迟到表缺席不得误报)", parsed.Data.Error)
	}
}

// SEM44-1 回归形状:全量形态(三族标记齐备)缺非迟到核心表仍必须 400——
// 迟到表容缺不得放宽为「任意表缺席放行」。
func TestSEM44_1_ImportConfigBackup_still_rejects_full_backup_missing_core_table(t *testing.T) {
	// Given 全量形态备份缺 upstreams(非迟到核心表)
	h := newBackupTestHandlers(t)
	r55SeedCurrentAdmin(t)
	backup := round44BackupJSONWithTableSet(t, round44FullBackupTablesMinus("upstreams"))

	// When
	response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("缺核心表的全量备份 status=%d, want 400; body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "备份缺少必需的数据表: upstreams") {
		t.Fatalf("拒绝必须点名 upstreams,实际: %s", response.Body.String())
	}
	r55AssertZeroWrite(t)
}

// SEM44-1 回归形状:v2.0.10-v2.1.0 八表时代导出(Version=2,无 security_policies)
// 走 hasSecurity=false 分类分支(已知表>0 即放行),修复不得破坏该既有可导入路径。
func TestSEM44_1_ImportConfigBackup_eight_table_era_uses_classification_branch(t *testing.T) {
	// Given Version=2 八表形态备份(无安全族表),新格式校验和覆盖实际内容
	h := newBackupTestHandlers(t)
	r55SeedCurrentAdmin(t)
	tables := map[string][]map[string]any{
		"lb_rules":            {},
		"upstreams":           {},
		"path_rules":          {},
		"users":               {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
		"api_keys":            {},
		"ca_providers":        {},
		"certificate_configs": {},
		"cert_jobs":           {},
	}
	backup := round44BackupJSONWithTableSet(t, tables)

	// When
	response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("八表时代备份导入 status=%d body=%s, want 200(分类分支既有行为)", response.Code, response.Body.String())
	}
}

// CERT44-1(P2):导入校验对 ca_providers 行补 provider 白名单门——保存/更新侧
// (services/caproviders.go:194)恒拒 letsencrypt/zerossl 之外的 provider,导入
// 侧不得更宽;违例整包 400 且零写入。
func TestCERT44_1_ImportConfigBackup_rejects_unknown_ca_provider(t *testing.T) {
	// Given 备份携带 provider=evil-ca 的 ca_providers 行
	h := newBackupTestHandlers(t)
	r55SeedCurrentAdmin(t)
	backup := r55BackupJSONWithConfig(t, map[string][]map[string]any{
		"ca_providers": {{"id": 1, "name": "evil", "provider": "evil-ca", "directory_url": "https://evil.example/acme", "credentials": "{}", "enabled": 1}},
	}, nil)

	// When
	response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("未知 CA 提供商备份 status=%d, want 400; body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "evil-ca") {
		t.Fatalf("拒绝必须点名违例 provider,实际: %s", response.Body.String())
	}
	r55AssertZeroWrite(t)
}

// CERT44-1(P2):directory_url 无条件覆写为官方常量(与服务层 :197-201 同
// 语义)——合法 provider + 恶意目录 URL 的备份导入后,落库 directory_url 必须
// 是官方常量而非备份原值。
func TestCERT44_1_ImportConfigBackup_overwrites_directory_url_with_official_constant(t *testing.T) {
	cases := []struct {
		provider string
		wantURL  string
	}{
		{provider: "letsencrypt", wantURL: services.LetsEncryptDirectoryURL},
		{provider: "zerossl", wantURL: services.ZeroSSLDirectoryURL},
	}
	for _, tt := range cases {
		t.Run(tt.provider, func(t *testing.T) {
			// Given 合法 provider + 恶意 directory_url
			h := newBackupTestHandlers(t)
			r55SeedCurrentAdmin(t)
			backup := r55BackupJSONWithConfig(t, map[string][]map[string]any{
				"ca_providers": {{"id": 1, "name": "ca", "provider": tt.provider, "directory_url": "https://evil.example/acme", "credentials": "{}", "enabled": 1}},
			}, nil)

			// When
			response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)

			// Then
			if response.Code != http.StatusOK {
				t.Fatalf("合法 provider 导入 status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var gotURL string
			if err := db.DB.QueryRow("SELECT directory_url FROM ca_providers WHERE id=1").Scan(&gotURL); err != nil {
				t.Fatalf("query ca_providers: %v", err)
			}
			if gotURL != tt.wantURL {
				t.Fatalf("directory_url=%q, want 官方常量 %q(恶意目录 URL 不得落库)", gotURL, tt.wantURL)
			}
		})
	}
}

// SYSB44-1(P3):OIDC JIT 用户 password_hash 为空(auth_oidc.go:476 置空)——
// 空哈希走 bcrypt 快路径(µs 级)会以时序差暴露「该用户名存在但无本地密码」,
// 须改用 loginDummyBcryptHash 等时占位(与 ErrNoRows 路径 :111 同型)。
// 延迟下限契约:错误密码登录耗时不得低于 bcrypt 比较地板(30ms;本机实测
// DefaultCost 比较 ≈45-47ms,空哈希快路径 ≈0ms,双侧安全)。
func TestSYSB44_1_Login_oidc_empty_password_hash_runs_timing_equalized_compare(t *testing.T) {
	const floor = 30 * time.Millisecond
	cases := []struct {
		name string
		seed string // 空串=不种子(用户不存在路径)
	}{
		{name: "OIDC 空哈希用户", seed: "INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider) VALUES (2,'oidc-user','','user',1,'oidc')"},
		{name: "回归:不存在的用户", seed: ""},
		{name: "回归:本地用户错误密码", seed: "INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (3,'local-user','" + string(loginDummyBcryptHash) + "','user',1)"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			if tt.seed != "" {
				if _, err := db.DB.Exec(tt.seed); err != nil {
					t.Fatalf("seed user: %v", err)
				}
			}
			username := "oidc-user"
			if tt.seed == "" {
				username = "ghost-user"
			} else if tt.name == "回归:本地用户错误密码" {
				username = "local-user"
			}

			// When 错误密码登录,计时
			start := time.Now()
			response := r55Post(t, h.Login, "/auth/login", `{"username":"`+username+`","password":"definitely-wrong-password"}`)
			elapsed := time.Since(start)

			// Then 401 且耗时不低于 bcrypt 等时地板
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s, want 401", response.Code, response.Body.String())
			}
			if elapsed < floor {
				t.Fatalf("错误密码登录耗时 %v 低于等时地板 %v——空哈希快路径暴露「无本地密码」", elapsed, floor)
			}
			t.Logf("elapsed=%v", elapsed)
		})
	}
}

// SYSB44-3(P5):GetAppLogs 128KB 尾读窗口起点可能切在多字节 UTF-8 rune 中段
// ——首行残段带无效字节,JSON 编码后以 U+FFFD 污染输出。修复:起点非零时
// 前进到下一 '\n' 再开始读(丢弃被截断的首行残段)。
// 构造:总长度使 startOffset=size-128KB 恰落在「中」(3 字节)的第 2 字节;
// 窗口内行数 <500(排除 maxLines 裁剪把残段首行裁掉的干扰)。
func TestSYSB44_3_GetAppLogs_tail_window_never_splits_multibyte_rune(t *testing.T) {
	// Given
	const maxBytes = 128 * 1024
	pad := strings.Repeat("a", 100) + "\n"               // 101 字节
	boundaryRune := "中"                                  // 占字节 101/102/103
	restOfBoundaryLine := strings.Repeat("c", 50) + "\n" // 边界行残余部分
	targetTotal := len(pad) + 1 + maxBytes               // startOffset=102=「中」第 2 字节
	fillerLen := targetTotal - len(pad) - len(boundaryRune) - len(restOfBoundaryLine)
	var fb strings.Builder
	longLine := strings.Repeat("d", 299) + "\n" // 300 字节长行,行数 <<500
	for fb.Len()+len(longLine) <= fillerLen {
		fb.WriteString(longLine)
	}
	if remaining := fillerLen - fb.Len(); remaining > 0 {
		fb.WriteString(strings.Repeat("e", remaining-1) + "\n")
	}
	filler := fb.String()
	if fillerLen <= 0 || len(filler) != fillerLen {
		t.Fatalf("夹具构造错误: fillerLen=%d len(filler)=%d", fillerLen, len(filler))
	}
	logPath := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(logPath, []byte(pad+boundaryRune+restOfBoundaryLine+filler), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	handler := &Handlers{cfg: &config.Config{LogFile: logPath}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/system/logs", handler.GetAppLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/logs", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.Contains(envelope.Data.Content, "\uFFFD") {
		t.Fatalf("输出含 U+FFFD 替换符——窗口起点切断多字节 rune,残段污染首行(首 64 字符: %q)", envelope.Data.Content[:64])
	}
	if envelope.Data.Content != filler {
		t.Fatalf("输出须恰好为截断后的完整行内容: 长度=%d, want %d(首行残段整体丢弃)", len(envelope.Data.Content), len(filler))
	}
}

// W3-R44-1(第 44 轮 W3 评审,高危):SYSB44-1 的等化修法把空哈希账户的比较
// 对象换成 loginDummyBcryptHash——其明文是源码内公开常量(随二进制分发),
// OIDC JIT 用户(password_hash=”)可用该公开串通过主比较登录。安全不变量:
// 空哈希账户任何密码不得认证(等时比较只取耗时副作用,结果必须恒败)。
func TestSYSB44_1_Login_oidc_empty_password_hash_never_authenticates(t *testing.T) {
	// Given OIDC JIT 用户(空 password_hash)
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider) VALUES (2,'oidc-dummy','','user',1,'oidc')"); err != nil {
		t.Fatalf("seed oidc user: %v", err)
	}

	// When 以公开 dummy 明文「登录」
	response := r55Post(t, h.Login, "/auth/login", `{"username":"oidc-dummy","password":"lazy-balancer timing-equalizer dummy"}`)

	// Then 必须 401——公开常量不得成为认证依据
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("空哈希用户以公开 dummy 串登录 status=%d body=%s, want 401(认证绕过)", response.Code, response.Body.String())
	}
}

// W3-R44-3(第 44 轮 W3 评审):SEC44-1 的 429 剔除只覆盖保存侧+启动归一,
// 备份导入路径可再引入 block_status_code=429 行(混入限流指标口径)。修复:
// validateV2BackupSecurityPolicies 对 429 归一为 403(与 CERT44-1 导入侧
// 覆写同格;旧备份不因新白名单硬拒)。
func TestW3R44_3_validateV2Backup_normalizes_block_status_429(t *testing.T) {
	// Given 修复前时代备份携带 block_status_code=429 的策略行
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_policies": {{"id": 1, "name": "p1", "block_status_code": 429}},
	})
	var b configBackup
	if err := json.Unmarshal([]byte(backup), &b); err != nil {
		t.Fatalf("unmarshal backup: %v", err)
	}

	// When 策略校验(归一所在阶段;导入 :2144 与预览 config_import_v1.go:622 双路径同走)
	if err := validateV2BackupSecurityPolicies(b.Tables); err != nil {
		t.Fatalf("validateV2BackupSecurityPolicies unexpected error: %v", err)
	}

	// Then 429 已归一为 403(导入落库即 403)
	got := b.Tables["security_policies"][0]["block_status_code"]
	if got != 403 && got != int64(403) && got != float64(403) {
		t.Fatalf("block_status_code=%v(%T), want 403(429 归一)", got, got)
	}
}

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// （2026-09-05 证书域审计裁定，2026-10-26 列退役）：global_config.dns_credentials
// 为退役列（签发链唯一凭证来源是 certificate_configs.dns_credentials，前端
// 零消费），列由启动迁移删除——GET /config 响应既不带值，也不再带键；
// 管理员与非管理员视角同形。
func TestGetConfig_omits_retiredGlobalDNSCredentials(t *testing.T) {
	// Given：对照字段有真实值，证明响应装配链路正常
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET acme_email='ops@example.com' WHERE id=1`); err != nil {
		t.Fatalf("seed acme email: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config", h.GetConfig)
	adminRouter := gin.New()
	adminRouter.Use(func(c *gin.Context) { c.Set("role", "admin") })
	adminRouter.GET("/config", h.GetConfig)

	for name, target := range map[string]*gin.Engine{"anonymous": router, "admin": adminRouter} {
		t.Run(name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			target.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))

			// Then：退役键彻底消失（字段退役后「值为空串」的旧契约升级为
			// 「键不存在」——消费者不得再依据该键存在与否做判定）。
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "dns_credentials") {
				t.Fatalf("response 仍携带退役键 dns_credentials: %s", response.Body.String())
			}
			var body struct {
				Data struct {
					DNSProvider string `json:"dns_provider"`
					ACMEEmail   string `json:"acme_email"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode config response: %v", err)
			}
			if body.Data.ACMEEmail != "ops@example.com" {
				t.Fatalf("acme_email=%q, want unaffected field intact", body.Data.ACMEEmail)
			}
		})
	}
}

// 设置页读路径 SQL 默认值字面量是治理默认值的第三次复制
// （DDL DEFAULT+启动回填+此处）——改参数绑定 db.Default* 常量后，本扫描钉
// 防字面量回流：GetConfig 函数体内治理列名旁不得再出现写死默认值字面量。
func TestGetConfig_noGovernedDefaultLiterals(t *testing.T) {
	src, err := os.ReadFile("caddy.go")
	if err != nil {
		t.Fatalf("read caddy.go: %v", err)
	}
	body := scopedFunctionBody(t, string(src), "func (h *Handlers) GetConfig(")
	cases := []struct {
		pattern string
		sample  string
	}{
		{`cert_expiry_days,` + "\r?`?\\s*" + `30`, "cert_expiry_days, 30"},
		{`cert_renewal_days,` + "\r?`?\\s*" + `30`, "cert_renewal_days, 30"},
		{`cert_renewal_attempts,` + "\r?`?\\s*" + `5`, "cert_renewal_attempts, 5"},
		{`caddy_log_size_mb,` + "\r?`?\\s*" + `100`, "caddy_log_size_mb, 100"},
		{`ELSE\s+128`, "ELSE 128"},
		{`http_read_timeout,` + "\r?`?\\s*" + `60`, "http_read_timeout, 60"},
		{`http_write_timeout,` + "\r?`?\\s*" + `60`, "http_write_timeout, 60"},
		{`http_idle_timeout,` + "\r?`?\\s*" + `120`, "http_idle_timeout, 120"},
		{`task_log_size_mb,` + "\r?`?\\s*" + `10`, "task_log_size_mb, 10"},
		{`audit_log_size_mb,` + "\r?`?\\s*" + `10`, "audit_log_size_mb, 10"},
		{`runtime_log_size_mb,` + "\r?`?\\s*" + `100`, "runtime_log_size_mb, 100"},
		{`audit_retention_months,` + "\r?`?\\s*" + `3`, "audit_retention_months, 3"},
		{`jwt_expire_minutes,` + "\r?`?\\s*" + `20`, "jwt_expire_minutes, 20"},
	}
	for _, tc := range cases {
		re := regexp.MustCompile(tc.pattern)
		// 合成自检：模式必须能抓到典型字面量样本，否则扫描面对真实代码同样
		// 永不命中（SQL 抽到 helper / 拼接形态变化后静默失效仍绿）。
		if !re.MatchString(tc.sample) {
			t.Fatalf("合成自检失败：模式 %q 抓不到样本 %q——扫描判据已失效", tc.pattern, tc.sample)
		}
		if re.MatchString(body) {
			t.Errorf("GetConfig 治理默认值字面量回流 %q——改用 db.Default* 参数绑定（G4 单源）", tc.pattern)
		}
	}
}

// scopedFunctionBody 截取以 scope 起、到下一个 "\nfunc " 止的函数体，并做
// 正向控制：失败或截取结果明显不可用时直接 fail——静默返回空串会让所有
// 禁止模式永不命中（扫描空转变为全绿）。
func scopedFunctionBody(t *testing.T, src, scope string) string {
	t.Helper()
	start := strings.Index(src, scope)
	if start < 0 {
		t.Fatalf("scope %q not found", scope)
	}
	end := strings.Index(src[start:], "\nfunc ")
	if end < 0 {
		t.Fatalf("scope %q end not found", scope)
	}
	body := src[start : start+end]
	if len(body) < len(scope)+40 {
		t.Fatalf("scope %q 截取结果过短（%d 字节）——函数边界判据失效", scope, len(body))
	}
	return body
}

// 带外写入 0（重启回填前窗口）时读侧必须原样下发：面板值与渲染层
// fail-visible 同源（resolveRuleOverrides 对 <=0 显性报错），不得展示一个
// 「已生效」的默认 128——按面板值排查会得出与运行态相反的结论。
func TestGetConfig_zeroRequestBodyMaxSizeIsVisible(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET request_body_max_size_mb=0 WHERE id=1`); err != nil {
		t.Fatalf("seed out-of-band zero: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config", h.GetConfig)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			RequestBodyMaxSizeMB int `json:"request_body_max_size_mb"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode config response: %v", err)
	}
	if body.Data.RequestBodyMaxSizeMB != 0 {
		t.Fatalf("request_body_max_size_mb=%d, want 0（读侧不得隐藏带外无效值）", body.Data.RequestBodyMaxSizeMB)
	}
}

// 行为钉：cert_expiry_days（fresh DDL 可空列）NULL 形态读路径回退
// db.DefaultCertExpiryDays 常量，不 500 不零值。批 1+2 值型列（request_body/
// http_*/caddy_log_size_mb）fresh DDL NOT NULL+启动回填报证 NULL 不可达，
// 其 COALESCE(? 常量) 仅为防御形态——由 TestGetConfig_noGovernedDefaultLiterals
// 与 db_truth_defaults_test.go 双向钉覆盖。
func TestGetConfig_nullCertExpiryDaysFallsBackToConstant(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET cert_expiry_days=NULL WHERE id=1`); err != nil {
		t.Fatalf("null cert_expiry_days: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config", h.GetConfig)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			CertExpiryDays int `json:"cert_expiry_days"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.CertExpiryDays != db.DefaultCertExpiryDays {
		t.Fatalf("NULL cert_expiry_days 须回退 db.DefaultCertExpiryDays(%d), got %d", db.DefaultCertExpiryDays, body.Data.CertExpiryDays)
	}
}

// cert_expiry_days 消费点族「默认值 30 字面量」回流钉——
// 同型扫描从 GetConfig 单函数扩展到六消费点族：SQL COALESCE 字面量一律参数
// 绑定 db.DefaultCertExpiryDays（caddy.go 形态），Go 降级分支一律取治理常量
// （services/certinfo.go GetCertExpiryThreshold 基准）。库值唯一真相（批 3）
// 的读侧防回流钉；caddy.go GetConfig 本体已由 TestGetConfig_noGovernedDefaultLiterals 覆盖。
func TestGovernedConfigDefaults_noDefaultLiteralsAcrossConsumers(t *testing.T) {
	governedSQLPatterns := []string{
		`COALESCE\(cert_expiry_days\s*,\s*30\)`,
		`COALESCE\(cert_renewal_days\s*,\s*30\)`,
		`COALESCE\(cert_renewal_attempts\s*,\s*5\)`,
	}
	cases := []struct {
		file     string
		scope    string   // 非空=只扫该函数体（func 起点到下一个 "\nfunc"）
		patterns []string // 命中即失败（禁止的默认值字面量形态）
	}{
		{"certinfo.go", "", []string{`COALESCE\(cert_expiry_days\s*,\s*30\)`}},
		{"certjobs.go", "", []string{`COALESCE\(cert_expiry_days\s*,\s*30\)`, `expiryDays\s*:?=\s*30\b`}},
		{"config_changes.go", "", []string{`COALESCE\(cert_expiry_days\s*,\s*30\)`}},
		{"../services/cluster_report.go", "", []string{`COALESCE\(cert_expiry_days\s*,\s*30\)`, `expiryDays\s*:?=\s*30\b`}},
		{"../services/cluster_snapshot.go", "func (s *ClusterService) loadSnapshotGlobalSettings(", []string{`COALESCE\(cert_expiry_days\s*,\s*30\)`}},
		{"../services/certinfo.go", "func GetCertExpiryThreshold(", []string{`return\s+30\b`, `default 30`, `降级默认 30`}},
	}
	// 合成自检：每条禁止模式必须能抓到一条典型样本，否则该行的扫描是空转。
	for _, sample := range []struct{ pattern, text string }{
		{`COALESCE\(cert_expiry_days\s*,\s*30\)`, "COALESCE(cert_expiry_days, 30)"},
		{`COALESCE\(cert_renewal_days\s*,\s*30\)`, "COALESCE(cert_renewal_days,30)"},
		{`COALESCE\(cert_renewal_attempts\s*,\s*5\)`, "COALESCE(cert_renewal_attempts, 5)"},
		{`expiryDays\s*:?=\s*30\b`, "expiryDays := 30"},
		{`return\s+30\b`, "return 30"},
		{`default 30`, "默认 default 30 天"},
		{`降级默认 30`, "降级默认 30"},
	} {
		if !regexp.MustCompile(sample.pattern).MatchString(sample.text) {
			t.Fatalf("合成自检失败：模式 %q 抓不到样本 %q", sample.pattern, sample.text)
		}
	}
	for _, tc := range cases {
		src, err := os.ReadFile(filepath.FromSlash(tc.file))
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		body := string(src)
		if tc.scope != "" {
			body = scopedFunctionBody(t, body, tc.scope)
		}
		for _, pattern := range governedSQLPatterns {
			if regexp.MustCompile(pattern).MatchString(body) {
				t.Errorf("%s 治理默认值 SQL 字面量回流 %q——改用对应 db.Default* 单源", tc.file, pattern)
			}
		}
		for _, pattern := range tc.patterns {
			if regexp.MustCompile(pattern).MatchString(body) {
				t.Errorf("%s cert_expiry_days 默认值字面量回流 %q——改用 db.DefaultCertExpiryDays 单源（R2/G4）", tc.file, pattern)
			}
		}
	}
}

// handler 侧：GET /config 的展示钳位必须与运行时/状态阈值同界，
// 低值 <10→60、高值 >86400→86400。
func TestGetConfig_syncIntervalClampMatchesRuntime(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config", h.GetConfig)
	for _, tc := range []struct {
		stored int
		want   int
	}{
		{stored: 5, want: 60},
		{stored: 86401, want: 86400},
		{stored: 1000000, want: 86400},
		{stored: 60, want: 60},
		{stored: 86400, want: 86400},
	} {
		if _, err := db.DB.Exec(`UPDATE global_config SET sync_interval=? WHERE id=1`, tc.stored); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("stored=%d status=%d body=%s", tc.stored, response.Code, response.Body.String())
		}
		var body struct {
			Data struct {
				SyncInterval int `json:"sync_interval"`
			} `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Data.SyncInterval != tc.want {
			t.Fatalf("stored=%d displayed=%d, want %d", tc.stored, body.Data.SyncInterval, tc.want)
		}
	}
}

// 自定义 Caddy 配置可包含私钥或敏感 header，非管理员及只读
// API Key 不得通过 GET /config 读取原文；管理员 JWT/读写 Key 保持回归。
func TestGetConfig_caddyConfigVisibilityByIdentity(t *testing.T) {
	const secret = `private-key-and-sensitive-header`
	for _, tc := range []struct {
		name      string
		role      string
		authType  string
		readOnly  bool
		wantPlain bool
	}{
		{name: "admin JWT", role: "admin", authType: "jwt", wantPlain: true},
		{name: "admin read-write key", role: "admin", authType: "api_key", wantPlain: true},
		{name: "non-admin JWT", role: "user", authType: "jwt"},
		{name: "admin read-only key", role: "admin", authType: "api_key", readOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			if _, err := db.DB.Exec(`UPDATE global_config SET caddy_config=? WHERE id=1`, secret); err != nil {
				t.Fatal(err)
			}
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("role", tc.role)
				c.Set("auth_type", tc.authType)
				c.Set("api_key_read_only", tc.readOnly)
			})
			router.GET("/config", h.GetConfig)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var body struct {
				Data struct {
					CaddyConfig string `json:"caddy_config"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if tc.wantPlain && body.Data.CaddyConfig != secret {
				t.Fatalf("caddy_config=%q, want plaintext", body.Data.CaddyConfig)
			}
			if !tc.wantPlain && (body.Data.CaddyConfig != "" || strings.Contains(response.Body.String(), secret)) {
				t.Fatalf("restricted identity received caddy_config=%q", body.Data.CaddyConfig)
			}
		})
	}
}

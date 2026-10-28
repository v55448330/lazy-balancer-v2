package config

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadForTest 是测试侧的单返回值加载包装：生产唯一入口是
// LoadCollectWarnings（告警延迟重放交给运行日志装配后的级别门）。测试仍按旧
// 口径把告警直接打到 log，供用例捕获校验文案——产品文件不得再提供无告警出口
// 的并行实现（双入口会让「测试覆盖的路径 ≠ 生产路径」无从发现；守卫见
// testonly_symbols_test.go）。
func loadForTest(path string) *Config {
	cfg, warnings := LoadCollectWarnings(path)
	for _, warning := range warnings {
		log.Printf("%s", warning)
	}
	return cfg
}

// loadOrCreateJWTSecretForTest 是 loadOrCreateJWTSecretWith 的测试直调入口：
// 告警直接打印（用例捕获输出校验文案）。
func loadOrCreateJWTSecretForTest(dataDir string) string {
	return loadOrCreateJWTSecretWith(dataDir, func(format string, args ...any) { log.Printf(format, args...) })
}

// APP_VERSION 未注入时版本兜底为 "unknown"（fail-visible）——不得静默显示
// 一个并非当前构建的版本号；发版链（Dockerfile ARG VERSION/buildx
// --build-arg）显式传参，不受兜底值影响。
func TestLoad_versionFallsBackToUnknownWhenAppVersionUnset(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("APP_VERSION", "") // getEnv 视空值为未注入

	loaded := loadForTest("")

	if loaded.Version != "unknown" {
		t.Fatalf("version=%q, want unknown（APP_VERSION 未注入兜底）", loaded.Version)
	}
}

func TestLoad_versionUsesAppVersionEnv(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("APP_VERSION", "v9.9.9-test")

	loaded := loadForTest("")

	if loaded.Version != "v9.9.9-test" {
		t.Fatalf("version=%q, want v9.9.9-test", loaded.Version)
	}
}

func TestLoad_parses_metrics_interval_with_safe_minimum(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	tests := []struct {
		name     string
		interval int
		want     int
	}{
		{name: "configured interval", interval: 12, want: 12},
		{name: "positive interval below minimum", interval: 1, want: 5},
		{name: "zero keeps default", interval: 0, want: 30},
		{name: "negative keeps default", interval: -10, want: 30},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			configPath := filepath.Join(t.TempDir(), "config.json")
			content := fmt.Sprintf(`{"metrics_interval":%d}`, test.interval)
			if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			// When
			loaded := loadForTest(configPath)

			// Then
			if loaded.MetricsInterval != test.want {
				t.Fatalf("metrics interval=%d, want %d", loaded.MetricsInterval, test.want)
			}
		})
	}
}

func TestLoad_resolves_log_file_with_default(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	tests := []struct {
		name     string
		envValue string
		wantPath string
	}{
		{name: "env override", envValue: "/tmp/custom.log", wantPath: "/tmp/custom.log"},
		{name: "empty env falls back to default", envValue: "", wantPath: "/app/logs/lazy-balancer.log"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			t.Setenv("LOG_FILE", test.envValue)

			// When
			loaded := loadForTest("")

			// Then
			if loaded.LogFile != test.wantPath {
				t.Fatalf("log file=%q, want %q", loaded.LogFile, test.wantPath)
			}
		})
	}
}

// 配置文件只解析六个支持键，其余键此前静默忽略——
// log_file/node_name/jwt_secret/backup_dir/version 写在文件里既无效也无提示。
// 未知键必须逐条告警；支持键零告警且照常生效。
func TestLoad_warnsOnUnsupportedConfigFileKeys(t *testing.T) {
	// Given：支持键 + 未知键混排的配置文件
	t.Setenv("JWT_SECRET", "test-secret")
	configPath := filepath.Join(t.TempDir(), "config.json")
	content := `{"data_dir":"/tmp/config-test-data","port":8081,"metrics_interval":10,"log_file":"/tmp/x.log","node_name":"n2"}`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	// When
	loaded := loadForTest(configPath)

	// Then：支持键生效
	if loaded.Port != 8081 || loaded.DataDir != "/tmp/config-test-data" || loaded.MetricsInterval != 10 {
		t.Fatalf("supported keys not applied: port=%d data_dir=%q interval=%d", loaded.Port, loaded.DataDir, loaded.MetricsInterval)
	}
	// And：未知键逐条告警，支持键零告警
	logs := logBuf.String()
	for _, unsupported := range []string{"log_file", "node_name"} {
		if !strings.Contains(logs, `ignoring unsupported config key "`+unsupported+`"`) {
			t.Fatalf("unsupported key %q must warn, log=%q", unsupported, logs)
		}
	}
	for _, supported := range []string{"data_dir", "port", "metrics_interval"} {
		if strings.Contains(logs, `ignoring unsupported config key "`+supported+`"`) {
			t.Fatalf("supported key %q must not warn, log=%q", supported, logs)
		}
	}
}

// caddy_admin_url 与渲染产物 admin 监听（127.0.0.1:2019）不一致时启动期
// 必须 WARN（首次 /load 后该端点失联）；回环等价类（localhost/127.0.0.1/::1 +
// 2019，含出厂默认值）与畸形 URL（由连接方报错）不告警。
func TestLoad_warnsOnMismatchedCaddyAdminURL(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")

	writeConfig := func(t *testing.T, adminURL string) string {
		configPath := filepath.Join(t.TempDir(), "config.json")
		content := `{"data_dir":"/tmp/config-test-data","caddy_admin_url":` + adminURL + `}`
		if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		return configPath
	}

	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	loadAndLog := func(t *testing.T, path string) string {
		t.Helper()
		logBuf.Reset()
		loadForTest(path)
		return logBuf.String()
	}

	// 地址或 scheme 与自管 admin 不等价 → WARN。
	for _, adminURL := range []string{`"http://127.0.0.1:2020"`, `"http://localhost:2020"`, `"http://0.0.0.0:2019"`, `"https://127.0.0.1:2019"`, `"ftp://127.0.0.1:2019"`} {
		logs := loadAndLog(t, writeConfig(t, adminURL))
		if !strings.Contains(logs, "caddy_admin_url") || !strings.Contains(logs, "127.0.0.1:2019") {
			t.Fatalf("caddy_admin_url=%s 必须 WARN, log=%q", adminURL, logs)
		}
	}

	// 回环等价类 + 2019 → 零告警（出厂默认值 localhost:2019 不得误报）。
	for _, adminURL := range []string{`"http://127.0.0.1:2019"`, `"http://localhost:2019"`, `"http://[::1]:2019"`} {
		logs := loadAndLog(t, writeConfig(t, adminURL))
		if strings.Contains(logs, "caddy_admin_url") {
			t.Fatalf("回环等价的 caddy_admin_url=%s 不应告警, log=%q", adminURL, logs)
		}
	}

	// 缺省路径（无配置文件，沿用内置默认 http://localhost:2019）→ 零告警。
	if logs := loadAndLog(t, ""); strings.Contains(logs, "caddy_admin_url") {
		t.Fatalf("缺省 caddy_admin_url 不应告警, log=%q", logs)
	}
}

func TestLoad_caddyMetricsURLSchemeIndependent(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	configPath := filepath.Join(t.TempDir(), "config.json")
	content := `{"data_dir":"/tmp/config-test-data","caddy_admin_url":"http://127.0.0.1:2019","caddy_metrics_url":"https://127.0.0.1:9443/metrics"}`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)
	cfg := loadForTest(configPath)
	if cfg.CaddyMetricsURL != "https://127.0.0.1:9443/metrics" {
		t.Fatalf("CaddyMetricsURL=%q, want 原样保留独立 HTTPS 指标地址", cfg.CaddyMetricsURL)
	}
	if strings.Contains(logBuf.String(), "caddy_admin_url") || strings.Contains(logBuf.String(), "caddy_metrics_url") {
		t.Fatalf("独立指标 scheme 不得触发 admin 一致性告警: %q", logBuf.String())
	}
}

func TestLoad_warnsOnSupportedConfigFileKeyTypeMismatch(t *testing.T) {
	// Given：六个支持键全部使用错误 JSON 类型。
	t.Setenv("JWT_SECRET", "test-secret")
	configPath := filepath.Join(t.TempDir(), "config.json")
	content := `{"data_dir":123,"static_dir":false,"port":"8000","caddy_admin_url":42,"caddy_metrics_url":[],"metrics_interval":"10"}`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	// When
	loaded := loadForTest(configPath)

	// Then：沿用默认值但每个误配键都必须有类型告警，不再静默。
	if loaded.Port != 8000 || loaded.DataDir != "/app/data" || loaded.StaticDir != "/app/ui" || loaded.CaddyAdminURL != "http://localhost:2019" || loaded.CaddyMetricsURL != "http://localhost:2019/metrics" || loaded.MetricsInterval != 30 {
		t.Fatalf("invalid-type config did not retain defaults: %+v", loaded)
	}
	logs := logBuf.String()
	for _, key := range []string{"data_dir", "static_dir", "port", "caddy_admin_url", "caddy_metrics_url", "metrics_interval"} {
		if !strings.Contains(logs, `invalid type for key "`+key+`"`) {
			t.Errorf("missing invalid-type warning for %q, log=%q", key, logs)
		}
	}

	// 回归形状：正确类型全部生效且零类型告警。
	logBuf.Reset()
	if err := os.WriteFile(configPath, []byte(`{"data_dir":"/tmp/config-type-data","static_dir":"/tmp/config-type-ui","port":8081,"caddy_admin_url":"http://127.0.0.1:2019","caddy_metrics_url":"http://127.0.0.1:2019/metrics","metrics_interval":10}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded = loadForTest(configPath)
	if loaded.Port != 8081 || loaded.DataDir != "/tmp/config-type-data" || loaded.StaticDir != "/tmp/config-type-ui" || loaded.MetricsInterval != 10 {
		t.Fatalf("valid config not applied: %+v", loaded)
	}
	if strings.Contains(logBuf.String(), "invalid type for key") {
		t.Fatalf("valid config produced type warning: %q", logBuf.String())
	}
}

// jwt_secret 路径存在但读取失败（非 ENOENT——瞬时
// IO/ACL 形态，测试用「同名目录」确定性复现）此前静默落入重生成——写入
// 成功则全部 JWT 失效且零日志。必须 warn 可见（与过短/目录/写失败分支
// 同一可见性准则）。
func TestLoadOrCreateJWTSecret_readErrorWarnsBeforeRegenerate(t *testing.T) {
	// Given：jwt_secret 路径被同名目录占据——os.ReadFile 返回非 ENOENT 错误
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "jwt_secret")
	if err := os.Mkdir(secretPath, 0755); err != nil {
		t.Fatalf("seed blocking directory: %v", err)
	}
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	// When
	secret := loadOrCreateJWTSecretForTest(dir)

	// Then：照常产出 64 字符 hex（可用性不变），但读取失败必须 warn 可见
	if len(secret) != 64 {
		t.Fatalf("secret len=%d; want 64-char hex", len(secret))
	}
	if !strings.Contains(logBuf.String(), "读取失败") {
		t.Fatalf("unreadable existing secret must log a warning before regenerating, got %q", logBuf.String())
	}
}

// jwt_secret 文件存在但内容过短（非空且 <32 字节）时，
// 覆写重生成必须 log warn——对齐同文件端口回退/密钥目录创建失败分支的可见性
// 准则；此前静默覆写，旧令牌全部失效且零信号。
func TestLoadOrCreateJWTSecret_shortSecretWarnsAndRegenerates(t *testing.T) {
	// Given 过短的既有密钥文件 + 捕获日志
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "jwt_secret")
	if err := os.WriteFile(secretPath, []byte("too-short"), 0600); err != nil {
		t.Fatalf("seed short secret: %v", err)
	}
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	// When
	secret := loadOrCreateJWTSecretForTest(dir)

	// Then：重生成 64 字符 hex 并覆写持久化
	if secret == "too-short" || len(secret) != 64 {
		t.Fatalf("secret=%q (len %d); want regenerated 64-char hex", secret, len(secret))
	}
	data, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if string(data) != secret {
		t.Fatalf("file=%q; want persisted regenerated secret", data)
	}
	// And：过短覆写必须 warn 可见
	if !strings.Contains(logBuf.String(), "过短") {
		t.Fatalf("short-secret overwrite must log a warning, got %q", logBuf.String())
	}
}

// 回归/边界形状：≥32 字节的既有密钥原样复用且零日志；空文件按缺失处理
// 重生成但不 warn（warn 仅针对非空过短——空文件等同未初始化）。
func TestLoadOrCreateJWTSecret_validReusedAndEmptyQuiet(t *testing.T) {
	t.Run("valid secret reused quietly", func(t *testing.T) {
		// Given 合法长度且高熵的密钥文件
		dir := t.TempDir()
		want := "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928"
		if err := os.WriteFile(filepath.Join(dir, "jwt_secret"), []byte(want), 0600); err != nil {
			t.Fatal(err)
		}
		var logBuf bytes.Buffer
		origOut := log.Writer()
		log.SetOutput(&logBuf)
		t.Cleanup(func() { log.SetOutput(origOut) })

		// When
		secret := loadOrCreateJWTSecretForTest(dir)

		// Then
		if secret != want {
			t.Fatalf("secret=%q; want existing valid secret reused", secret)
		}
		if logBuf.Len() != 0 {
			t.Fatalf("valid secret reuse must not log, got %q", logBuf.String())
		}
	})
	t.Run("empty file regenerates without short-warning", func(t *testing.T) {
		// Given 空密钥文件（等同未初始化，非「过短」形态）
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "jwt_secret"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		var logBuf bytes.Buffer
		origOut := log.Writer()
		log.SetOutput(&logBuf)
		t.Cleanup(func() { log.SetOutput(origOut) })

		// When
		secret := loadOrCreateJWTSecretForTest(dir)

		// Then
		if len(secret) != 64 {
			t.Fatalf("secret=%q (len %d); want regenerated 64-char hex", secret, len(secret))
		}
		if strings.Contains(logBuf.String(), "过短") {
			t.Fatalf("empty file must not trigger short-secret warning, got %q", logBuf.String())
		}
	})
}

// JWT_SECRET 环境变量过短必须告警可见（文件通道强制 ≥32 并再生，
// 环境变量通道此前完全不校验——3 字节 HS256 密钥可离线爆破）。
func TestLoad_warnsOnShortEnvJWTSecret(t *testing.T) {
	t.Setenv("JWT_SECRET", "abc")
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	loaded := loadForTest("")

	if loaded.JWTSecret != "abc" {
		t.Fatalf("env secret=%q; want operator-provided value preserved", loaded.JWTSecret)
	}
	if !strings.Contains(logBuf.String(), "强度不足") || !strings.Contains(logBuf.String(), "过短") {
		t.Fatalf("short env secret must warn, got %q", logBuf.String())
	}

	// 回归形状：≥32 字节的高熵环境变量零告警。
	strong := "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928"
	t.Setenv("JWT_SECRET", strong)
	logBuf.Reset()
	if loaded := loadForTest(""); loaded.JWTSecret != strong {
		t.Fatalf("valid env secret=%q", loaded.JWTSecret)
	}
	if strings.Contains(logBuf.String(), "强度不足") || strings.Contains(logBuf.String(), "过短") {
		t.Fatalf("valid env secret must not warn, got %q", logBuf.String())
	}
}

// metrics_interval 的 ≤0 与超范围必须告警且结果确定（旧实现 0/负值
// 静默回落默认；巨值 float→int 回绕后可能被静默抬成 5s 高频采集）。
func TestLoad_metricsIntervalBoundsWarn(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	cases := []struct {
		name    string
		raw     string
		want    int
		wantLog string
	}{
		{name: "zero warns", raw: "0", want: 30, wantLog: "must be positive"},
		{name: "negative warns", raw: "-10", want: 30, wantLog: "must be positive"},
		{name: "huge clamps to max", raw: "1e300", want: metricsIntervalMax, wantLog: "above maximum"},
		{name: "above max clamps", raw: "90000", want: metricsIntervalMax, wantLog: "above maximum"},
		{name: "in range unchanged", raw: "12", want: 12, wantLog: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			origOut := log.Writer()
			log.SetOutput(&logBuf)
			t.Cleanup(func() { log.SetOutput(origOut) })

			configPath := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(configPath, []byte(`{"metrics_interval":`+tc.raw+`}`), 0600); err != nil {
				t.Fatal(err)
			}
			loaded := loadForTest(configPath)
			if loaded.MetricsInterval != tc.want {
				t.Fatalf("metrics interval=%d, want %d", loaded.MetricsInterval, tc.want)
			}
			if tc.wantLog != "" && !strings.Contains(logBuf.String(), tc.wantLog) {
				t.Fatalf("expected log %q, got %q", tc.wantLog, logBuf.String())
			}
			if tc.wantLog == "" && strings.Contains(logBuf.String(), "metrics_interval") {
				t.Fatalf("in-range interval must not log, got %q", logBuf.String())
			}
		})
	}
}

func TestLoad_normalizesRelativeDataDir(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("config.json", []byte(`{"data_dir":"./data"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := loadForTest("config.json")
	wantData := filepath.Join(dir, "data")
	if cfg.DataDir != wantData {
		t.Fatalf("DataDir=%q, want absolute %q", cfg.DataDir, wantData)
	}
	if cfg.BackupDir != filepath.Join(dir, "backup") {
		t.Fatalf("BackupDir=%q, want absolute sibling backup", cfg.BackupDir)
	}
}

// static_dir 与 data_dir/backup_dir 同口径：相对值以进程 cwd 解析（不是配置文件
// 目录），且消费侧直接拼接——必须绝对化并去尾随斜杠；目录不存在要在启动期告警，
// 而不是运行期静默 404。
func TestLoad_normalizesRelativeStaticDirAndWarnsWhenMissing(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll("ui", 0o755); err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	if err := os.WriteFile("config.json", []byte(`{"static_dir":"./ui/"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := loadForTest("config.json")
	if want := filepath.Join(dir, "ui"); cfg.StaticDir != want {
		t.Fatalf("StaticDir=%q, want absolute %q（去尾随斜杠）", cfg.StaticDir, want)
	}
	if strings.Contains(logBuf.String(), "static_dir") {
		t.Fatalf("存在的目录不应告警：%s", logBuf.String())
	}

	logBuf.Reset()
	if err := os.WriteFile("config.json", []byte(`{"static_dir":"missing-ui"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg = loadForTest("config.json")
	if want := filepath.Join(dir, "missing-ui"); cfg.StaticDir != want {
		t.Fatalf("StaticDir=%q, want absolute %q", cfg.StaticDir, want)
	}
	if !strings.Contains(logBuf.String(), "static_dir") || !strings.Contains(logBuf.String(), "404") {
		t.Fatalf("static_dir 不存在时缺少启动期告警：%q", logBuf.String())
	}
}

// 仅长度检查会让 32 个空格/单字符重复通过——可预测的 HS256 密钥
// 等价于无签名（JWT/OIDC state 可离线伪造）。低熵形态必须告警可见，且仍
// 保持「env 是运维显式输入、不自动替换」的既有裁定。
func TestLoad_warnsOnLowEntropyEnvJWTSecret(t *testing.T) {
	cases := []struct {
		name   string
		secret string
	}{
		{name: "all spaces", secret: strings.Repeat(" ", 32)},
		{name: "single repeated byte", secret: strings.Repeat("k", 32)},
		{name: "short distinct set", secret: strings.Repeat("ab", 16)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JWT_SECRET", tc.secret)
			var logBuf bytes.Buffer
			origOut := log.Writer()
			log.SetOutput(&logBuf)
			t.Cleanup(func() { log.SetOutput(origOut) })

			loaded := loadForTest("")

			if loaded.JWTSecret != tc.secret {
				t.Fatalf("env secret=%q; want operator-provided value preserved", loaded.JWTSecret)
			}
			if !strings.Contains(logBuf.String(), "强度不足") {
				t.Fatalf("low-entropy env secret must warn, got %q", logBuf.String())
			}
		})
	}
}

// port 必须与 metrics_interval 同口径——先判界再 float→int 转换。
// 1e300/0 直接转换会产生实现相关整数与怪日志；8000.9 仍须留痕截断。
func TestLoad_portBoundsBeforeConversion(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    int
		wantLog string
	}{
		{name: "in range", raw: "8081", want: 8081, wantLog: ""},
		{name: "fractional truncation", raw: "8000.9", want: 8000, wantLog: "not an integer"},
		{name: "huge magnitude", raw: "1e300", want: 8000, wantLog: "outside 1-65535"},
		{name: "zero", raw: "0", want: 8000, wantLog: "outside 1-65535"},
		{name: "negative", raw: "-1", want: 8000, wantLog: "outside 1-65535"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JWT_SECRET", "test-secret")
			var logBuf bytes.Buffer
			origOut := log.Writer()
			log.SetOutput(&logBuf)
			t.Cleanup(func() { log.SetOutput(origOut) })

			configPath := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(configPath, []byte(`{"port":`+tc.raw+`}`), 0600); err != nil {
				t.Fatal(err)
			}
			loaded := loadForTest(configPath)

			if loaded.Port != tc.want {
				t.Fatalf("port=%d, want %d (raw %s)", loaded.Port, tc.want, tc.raw)
			}
			if tc.wantLog != "" && !strings.Contains(logBuf.String(), tc.wantLog) {
				t.Fatalf("expected log %q, got %q", tc.wantLog, logBuf.String())
			}
			if tc.wantLog == "" && strings.Contains(logBuf.String(), "port") {
				t.Fatalf("in-range port must not log, got %q", logBuf.String())
			}
		})
	}
}

// 越界端口的告警必须指名**当前**默认值：消息里写死 8000 会在默认值改动后
// 立刻说谎，运维按提示改到旧默认值反而落入同一个越界分支。断言对着默认值
// 常量，而不是字面量。
func TestLoad_portOutOfRangeWarningNamesCurrentDefault(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"port":70000}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded := loadForTest(configPath)

	if loaded.Port != defaultPort {
		t.Fatalf("port=%d, want default %d", loaded.Port, defaultPort)
	}
	want := fmt.Sprintf("using default %d", defaultPort)
	if !strings.Contains(logBuf.String(), want) {
		t.Fatalf("warning 必须指名当前默认值 %q, got %q", want, logBuf.String())
	}
}

// 启动期配置告警必须能交回调用方重放：LoadCollectWarnings 不直接打印，
// 由 main 在运行日志装配完成后经统一日志级别门重放——否则只采集日志文件的
// 部署看不到未知键/类型错误/弱密钥/APP_VERSION 未注入等误配信号。
func TestLoadCollectWarnings_defersWarningsToCaller(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("APP_VERSION", "")
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"port":"not-a-number","bogus_key":1}`), 0600); err != nil {
		t.Fatal(err)
	}

	loaded, warnings := LoadCollectWarnings(configPath)

	if logBuf.Len() != 0 {
		t.Fatalf("收集模式不得直接打印告警，got %q", logBuf.String())
	}
	if loaded.Port != 8000 {
		t.Fatalf("port=%d, want 默认 8000（类型错误沿用默认值）", loaded.Port)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{
		`invalid type for key "port"`,
		`ignoring unsupported config key "bogus_key"`,
		"APP_VERSION 未注入",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("告警缺失 %q，got %q", want, joined)
		}
	}

	// 对照：测试侧包装 loadForTest 把同一批告警直接打到 log（既有用例的捕获
	// 口径）。生产不再有无告警出口的并行实现——唯一入口是本函数。
	logBuf.Reset()
	loadForTest("")
	if !strings.Contains(logBuf.String(), "APP_VERSION 未注入") {
		t.Fatalf("loadForTest 必须转发告警到 log，got %q", logBuf.String())
	}
}

// configFileKeys 是配置键的唯一登记表：类型校验与应用都由同一登记项驱动。
// 本用例逐键机械对表——正确类型必须生效且零类型告警，错误类型必须告警且
// 不改默认值。新增键漏写 apply（"支持但静默不生效"）会在此变红。
func TestConfigFileKeys_everyKeyAppliesAndValidates(t *testing.T) {
	t.Setenv("JWT_SECRET", "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928")
	cases := []struct {
		key      string
		goodJSON string
		check    func(t *testing.T, cfg *Config)
	}{
		{key: "data_dir", goodJSON: `"/tmp/lb-data-dir"`, check: func(t *testing.T, cfg *Config) {
			if cfg.DataDir != "/tmp/lb-data-dir" {
				t.Fatalf("data_dir=%q", cfg.DataDir)
			}
		}},
		{key: "static_dir", goodJSON: `"/tmp/lb-static"`, check: func(t *testing.T, cfg *Config) {
			if cfg.StaticDir != "/tmp/lb-static" {
				t.Fatalf("static_dir=%q", cfg.StaticDir)
			}
		}},
		{key: "port", goodJSON: `18081`, check: func(t *testing.T, cfg *Config) {
			if cfg.Port != 18081 {
				t.Fatalf("port=%d", cfg.Port)
			}
		}},
		{key: "caddy_admin_url", goodJSON: `"http://127.0.0.1:12019"`, check: func(t *testing.T, cfg *Config) {
			if cfg.CaddyAdminURL != "http://127.0.0.1:12019" {
				t.Fatalf("caddy_admin_url=%q", cfg.CaddyAdminURL)
			}
		}},
		{key: "caddy_metrics_url", goodJSON: `"http://127.0.0.1:12019/metrics"`, check: func(t *testing.T, cfg *Config) {
			if cfg.CaddyMetricsURL != "http://127.0.0.1:12019/metrics" {
				t.Fatalf("caddy_metrics_url=%q", cfg.CaddyMetricsURL)
			}
		}},
		{key: "metrics_interval", goodJSON: `17`, check: func(t *testing.T, cfg *Config) {
			if cfg.MetricsInterval != 17 {
				t.Fatalf("metrics_interval=%d", cfg.MetricsInterval)
			}
		}},
	}
	if len(cases) != len(configFileKeys) {
		t.Fatalf("用例 %d 个，configFileKeys %d 个——新增键必须同步补对表用例", len(cases), len(configFileKeys))
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			spec, ok := configFileKeys[tc.key]
			if !ok {
				t.Fatalf("configFileKeys 缺键 %q", tc.key)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(`{"`+tc.key+`":`+tc.goodJSON+`}`), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, warnings := LoadCollectWarnings(path)
			for _, w := range warnings {
				if strings.Contains(w, "invalid type") || strings.Contains(w, "unsupported") {
					t.Fatalf("正确类型不得告警: %q", w)
				}
			}
			tc.check(t, cfg)

			// 畸形形状：类型不符必须告警且沿用默认值。
			// 反类型：字符串键喂数字、数值键喂字符串（类型不符必须告警）。
			badJSON := `123`
			if spec.kind == configNumberValue {
				badJSON = `"7"`
			}
			if err := os.WriteFile(path, []byte(`{"`+tc.key+`":`+badJSON+`}`), 0600); err != nil {
				t.Fatal(err)
			}
			_, warnings = LoadCollectWarnings(path)
			found := false
			for _, w := range warnings {
				if strings.Contains(w, `invalid type for key "`+tc.key+`"`) {
					found = true
				}
			}
			if !found {
				t.Fatalf("错误类型必须告警，got %q", warnings)
			}
		})
	}
}

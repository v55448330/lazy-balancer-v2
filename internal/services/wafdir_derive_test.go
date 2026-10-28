package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/wafiplist"
)

// saveWafPathVars 保存/恢复 ConfigureWafDirs 可改写的全部包级路径变量
// （ 起派生面扩大，逐变量手抄易漏导致测试间污染）。
func saveWafPathVars(t *testing.T) {
	t.Helper()
	old := struct {
		wafDir, wafDistDir, ipListDir, allowedPrefix               string
		crsLive, crsDirectives, crsRuleIndex, crsSnapshot, crsDist string
		xdbLive, xdbDist, crawlerSeed, crawlerLive                 string
		auditLog, eventsOffset, downloadIntegrity                  string
		ipcSocket, spoolDir                                        string
	}{
		wafDir, wafDistDir, IPListDataDir, wafiplist.AllowedPathPrefix,
		crsLiveDir, crsDirectivesDir, CRSRuleIndexDir, crsSnapshotDir, crsDistDir,
		ip2regionLivePath, ip2regionDistPath, crawlerDistSeedFile, crawlerIPListFile,
		auditLogPath, securityEventsOffsetPath, downloadIntegrityPath,
		securityEventsIPCSocketPath, securityEventsSpoolDir,
	}
	t.Cleanup(func() {
		wafDir, wafDistDir, IPListDataDir, wafiplist.AllowedPathPrefix =
			old.wafDir, old.wafDistDir, old.ipListDir, old.allowedPrefix
		crsLiveDir, crsDirectivesDir, CRSRuleIndexDir, crsSnapshotDir, crsDistDir =
			old.crsLive, old.crsDirectives, old.crsRuleIndex, old.crsSnapshot, old.crsDist
		ip2regionLivePath, ip2regionDistPath, crawlerDistSeedFile, crawlerIPListFile =
			old.xdbLive, old.xdbDist, old.crawlerSeed, old.crawlerLive
		auditLogPath, securityEventsOffsetPath = old.auditLog, old.eventsOffset
		downloadIntegrityPath = old.downloadIntegrity
		securityEventsIPCSocketPath, securityEventsSpoolDir = old.ipcSocket, old.spoolDir
	})
}

func TestConfigureWafDirs_propagatesThreatWafDir(t *testing.T) {
	saveWafPathVars(t)

	dataDir := filepath.Join(t.TempDir(), "custom-data")
	ConfigureWafDirs(dataDir)
	wantWaf := filepath.Join(filepath.Dir(dataDir), "waf")
	if wafDir != wantWaf {
		t.Fatalf("wafDir=%q, want %q (threat files must follow data_dir)", wafDir, wantWaf)
	}
	if IPListDataDir != filepath.Join(wantWaf, "ip-lists") {
		t.Fatalf("IPListDataDir=%q", IPListDataDir)
	}
	if wafiplist.AllowedPathPrefix != wantWaf+string(filepath.Separator) {
		t.Fatalf("AllowedPathPrefix=%q", wafiplist.AllowedPathPrefix)
	}
}

// ConfigureWafDirs 必须是全部 WAF 路径的单点派生真源——此前
// CRS 活树/快照/dist、xdb 与指令目录各自硬编码 /app，data_dir ≠ /app/data
// 时写侧散落到数据卷之外、读侧（索引/渲染）仍读 /app，安全链静默不渲染。
func TestConfigureWafDirs_derivesAllWafPaths(t *testing.T) {
	saveWafPathVars(t)

	parent := t.TempDir()
	dataDir := filepath.Join(parent, "custom-data")
	ConfigureWafDirs(dataDir)

	wantWaf := filepath.Join(parent, "waf")
	wantDist := filepath.Join(parent, "waf.dist")
	cases := []struct{ name, got, want string }{
		{"wafDir", wafDir, wantWaf},
		{"wafDistDir", wafDistDir, wantDist},
		{"IPListDataDir", IPListDataDir, filepath.Join(wantWaf, "ip-lists")},
		{"crsLiveDir", crsLiveDir, filepath.Join(wantWaf, "crs")},
		{"crsDirectivesDir", crsDirectivesDir, filepath.Join(wantWaf, "crs")},
		{"CRSRuleIndexDir", CRSRuleIndexDir, filepath.Join(wantWaf, "crs", "rules")},
		{"crsSnapshotDir", crsSnapshotDir, filepath.Join(dataDir, "crs")},
		{"crsDistDir", crsDistDir, filepath.Join(wantDist, "crs")},
		{"ip2regionLivePath", ip2regionLivePath, filepath.Join(dataDir, "ip2region.xdb")},
		{"ip2regionDistPath", ip2regionDistPath, filepath.Join(wantDist, "ip2region.xdb")},
		{"crawlerDistSeedFile", crawlerDistSeedFile, filepath.Join(wantDist, "crawler-ip-lists.seed.json")},
		// 爬虫运行快照同属数据卷派生面（root 服务写、插件读）。
		{"crawlerIPListFile", crawlerIPListFile, filepath.Join(dataDir, "crawler-ip-lists.json")},
		// 审计日志与摄取 offset 同属派生面（此前硬编码 /app）。
		{"auditLogPath", auditLogPath, filepath.Join(parent, "logs", "waf-audit", "audit.log")},
		{"securityEventsOffsetPath", securityEventsOffsetPath, filepath.Join(dataDir, "security_events.offset")},
		// 下载 TOFU 完整性基线同属数据卷派生面（此前硬编码 /app/data，
		// 自定义 data_dir 下基线持久化恒失败 → 代理投毒阻断静默失效）。
		{"downloadIntegrityPath", downloadIntegrityPath, filepath.Join(dataDir, ".download-integrity.json")},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s=%q, want %q（未跟随 data_dir 派生→写读分叉）", c.name, c.got, c.want)
		}
	}
}

// 容器默认形态（data_dir=/app/data）必须保持 /app/* 常量逐字节一致。
func TestConfigureWafDirs_containerDefaultKeepsAppPaths(t *testing.T) {
	saveWafPathVars(t)

	ConfigureWafDirs("/app/data")
	if crsLiveDir != "/app/waf/crs" || crsSnapshotDir != "/app/data/crs" ||
		crsDistDir != "/app/waf.dist/crs" || ip2regionLivePath != "/app/data/ip2region.xdb" ||
		ip2regionDistPath != "/app/waf.dist/ip2region.xdb" || CRSRuleIndexDir != "/app/waf/crs/rules" {
		t.Fatalf("容器默认路径被改写: crs=%q snapshot=%q dist=%q xdb=%q/%q index=%q",
			crsLiveDir, crsSnapshotDir, crsDistDir, ip2regionLivePath, ip2regionDistPath, CRSRuleIndexDir)
	}
	// 容器默认形态保持既有审计日志/offset 路径逐字节一致。
	if auditLogPath != "/app/logs/waf-audit/audit.log" || securityEventsOffsetPath != "/app/data/security_events.offset" {
		t.Fatalf("容器默认审计路径被改写: audit=%q offset=%q", auditLogPath, securityEventsOffsetPath)
	}
	// 容器默认形态爬虫运行快照保持 /app/data 常量逐字节一致。
	if crawlerIPListFile != "/app/data/crawler-ip-lists.json" {
		t.Fatalf("容器默认爬虫快照路径被改写: %q", crawlerIPListFile)
	}
	// TOFU 完整性基线在容器默认形态同样保持 /app/data 常量。
	if downloadIntegrityPath != "/app/data/.download-integrity.json" {
		t.Fatalf("容器默认完整性基线路径被改写: %q", downloadIntegrityPath)
	}
}

// data_dir 为 /app 的直接子目录、但不是容器默认 /app/data 时同样必须派生：旧判据
// 「父目录 == /app」会把 /app/custom 当成容器默认形态早退，CRS 快照/xdb/crawler
// 快照/审计日志全部留在 /app/*（容器重建即丢、xdb 指向不存在的库）。
func TestConfigureWafDirs_appSubdirIsNotContainerDefault(t *testing.T) {
	saveWafPathVars(t)

	ConfigureWafDirs("/app/custom")
	cases := []struct{ name, got, want string }{
		{"wafDir", wafDir, "/app/waf"},
		{"IPListDataDir", IPListDataDir, "/app/waf/ip-lists"},
		{"crsLiveDir", crsLiveDir, "/app/waf/crs"},
		{"crsSnapshotDir", crsSnapshotDir, "/app/custom/crs"},
		{"ip2regionLivePath", ip2regionLivePath, "/app/custom/ip2region.xdb"},
		{"crawlerIPListFile", crawlerIPListFile, "/app/custom/crawler-ip-lists.json"},
		{"securityEventsOffsetPath", securityEventsOffsetPath, "/app/custom/security_events.offset"},
		{"downloadIntegrityPath", downloadIntegrityPath, "/app/custom/.download-integrity.json"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s=%q, want %q（/app 子目录被误判为容器默认形态→派生被跳过）", c.name, c.got, c.want)
		}
	}
}

func TestConfigureWafDirs_derivesIPCEnvironmentWithoutOverridingExplicitPaths(t *testing.T) {
	saveWafPathVars(t)
	restoreEnv := func(name string) {
		value, present := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}
		t.Cleanup(func() {
			if present {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
	restoreEnv(SecurityEventsIPCSocketEnv)
	restoreEnv(SecurityEventsSpoolDirEnv)

	dataDir := filepath.Join(t.TempDir(), "custom-data")
	ConfigureWafDirs(dataDir)
	if got, want := os.Getenv(SecurityEventsIPCSocketEnv), filepath.Join(dataDir, "security-events.sock"); got != want {
		t.Fatalf("IPC socket env=%q, want %q", got, want)
	}
	if got, want := os.Getenv(SecurityEventsSpoolDirEnv), filepath.Join(dataDir, "security-events-spool"); got != want {
		t.Fatalf("spool env=%q, want %q", got, want)
	}

	if err := os.Setenv(SecurityEventsIPCSocketEnv, "/explicit/custom.sock"); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(SecurityEventsSpoolDirEnv, "/explicit/custom-spool"); err != nil {
		t.Fatal(err)
	}
	ConfigureWafDirs(filepath.Join(t.TempDir(), "other-data"))
	if got := os.Getenv(SecurityEventsIPCSocketEnv); got != "/explicit/custom.sock" {
		t.Fatalf("explicit socket env overwritten: %q", got)
	}
	if got := os.Getenv(SecurityEventsSpoolDirEnv); got != "/explicit/custom-spool" {
		t.Fatalf("explicit spool env overwritten: %q", got)
	}
}

// 非默认 data_dir 下「面板派生」只发生在面板进程：Caddy 二进制里的
// wafiplist 名单白名单是常量 /app/waf/、IPC 路径取自 Caddy 自身环境（容器形态
// 由监督器先启动 Caddy，面板随后的 os.Setenv 到不了它）。此前这条断裂完全
// 静默——直到某条规则启用 IP 访问控制/受信代理时配置被拒、安全事件永远为空。
// 启动期必须显式留痕并指向根因与支持矩阵。
func TestConfigureWafDirs_logsPluginDivergenceForNonDefaultDataDir(t *testing.T) {
	saveWafPathVars(t)
	for _, name := range []string{SecurityEventsIPCSocketEnv, SecurityEventsSpoolDirEnv} {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	buf := captureLogf(t)

	ConfigureWafDirs(filepath.Join(t.TempDir(), "custom-data"))

	logged := buf.String()
	for _, want := range []string{"不是容器默认", "/app/waf", "Caddy", "不会被它继承", SecurityEventsIPCSocketEnv} {
		if !strings.Contains(logged, want) {
			t.Fatalf("启动期告警 %q 未包含 %q（须指向根因与显式 env 兜底）", logged, want)
		}
	}
}

// 容器默认形态（data_dir=/app/data）两侧常量逐字节一致，不得产生噪音告警。
func TestConfigureWafDirs_defaultDataDirHasNoDivergenceWarning(t *testing.T) {
	saveWafPathVars(t)
	buf := captureLogf(t)

	ConfigureWafDirs("/app/data")

	if strings.Contains(buf.String(), "不是容器默认") {
		t.Fatalf("默认 data_dir 不得告警: %q", buf.String())
	}
}

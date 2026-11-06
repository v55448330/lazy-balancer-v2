package handlers

// OIDC 与会话写路径取消传播的源码契约守卫（技法同 autobackup_read_ctx_guard_test.go）：
// 配置保存/删除、OIDC JIT 开户 INSERT、显示名刷新 UPDATE、登出吊销 INSERT
// 等请求面写点此前用无 ctx 的 Exec/Begin——客户端断开后写事务仍无主跑完，
// 「取消即中止」退化为逐点人工核对的不变量。这里按函数体扫描把 ctx-less
// 写访问钉成确定性失败。

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestRequestSurfaceWritesConsumeRequestContext(t *testing.T) {
	ctxless := regexp.MustCompile(`db\.DB\.(Exec|Begin)\(`)
	tests := []struct {
		file    string
		fn      string
		markers []string
	}{
		{
			// 单点写契约：语句消费调用方传入的请求 ctx（取消即中止、零副作用）。
			file:    "auth_oidc.go",
			fn:      "func saveOIDCConfig(ctx context.Context, cfg OIDCConfig) error {",
			markers: []string{"ExecContext(ctx"},
		},
		{
			// 契约=「事务开启消费请求 ctx」（BeginTx 排锁/迁移读取阶段取消即
			// 中止）；配置写回与身份行迁移全有或全无，未提交事务由 committed
			// 标记 defer 回滚兜住。marker 只钉开启点。
			file:    "auth_oidc.go",
			fn:      "func saveOIDCConfigWithIssuerMigration(ctx context.Context, cfg OIDCConfig, migrateFrom string) (oidcIssuerMigration, error) {",
			markers: []string{"BeginTx(ctx"},
		},
		{
			// OIDC JIT 开户 INSERT：登录链上的请求面写点，语句消费请求 ctx
			//（客户端断开/超时即中止，零副作用）。
			file:    "auth_oidc.go",
			fn:      "func createOIDCUserWithRetry(ctx context.Context, issuer, subject, base, displayName string) (oidcIdentity, bool, error) {",
			markers: []string{"ExecContext(ctx"},
		},
		{
			// 显示名刷新 UPDATE：best-effort 不中断登录，但仍是请求面写点，
			// 同契约。
			file:    "auth_oidc.go",
			fn:      "func refreshOIDCDisplayName(ctx context.Context, userID int, username, name string) {",
			markers: []string{"ExecContext(ctx"},
		},
		{
			// 登出吊销 INSERT（revoked_jti）：请求面写点同契约，handler 内
			// 直接取 c.Request.Context()。
			file:    "auth.go",
			fn:      "func (h *Handlers) Logout(c *gin.Context) {",
			markers: []string{"ExecContext(c.Request.Context()"},
		},
	}
	for _, test := range tests {
		source, err := os.ReadFile(test.file)
		if err != nil {
			t.Fatal(err)
		}
		body, ok := handlerFunctionBody(string(source), test.fn)
		if !ok {
			t.Fatalf("%s 中未找到 %q（函数改名会让本守卫失效）", test.file, test.fn)
		}
		if hit := ctxless.FindString(body); hit != "" {
			t.Fatalf("%s 的 %s 仍有无 ctx 的 %s（客户端断开后写事务继续跑；须改 *Context 系列）", test.file, test.fn, hit)
		}
		marked := false
		for _, marker := range test.markers {
			if strings.Contains(body, marker) {
				marked = true
				break
			}
		}
		if !marked {
			t.Fatalf("%s 的 %s 未出现任何 ctx 透传形态（%v），扫描面可能失效", test.file, test.fn, test.markers)
		}
	}
}

// 两个 HTTP 写点必须把请求 ctx 传入保存入口（签名收敛后调用侧的 ctx 透传
// 同样钉死，防止后续改回 Background 假贯通）。
func TestOIDCConfigSaveHandlersPassRequestContext(t *testing.T) {
	source, err := os.ReadFile("auth_oidc.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"saveOIDCConfigWithIssuerMigration(c.Request.Context(), cfg, migrateFrom)",
		"saveOIDCConfig(c.Request.Context(), OIDCConfig{})",
	} {
		if !strings.Contains(string(source), want) {
			t.Fatalf("OIDC 配置写点必须把请求 ctx 传入保存入口，缺少: %q", want)
		}
	}
}

// 刻意无 ctx 写点的登记豁免表（「登记豁免表」模式）：请求面五个文件中全部
// db.DB.Exec/Begin ctx-less 写点必须落在表内函数，且函数体必须带「刻意无 ctx
// 豁免」标记注释（rationale 与本表互引）。三重失败面：①表外新增 ctx-less
// 写点（文件总写点数 > 表内登记数之和）；②表内函数写点数与登记 count 不符
// （函数内新增/删减写点）；③豁免标记注释被删。表内函数改名的失效由
// handlerFunctionBody 找不到签名钉住——登记必须与代码同步更新。
func TestDeliberateCtxlessWritesAreRegistered(t *testing.T) {
	const marker = "刻意无 ctx 豁免"
	// 扫描集：认证/API Key/品牌播种/配置导入四个请求面 handler 文件 + OIDC
	// 文件（后者表内零登记——其写点全部走上方消费契约，任何 ctx-less 新增即红）。
	scanFiles := []string{"auth.go", "auth_oidc.go", "apikeys.go", "branding.go", "config_backup.go"}
	exemptions := []struct {
		file  string
		fn    string // 顶层 func 签名（改名即失效——登记与代码同步更新）
		count int    // 函数体内允许的 ctx-less 写点数
	}{
		// 登录链失败计数与锁定：攻击者断连时盲改 ctx 会丢暴力破解证据——
		// 失败计数是事实，随请求中止等于给断连重放免费擦除窗口（rationale
		// 详见函数体内豁免注释）。
		{file: "auth.go", fn: "func recordLoginFailure(userID int) {", count: 2},
		// 登录成功收尾清零：best-effort 有意设计——清零失败不撤销已签发 JWT。
		{file: "auth.go", fn: "func (h *Handlers) Login(c *gin.Context) {", count: 1},
		// touchLastLogin：last_login 活动证据记账 best-effort，非授权前提。
		{file: "auth.go", fn: "func touchLastLogin(userID int, username, clientIP string) (time.Time, bool) {", count: 1},
		// SetupAdmin：引导期一次性播种，幂等 NOT EXISTS，写入必须无条件完成。
		{file: "auth.go", fn: "func (h *Handlers) SetupAdmin(c *gin.Context) {", count: 1},
		// deleteAPIKey：name 查询与 DELETE 分离两语句、无事务包裹（audit125
		// 已披露的同族分离形态，注释互引）。
		{file: "apikeys.go", fn: "func deleteAPIKey(c *gin.Context, scopedUserID int) {", count: 1},
		// SeedDefaultBlockPage：默认页/内置页播种族，boot/同步语境漂移自愈。
		{file: "branding.go", fn: "func SeedDefaultBlockPage(dataDir string) (bool, error) {", count: 3},
		// importConfigBackupCore 水位收敛：auto_backup_last_run 单行 UPDATE，
		// 恢复通道自有一致性机制。
		{file: "config_backup.go", fn: "func (h *Handlers) importConfigBackupCore(c *gin.Context, data []byte, filename, action string) {", count: 1},
	}
	ctxless := regexp.MustCompile(`db\.DB\.(Exec|Begin)\(`)
	fileTotals := map[string]int{}
	for _, f := range scanFiles {
		source, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fileTotals[f] = len(ctxless.FindAllString(string(source), -1))
	}
	registeredTotals := map[string]int{}
	for _, ex := range exemptions {
		source, err := os.ReadFile(ex.file)
		if err != nil {
			t.Fatal(err)
		}
		body, ok := handlerFunctionBody(string(source), ex.fn)
		if !ok {
			t.Fatalf("%s 中未找到 %q（函数改名会让本守卫失效，登记必须同步更新）", ex.file, ex.fn)
		}
		registeredTotals[ex.file] += ex.count
		if got := len(ctxless.FindAllString(body, -1)); got != ex.count {
			t.Fatalf("%s 的 %s 实际 ctx-less 写点 %d 处，登记 %d 处——函数内新增/删减写点必须同步更新登记表", ex.file, ex.fn, got, ex.count)
		}
		if !strings.Contains(body, marker) {
			t.Fatalf("%s 的 %s 缺少「%s」标记注释——表内函数必须留豁免 rationale 与登记表互引", ex.file, ex.fn, marker)
		}
	}
	for _, f := range scanFiles {
		if fileTotals[f] != registeredTotals[f] {
			t.Fatalf("%s 共 %d 处 ctx-less 写点，登记表仅覆盖 %d 处——表外新增写点必须改 *Context 系列消费请求 ctx 或带 rationale 登记", f, fileTotals[f], registeredTotals[f])
		}
	}
}

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

// 刻意无 ctx 写点的登记豁免表（「登记豁免表」模式）：请求面 handler 文件
// 全集（12 文件，见 scanFiles）中全部
// db.DB.Exec/Begin ctx-less 写点必须落在表内函数，且函数体必须带「刻意无 ctx
// 豁免」标记注释（rationale 与本表互引）。三重失败面：①表外新增 ctx-less
// 写点（文件总写点数 > 表内登记数之和）；②表内函数写点数与登记 count 不符
// （函数内新增/删减写点）；③豁免标记注释被删。表内函数改名的失效由
// handlerFunctionBody 找不到签名钉住——登记必须与代码同步更新。
func TestDeliberateCtxlessWritesAreRegistered(t *testing.T) {
	const marker = "刻意无 ctx 豁免"
	// 扫描集：请求面 handler 文件全集（全仓 db.DB.Exec/Begin 静态文本清点
	// 仅此 12 个非测试文件命中；count 字段=静态文本出现数，循环内写点按
	// 出现次数计，非运行次数）+ OIDC 文件（表内零登记——其写点全部走上方
	// 消费契约，任何 ctx-less 新增即红）。
	scanFiles := []string{
		"auth.go", "auth_oidc.go", "apikeys.go", "branding.go", "config_backup.go",
		"mfa.go", "users.go", "rules.go", "certjobs.go", "certificates.go", "admintls.go", "handlers.go",
	}
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
		// deleteAPIKey：name 查询与 DELETE 分离两语句、无事务包裹（既有已
		// 披露的同族分离形态，注释互引）。
		{file: "apikeys.go", fn: "func deleteAPIKey(c *gin.Context, scopedUserID int) {", count: 1},
		// SeedDefaultBlockPage：默认页/内置页播种族，boot/同步语境漂移自愈。
		{file: "branding.go", fn: "func SeedDefaultBlockPage(dataDir string) (bool, error) {", count: 3},
		// importConfigBackupCore 水位收敛：auto_backup_last_run 单行 UPDATE，
		// 恢复通道自有一致性机制。
		{file: "config_backup.go", fn: "func (h *Handlers) importConfigBackupCore(c *gin.Context, data []byte, filename, action string) {", count: 1},
		// —— 以下为 mfa.go/users.go/rules.go/certjobs.go/certificates.go/
		// admintls.go/handlers.go 的逐函数登记（与既有七函数同族口径；
		// rationale 详见各函数体内「刻意无 ctx 豁免」注释）——
		// MFAVerifyLogin：登录验证链两点（挑战消费删除+登录成功清零），
		// 清零与 auth.go Login 已登记点逐字同语义。
		{file: "mfa.go", fn: "func (h *Handlers) MFAVerifyLogin(c *gin.Context) {", count: 2},
		// MFASetup：pending 密钥单行原子写（新密钥+失败计数清零同生共死）。
		{file: "mfa.go", fn: "func (h *Handlers) MFASetup(c *gin.Context) {", count: 1},
		// CreateUser：单行 INSERT，唯一约束 409 分判在位。
		{file: "users.go", fn: "func (h *Handlers) CreateUser(c *gin.Context) {", count: 1},
		// UpdateRule：域迁移事务开启（规则主更新已提交后的续链）+
		// 重启用 resume 记账。
		{file: "rules.go", fn: "func (h *Handlers) UpdateRule(c *gin.Context) {", count: 2},
		// EnableRule：启用失败补偿恢复写 + resume 记账。
		{file: "rules.go", fn: "func (h *Handlers) EnableRule(c *gin.Context) {", count: 2},
		// retryCertJobByID：部署重试失败文案留痕 + CA 队列重入队任务函数。
		{file: "certjobs.go", fn: "func (h *Handlers) retryCertJobByID(c *gin.Context, id int) {", count: 2},
		// registerDownloadedCertJobDeploymentRetry：timer 登记失败后的文案纠偏。
		{file: "certjobs.go", fn: "func registerDownloadedCertJobDeploymentRetry(id int, ruleID string) error {", count: 1},
		// DeleteCertJob：删除链五写点（disable CAS/DELETE/恢复/重入队/failed 回退）。
		{file: "certjobs.go", fn: "func (h *Handlers) DeleteCertJob(c *gin.Context) {", count: 5},
		// CreateCertificateConfig：DNS 配置单行 INSERT。
		{file: "certificates.go", fn: "func (h *Handlers) CreateCertificateConfig(c *gin.Context) {", count: 1},
		// DeleteCertificateConfig：引用查询与 DELETE 分离两语句（deleteAPIKey
		// 同族分离形态）。
		{file: "certificates.go", fn: "func (h *Handlers) DeleteCertificateConfig(c *gin.Context) {", count: 1},
		// UpdateAdminTLS：HTTPS 配置单行写（材料校验前置、RowsAffected 核对在位）。
		{file: "admintls.go", fn: "func (h *Handlers) UpdateAdminTLS(c *gin.Context) {", count: 1},
		// recordCaddyApplyResult：apply 结果横幅清除（best-effort 运维可见性记账）。
		{file: "handlers.go", fn: "func (h *Handlers) recordCaddyApplyResult(err error) {", count: 1},
		// persistCaddyApplyBanner：横幅持久化（best-effort，失败仅 warn）。
		{file: "handlers.go", fn: "func persistCaddyApplyBanner(text string) {", count: 1},
		// rollbackLeakedTx：提交失败后连接池补发 ROLLBACK——var 闭包无顶层
		// func 签名，按 var 声明行钉名（改名即失效，登记与代码同步更新）。
		{file: "handlers.go", fn: "var rollbackLeakedTx = func() {", count: 1},
		// clampAuditRetentionMonthsOnStartup：启动阶段一次性钳位（无请求 ctx
		// 存在的语境）。
		{file: "handlers.go", fn: "func clampAuditRetentionMonthsOnStartup() {", count: 1},
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

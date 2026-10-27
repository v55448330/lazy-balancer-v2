package handlers

// 路由可达但此前零覆盖/零契约断言的端点（handlers 包 0% 函数清单）：
// MCP 运维手册下载、OpenAPI 规格/Swagger 壳、登出、CA/DNS 提供商列表、
// 注册令牌生成、更新日志端点、Caddy 重启 watcher 幂等门、指标总览、
// IP2Region 状态/日志、导入失败收尾（failImportTx）。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func getRoute(t *testing.T, h *Handlers, path string, register gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET(path, register)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

// MCP 运维手册下载：任何登录用户可达，媒体类型/附件名/正文装配是外部契约
// （改成 JSON、丢附件名或空正文都会让 MCP 客户端拿到坏文件）。
func TestGetMCPOpsPlaybook_servesMarkdownAttachment(t *testing.T) {
	h := NewHandlers(Dependencies{})
	recorder := getRoute(t, h, "/api/v1/mcp/ops-playbook", h.GetMCPOpsPlaybook)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got, want := recorder.Header().Get("Content-Type"), "text/markdown; charset=utf-8"; got != want {
		t.Fatalf("Content-Type=%q, want %q", got, want)
	}
	if got, want := recorder.Header().Get("Content-Disposition"), `attachment; filename="lazy-balancer-mcp-ops-playbook.md"`; got != want {
		t.Fatalf("Content-Disposition=%q, want %q", got, want)
	}
	body := recorder.Body.String()
	if !strings.HasPrefix(body, "#") {
		t.Fatalf("正文必须以 Markdown 标题开头（不是空/JSON）: %q", body[:min(len(body), 80)])
	}
	if body != mcpserver.OpsPlaybook() {
		t.Fatal("响应正文必须与单源 OpsPlaybook() 完全一致（装配不得二次加工）")
	}
}

// OpenAPI YAML 是前端 API 文档页与外部集成方的规格源：媒体类型与关键节点
// （openapi/paths/security）必须具备，且包含真实路由。
func TestGetOpenAPIYAML_servesSpecWithPathsAndBearerSecurity(t *testing.T) {
	h := NewHandlers(Dependencies{})
	recorder := getRoute(t, h, "/api/v1/openapi.yaml", h.GetOpenAPIYAML)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/yaml") {
		t.Fatalf("Content-Type=%q, want application/yaml", got)
	}
	spec := recorder.Body.String()
	for _, marker := range []string{"openapi:", "paths:", "/api/v1/rules"} {
		if !strings.Contains(spec, marker) {
			t.Fatalf("规格缺 %q（前 200 字节：%q）", marker, spec[:min(len(spec), 200)])
		}
	}
}

// Swagger UI 壳：必须是 HTML 且指向已鉴权规格端点 + 离线 fallback 链接。
func TestGetAPIDocs_servesSwaggerShellWithFallback(t *testing.T) {
	h := NewHandlers(Dependencies{})
	recorder := getRoute(t, h, "/api/v1/docs", h.GetAPIDocs)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("Content-Type=%q, want text/html", got)
	}
	page := recorder.Body.String()
	for _, marker := range []string{"swagger-ui", "/api/v1/openapi.yaml", "id=\"fallback\""} {
		if !strings.Contains(page, marker) {
			t.Fatalf("Swagger 壳缺 %q", marker)
		}
	}
}

// Logout 的三分支：API Key 无会话令牌 404、缺吊销材料 500、JWT 成功写
// revoked_jti 并留审计。
func TestLogout_branches(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	mount := func(setup func(*gin.Context)) *gin.Engine {
		router := gin.New()
		router.POST("/logout", func(c *gin.Context) {
			setup(c)
			h.Logout(c)
		})
		return router
	}
	post := func(router *gin.Engine) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/logout", nil))
		return recorder
	}

	// API Key 认证：无会话令牌可吊销。
	recorder := post(mount(func(c *gin.Context) { c.Set("auth_type", "api_key") }))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("API Key 登出 status=%d, want 404（无会话令牌）", recorder.Code)
	}

	// JWT 但缺少吊销材料：500（不写库）。
	recorder = post(mount(func(c *gin.Context) { c.Set("username", "zhang") }))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("缺吊销材料 status=%d, want 500", recorder.Code)
	}

	// 成功路径：写 revoked_jti + 审计。
	hash := "sha256:logout-test-hash"
	recorder = post(mount(func(c *gin.Context) {
		c.Set("username", "zhang")
		c.Set("token_revocation_hash", hash)
		c.Set("token_expires_at", time.Now().Add(time.Hour))
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("成功登出 status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM revoked_jti WHERE jti_hash=?`, hash).Scan(&stored); err != nil {
		t.Fatalf("read revoked_jti: %v", err)
	}
	if stored != 1 {
		t.Fatalf("revoked_jti 行数=%d, want 1（登出未落吊销记录=令牌仍可用）", stored)
	}
	if n := countAuditRows(t, "登出", "用户认证"); n != 1 {
		t.Fatalf("登出审计=%d, want 1", n)
	}
}

// CA 提供商列表：管理页提供商选择器数据源，空列表会把「默认提供商」下拉
// 变空（用户无法配置）；断言非空 + 关键字段。
func TestListCAProviders_returnsSeededProviders(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	recorder := getRoute(t, h, "/ca-providers", h.ListCAProviders)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code int `json:"code"`
		Data []map[string]any
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Code != 0 || len(body.Data) == 0 {
		t.Fatalf("CA 提供商列表为空: %s", recorder.Body.String())
	}
	for _, field := range []string{"id", "name", "provider", "enabled"} {
		if _, ok := body.Data[0][field]; !ok {
			t.Fatalf("提供商条目缺 %q: %v", field, body.Data[0])
		}
	}
}

// DNS 提供商列表：前端证书配置表单的字段元数据单源（Code 排序稳定）。
func TestListDNSProviders_returnsRegistryMetadata(t *testing.T) {
	h := NewHandlers(Dependencies{})
	recorder := getRoute(t, h, "/dns-providers", h.ListDNSProviders)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code int `json:"code"`
		Data []struct {
			Code   string           `json:"code"`
			Fields []map[string]any `json:"credential_fields"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Code != 0 || len(body.Data) == 0 {
		t.Fatalf("DNS 提供商列表为空: %s", recorder.Body.String())
	}
	last := ""
	for _, provider := range body.Data {
		if provider.Code <= last {
			t.Fatalf("提供商顺序不稳定（%q 之后是 %q）", last, provider.Code)
		}
		last = provider.Code
		if len(provider.Fields) == 0 {
			t.Fatalf("提供商 %s 缺 credential_fields（前端表单无法渲染）", provider.Code)
		}
	}
}

// 注册令牌生成：令牌只显示一次、返回 RFC3339 到期时间并留审计。
func TestGenerateClusterRegisterToken_returnsTokenAndAudits(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/register-tokens", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "zhang")
		h.GenerateClusterRegisterToken(c)
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/cluster/register-tokens", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code int `json:"code"`
		Data struct {
			Token     string `json:"token"`
			ExpiresAt string `json:"expires_at"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data.Token) < 16 {
		t.Fatalf("注册令牌过短: %q", body.Data.Token)
	}
	if _, err := time.Parse(time.RFC3339, body.Data.ExpiresAt); err != nil {
		t.Fatalf("expires_at=%q 非 RFC3339: %v", body.Data.ExpiresAt, err)
	}
	if n := countAuditRows(t, "生成", "注册令牌"); n != 1 {
		t.Fatalf("注册令牌审计=%d, want 1", n)
	}
}

// 更新日志端点：任务日志文件（含轮转副本）是唯一数据源。
func TestLibUpdateLogs_readTaskLogWithRotation(t *testing.T) {
	old := taskengine.LogDir()
	dir := t.TempDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(old) })

	handler := NewHandlers(Dependencies{})
	cases := []struct {
		name     string
		taskID   string
		register gin.HandlerFunc
	}{
		{"ip2region 更新日志", "ip2region", handler.GetIP2RegionUpdateLogs},
		{"爬虫地址库更新日志", services.CrawlerTaskID, handler.GetCrawlerLibUpdateLogs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := taskengine.TaskLogPath(tc.taskID)
			if path == "" {
				t.Fatal("任务日志路径为空（LogDir 未设置）")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("当前轮日志\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".1", []byte("轮转前日志\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			recorder := getRoute(t, handler, "/logs", tc.register)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if body := recorder.Body.String(); !strings.Contains(body, "轮转前日志") || !strings.Contains(body, "当前轮日志") {
				t.Fatalf("日志尾读缺轮转副本或当前文件: %s", body)
			}
		})
	}
}

// Caddy 重启 watcher 幂等门：重复调用不得启动第二个 watcher（双 watcher 会
// 让同一触发文件被执行两次全量渲染 + /load）。断言启动次数而非标志位——
// 标志位区分不了「第二次提前返回」与「第二次又起了一个 goroutine」。
func TestStartCaddyRestartWatcher_secondCallStartsNoSecondLoop(t *testing.T) {
	oldLoop := caddyRestartWatcherLoop
	release := make(chan struct{})
	starts := make(chan struct{}, 2)
	// 替身循环：登记一次启动后挂起，既证明「起了一个」也不让真实 2s 轮询
	// 泄漏到后续用例。
	caddyRestartWatcherLoop = func(*Handlers) {
		starts <- struct{}{}
		<-release
	}
	caddyRestartWatcherStarted.Store(false)
	t.Cleanup(func() {
		close(release) // 先停替身循环，再还原 seam
		caddyRestartWatcherStarted.Store(false)
		caddyRestartWatcherLoop = oldLoop
	})

	h := NewHandlers(Dependencies{})
	h.StartCaddyRestartWatcher()
	select {
	case <-starts:
	case <-time.After(2 * time.Second):
		t.Fatal("首次调用未启动 watcher 循环")
	}
	if !caddyRestartWatcherStarted.Load() {
		t.Fatal("首次调用必须置位 started 标记")
	}

	// 第二次调用必须被 CAS 门挡住：200ms 内不得出现第二个循环实例。
	h.StartCaddyRestartWatcher()
	select {
	case <-starts:
		t.Fatal("第二次调用又启动了 watcher 循环（幂等门失效）")
	case <-time.After(200 * time.Millisecond):
	}
	if !caddyRestartWatcherStarted.Load() {
		t.Fatal("幂等门被重置（第二调用不应改状态）")
	}
}

// 指标总览端点：空采样也必须返回结构化 0 值（前端卡片按字段渲染，缺键会
// 变成 undefined 显示）。
func TestGetMetricsOverview_returnsStructuredZeroValue(t *testing.T) {
	h := NewHandlers(Dependencies{MetricsService: services.NewMetricsService("http://127.0.0.1:1/metrics", 60)})
	recorder := getRoute(t, h, "/metrics/overview", h.GetMetricsOverview)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code int                    `json:"code"`
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Code != 0 {
		t.Fatalf("code=%d", body.Code)
	}
	if len(body.Data) == 0 {
		t.Fatalf("总览数据为空对象（前端卡片字段全 undefined）: %s", recorder.Body.String())
	}
}

// IP2Region 更新状态端点：manager 缺席 500（显式「未初始化」），初始化后
// 200 且 status 字段存在。
func TestGetIP2RegionUpdateStatus_managerLifecycle(t *testing.T) {
	// manager 初始化会写版本行（ensureVersionTableRow）——必须有可用测试库。
	_ = newBackupTestHandlers(t)
	// manager 是进程级单例：用例前后都复位，否则 -shuffle/重复执行时前序
	// 用例留下的 manager 会让「未初始化 → 500」契约整段消失。
	services.ResetIP2RegionUpdateManagerForTest()
	t.Cleanup(services.ResetIP2RegionUpdateManagerForTest)
	h := NewHandlers(Dependencies{})
	if manager := services.GetIP2RegionUpdateManager(); manager != nil {
		t.Fatal("前置态错误：IP2Region 更新 manager 应为未初始化")
	}
	recorder := getRoute(t, h, "/status", h.GetIP2RegionUpdateStatus)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("manager 缺席 status=%d, want 500", recorder.Code)
	}
	services.InitIP2RegionUpdateManager(func() error { return nil })
	recorder = getRoute(t, h, "/status", h.GetIP2RegionUpdateStatus)
	if recorder.Code != http.StatusOK {
		t.Fatalf("初始化后 status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body.Data["status"]; !ok {
		t.Fatalf("状态快照缺 status: %v", body.Data)
	}
}

// failImportTx：导入失败收尾唯一出口——回滚 + 失败审计 + 响应三件事必须
// 一次完成；漏接会在 audit_log 中完全无痕。
func TestFailImportTx_auditsAndResponds(t *testing.T) {
	h := newBackupTestHandlers(t)
	cause := errors.New("事务内写入失败")

	run := func(responsePrefix string, status int) (*httptest.ResponseRecorder, error) {
		gin.SetMode(gin.TestMode)
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/config/import", nil)
		session := &configImportSession{h: h, action: "导入"}
		return recorder, failImportTx(ctx, session, "导入", "导入事务失败", cause, status, responsePrefix)
	}

	// 客户端可修正形态（400）：响应正文即真实原因，不带「已回滚」前缀。
	recorder, err := run("", http.StatusBadRequest)
	if !errors.Is(err, cause) {
		t.Fatalf("返回错误=%v, want 原始 cause", err)
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", recorder.Code)
	}
	var resp models.APIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 400 || resp.Message != cause.Error() {
		t.Fatalf("响应=%+v, want code=400 message=%q", resp, cause.Error())
	}
	if n := countAuditRows(t, "导入失败", "配置备份"); n != 1 {
		t.Fatalf("失败审计=%d, want 1", n)
	}

	// 系统故障形态（500）：前缀 + 「已回滚」+ 原因。
	recorder, _ = run("导入失败", http.StatusInternalServerError)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", recorder.Code)
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Message, "导入失败，已回滚: ") || !strings.Contains(resp.Message, cause.Error()) {
		t.Fatalf("500 响应文案=%q，必须为「<前缀>，已回滚: <原因>」", resp.Message)
	}
	if n := countAuditRows(t, "导入失败", "配置备份"); n != 2 {
		t.Fatalf("第二次失败审计累计=%d, want 2", n)
	}
}

// 24h 分小时统计端点：引擎缺席 → 显式空数组；有引擎 → 24 个墙面小时桶。
// 图表按数组迭代，null 会在前端炸成运行时异常；桶数/升序/零值是数据契约。
func TestGetSystemTaskStats24hSeries_bothBranches(t *testing.T) {
	h := NewHandlers(Dependencies{})
	// 分支一：引擎缺席。全局引擎属包级单例，先显式停止以避免依赖用例顺序。
	services.StopTaskEngine()
	recorder := getRoute(t, h, "/system/tasks/stats-24h-series", h.GetSystemTaskStats24hSeries)
	if recorder.Code != http.StatusOK {
		t.Fatalf("引擎缺席 status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var empty struct {
		Data struct {
			Series []taskengine.TaskHourlyStat `json:"series"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &empty); err != nil {
		t.Fatal(err)
	}
	if empty.Data.Series == nil {
		t.Fatalf("引擎缺席时必须下发空数组（null 会让前端图表迭代失败）: %s", recorder.Body.String())
	}
	if len(empty.Data.Series) != 0 {
		t.Fatalf("引擎缺席 series=%v, want 空", empty.Data.Series)
	}

	// 分支二：有引擎 → 24 桶、时间升序，且已落库的运行进入对应小时桶。
	// 引擎装配本身可能写当日启动行，故不在当前小时断零；改为在窗口内
	// 5 小时前种一组已知计数，按桶键精确断言。
	initTaskEngineForTest(t)
	seededAt := time.Now().Add(-5 * time.Hour)
	seededHour := seededAt.Format("2006-01-02 15") + ":00:00"
	for _, status := range []string{"success", "success", "failed"} {
		if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, status, started_at) VALUES ('stats-series-probe','test',?,?)`, status, seededHour); err != nil {
			t.Fatalf("seed task_runs: %v", err)
		}
	}
	recorder = getRoute(t, h, "/system/tasks/stats-24h-series", h.GetSystemTaskStats24hSeries)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Series []taskengine.TaskHourlyStat `json:"series"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Series) != 24 {
		t.Fatalf("series 桶数=%d, want 24（最近 24 个墙面小时）", len(payload.Data.Series))
	}
	seededSeen := false
	for i, stat := range payload.Data.Series {
		if _, err := time.Parse("2006-01-02 15:04:05", stat.Hour); err != nil {
			t.Fatalf("桶 %d hour=%q 非预期格式: %v", i, stat.Hour, err)
		}
		if i > 0 && stat.Hour <= payload.Data.Series[i-1].Hour {
			t.Fatalf("桶未按小时升序: %q 之后是 %q", payload.Data.Series[i-1].Hour, stat.Hour)
		}
		if stat.Hour == seededHour {
			seededSeen = true
			if stat.Success != 2 || stat.Failed != 1 {
				t.Fatalf("桶 %s 计数=%d/%d, want 2 成功/1 失败", stat.Hour, stat.Success, stat.Failed)
			}
		}
	}
	if !seededSeen {
		t.Fatalf("窗口内缺已种入的小时桶 %s（series=%v）", seededHour, payload.Data.Series)
	}
}

// TCP 规则指标解析：L4 指标只带 upstream 标签，按规则启用的上游地址归集；
// 未列出的上游 / 无 upstream 标签的样本不计入（共享上游合计口径见实现注释）。
func TestParseTCPRuleMetricsFromPrometheus_aggregatesListedUpstreams(t *testing.T) {
	body := strings.Join([]string{
		`# HELP caddy_layer4_proxy_connections_total L4 proxy connections`,
		`caddy_layer4_proxy_connections_total{upstream="10.0.0.1:9001"} 5`,
		`caddy_layer4_proxy_active_connections{upstream="10.0.0.1:9001"} 2`,
		`caddy_layer4_proxy_connections_total{upstream="10.0.0.2:9002"} 7`,
		`caddy_layer4_proxy_connections_total{upstream="10.0.0.9:9009"} 99`,
		`caddy_layer4_proxy_connections_total 42`,
	}, "\n")
	upstreams := []models.Upstream{
		{Host: "10.0.0.1", Port: 9001, Enabled: true},
		{Host: "10.0.0.2", Port: 9002, Enabled: true},
		{Host: "10.0.0.3", Port: 9003, Enabled: false},
	}
	metrics, err := parseTCPRuleMetricsFromPrometheus(body, upstreams)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]int64{
		"requests_total":     12, // 5+7；0.0.0.9 未在上游表内、禁用上游不计
		"requests_in_flight": 2,
		"status_2xx":         0,
		"status_3xx":         0,
		"status_4xx":         0,
		"status_5xx":         0,
		"bytes_in":           0,
		"bytes_out":          0,
	}
	if len(metrics) != len(want) {
		t.Fatalf("指标键集=%v, want %d 个统一键", metrics, len(want))
	}
	for key, expected := range want {
		if got, ok := metrics[key].(int64); !ok || got != expected {
			t.Fatalf("%s=%v, want %d（metrics=%v）", key, metrics[key], expected, metrics)
		}
	}
	if _, ok := metrics["blocked"]; ok {
		t.Fatal("解析层不得写 blocked（TCP 端点在 handler 侧恒置 0）")
	}

	// 空上游表：八个键齐全且全零，不得返回 nil（调用方直接写响应）。
	zeroed, err := parseTCPRuleMetricsFromPrometheus(`caddy_layer4_proxy_connections_total{upstream="10.0.0.1:9001"} 3`, nil)
	if err != nil {
		t.Fatalf("空上游表 parse: %v", err)
	}
	if len(zeroed) != len(want) {
		t.Fatalf("空上游表指标=%v, want 统一键集", zeroed)
	}
	for key := range want {
		if got, ok := zeroed[key].(int64); !ok || got != 0 {
			t.Fatalf("空上游表 %s=%v, want 0", key, zeroed[key])
		}
	}

	// 畸形形态：样本值非数字必须报错（带行号），全无效正文同样报错。
	if _, err := parseTCPRuleMetricsFromPrometheus("caddy_layer4_proxy_connections_total{upstream=\"10.0.0.1:9001\"} not-a-number", upstreams); err == nil || !strings.Contains(err.Error(), "第 1 行") {
		t.Fatalf("畸形样本值 err=%v, want 带行号的解析错误", err)
	}
	for _, emptyBody := range []string{"", "# 只有注释\n", "caddy_layer4_proxy_connections_total{upstream=\"x\"} NaN"} {
		if _, err := parseTCPRuleMetricsFromPrometheus(emptyBody, upstreams); err == nil || !strings.Contains(err.Error(), "不包含有效样本") {
			t.Fatalf("正文 %q err=%v, want 无有效样本错误", emptyBody, err)
		}
	}
}

// 实时流量端点：500 分支固定信封文案（底层路径/错误不回显），成功分支恒带
// bytes_in/bytes_out——仪表盘直接读这两个键，字段名或信封结构漂移会让首屏
// 静默空白。同名采样 helper 已有多条单测，端点装配此前零覆盖。
func TestGetRealtimeTraffic_envelopeOnFailureAndSuccess(t *testing.T) {
	withIsolatedGlobal(t)
	h := NewHandlers(Dependencies{})
	disableNetSampleWindowForTest(t)
	original := systemMetricsReadFile
	t.Cleanup(func() { systemMetricsReadFile = original })
	lastNetStats.mu.Lock()
	lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.iface = 0, 0, ""
	lastNetStats.time = time.Time{}
	lastNetStats.hasValue = false
	lastNetStats.mu.Unlock()

	// Given 网卡计数器读取失败。Then 500 信封 + 固定文案，且不回显底层错误。
	systemMetricsReadFile = func(path string) ([]byte, error) {
		if path == "/proc/net/dev" {
			return nil, errors.New("read /proc/net/dev: permission denied")
		}
		return original(path)
	}
	recorder := getRoute(t, h, "/api/v1/metrics/realtime", h.GetRealtimeTraffic)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	var failure models.APIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &failure); err != nil {
		t.Fatalf("decode failure envelope: %v", err)
	}
	if failure.Code != http.StatusInternalServerError || failure.Message != "读取实时流量失败" {
		t.Fatalf("信封=%+v, want code=500 message=读取实时流量失败", failure)
	}
	if strings.Contains(recorder.Body.String(), "permission denied") {
		t.Fatalf("底层错误回显给客户端: %s", recorder.Body.String())
	}

	// When 采样成功。Then code=0 且两个速率字段恒在（不依赖非零值）。
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/net/route":
			return []byte("Iface Destination Gateway Flags\neth0 00000000 0100000A 0003\n"), nil
		case "/proc/net/dev":
			return []byte("Inter-| Receive | Transmit\neth0: 4096 0 0 0 0 0 0 0 2048 0 0 0 0 0 0 0\n"), nil
		}
		return original(path)
	}
	recorder = getRoute(t, h, "/api/v1/metrics/realtime", h.GetRealtimeTraffic)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var success struct {
		Code int                    `json:"code"`
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &success); err != nil {
		t.Fatalf("decode success envelope: %v", err)
	}
	if success.Code != 0 || success.Data == nil {
		t.Fatalf("信封=%+v, want code=0 且 data 非空", success)
	}
	for _, key := range []string{"bytes_in", "bytes_out"} {
		if _, ok := success.Data[key]; !ok {
			t.Fatalf("data 缺少 %q（仪表盘直接读该键）: %v", key, success.Data)
		}
	}
}

// 连接统计端点：与实时流量同族信封契约（底层 netstat 错误只进运行日志），
// 成功分支的十个连接状态键恒在。
func TestGetConnectionStats_envelopeOnFailureAndSuccess(t *testing.T) {
	withIsolatedGlobal(t)
	h := NewHandlers(Dependencies{})
	resetConnectionStatsCacheForTest(t)
	original := netstatCommand
	t.Cleanup(func() { netstatCommand = original })

	// Given netstat 执行失败。Then 500 + 固定文案。
	netstatCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "false")
	}
	recorder := getRoute(t, h, "/api/v1/metrics/connections", h.GetConnectionStats)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	var failure models.APIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &failure); err != nil {
		t.Fatalf("decode failure envelope: %v", err)
	}
	if failure.Code != http.StatusInternalServerError || failure.Message != "读取连接统计失败" {
		t.Fatalf("信封=%+v, want code=500 message=读取连接统计失败", failure)
	}

	// When 解析成功。Then code=0 且状态键齐全（缺键会让面板按零值渲染假空闲）。
	resetConnectionStatsCacheForTest(t)
	sample := strings.Join([]string{
		"Proto Recv-Q Send-Q Local Address Foreign Address (state)",
		"tcp4 0 0 127.0.0.1.8080 127.0.0.1.5000 ESTABLISHED",
		"tcp4 0 0 127.0.0.1.8080 127.0.0.1.5001 ESTABLISHED",
		"tcp4 0 0 127.0.0.1.8080 127.0.0.1.5002 TIME_WAIT",
		"tcp4 0 0 *.8080 *.* LISTEN",
	}, "\n")
	netstatCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "printf", "%s", sample)
	}
	recorder = getRoute(t, h, "/api/v1/metrics/connections", h.GetConnectionStats)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var success struct {
		Code int                    `json:"code"`
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &success); err != nil {
		t.Fatalf("decode success envelope: %v", err)
	}
	if success.Code != 0 || success.Data == nil {
		t.Fatalf("信封=%+v, want code=0 且 data 非空", success)
	}
	for _, key := range []string{"established", "time_wait", "syn_sent", "syn_recv", "fin_wait1", "fin_wait2", "close_wait", "last_ack", "listening", "closing", "total"} {
		if _, ok := success.Data[key]; !ok {
			t.Fatalf("data 缺少 %q: %v", key, success.Data)
		}
	}
	if got := success.Data["established"]; got != float64(2) {
		t.Fatalf("established=%v, want 2（ESTABLISHED 行计数）", got)
	}
	if got := success.Data["listening"]; got != float64(1) {
		t.Fatalf("listening=%v, want 1", got)
	}
}

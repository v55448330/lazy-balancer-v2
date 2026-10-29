package handlers

// 任务监控 handlers 测试（v2.3.4）：聚合形状、触发映射、取消语义、暂停开关、
// 主节点门。直接 handler 调用（与既有测试同模式——鉴权由路由组中间件承担，
// 此处测 handler 内的门与映射）。

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

type syncTaskMonitorLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (b *syncTaskMonitorLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncTaskMonitorLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func (b *syncTaskMonitorLog) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.b.Reset()
}

func initTaskEngineForTest(t *testing.T) {
	t.Helper()
	// 恒重建引擎实例：复用前一用例留下的实例会让注册表、cert-waiting-ca 的
	// loopEnabled、task_loop_prefs 内存态与任务日志目录指针（前用例的
	// t.TempDir()，已随清理删除 → 写日志静默熔断）跨用例延续，而 db.DB 已被
	// newBackupTestHandlers 换成新临时库——顺序依赖会掩盖真实回归。
	// 库不动（调用方可能已播种）：仅在无库时自建，收尾仍走句柄单源复位。
	if services.TaskEngine() != nil {
		services.StopTaskEngine()
	}
	if db.DB == nil {
		oldDB, oldM, oldA, oldCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
		if err := db.Initialize(t.TempDir()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = db.Close()
			db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA
			db.SetDB(oldCurrent)
		})
	}
	t.Cleanup(services.StopTaskEngine)
	services.InitTaskEngine("", t.TempDir()+"/app.log")
}

func taskMonitorRouter() (*gin.Engine, *Handlers) {
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	r := gin.New()
	r.GET("/system/tasks", h.ListSystemTasks)
	r.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
	r.POST("/system/tasks/:id/toggle", h.ToggleSystemTask)
	r.POST("/system/tasks/:id/cancel", h.CancelSystemTask)
	return r, h
}

// 历史端点与 trigger/toggle 同口径做注册存在性门；
// 已注册但零历史的任务仍返回 200 + 空数组。
func TestGetSystemTaskHistory_checksTaskExistence(t *testing.T) {
	newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	if err := te.Register(taskengine.Descriptor{
		ID: "history-empty", Family: "test", Name: "空历史任务", Kind: taskengine.KindOneshot, RunsOn: taskengine.RoleAny,
		Run: func(taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	h := &Handlers{}
	router.GET("/system/tasks/:id/history", h.GetSystemTaskHistory)

	t.Run("unknown", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/system/tasks/not-a-task/history", nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("不存在任务 status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
		}
	})
	t.Run("registered empty", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/system/tasks/history-empty/history", nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"runs":[]`) {
			t.Fatalf("已注册空历史 status=%d body=%s, want 200 runs=[]", recorder.Code, recorder.Body.String())
		}
	})
}

// Given 空库（迁移种子三威胁源）。
// Then 聚合返回全部任务族，字段形状完整，threat 含三源摘要。
func TestListSystemTasks_allFamiliesPresent(t *testing.T) {
	newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	r, _ := taskMonitorRouter()
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/system/tasks", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String()[:min(300, len(resp.Body.String()))])
	}
	var payload struct {
		Data struct {
			Tasks []struct {
				ID             string `json:"id"`
				Name           string `json:"name"`
				Category       string `json:"category"`
				Kind           string `json:"kind"`
				Status         string `json:"status"`
				BusinessDriven bool   `json:"business_driven"`
			} `json:"tasks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	// 任务视图只承载 loop_on，不暴露诊断字段 enabled。
	if strings.Contains(resp.Body.String(), `"enabled"`) {
		t.Error("任务列表 JSON 不应含 enabled 键（调度语义只由 loop_on 表达）")
	}
	got := map[string]string{}
	for _, tk := range payload.Data.Tasks {
		got[tk.ID] = tk.Category
	}
	// 期望集合独立冻结（族身份 + 分类）：从 DescribeAll 派生会与响应同源，
	// 注册表误删一族、族 ID 改名或分类漂移时两侧同步变化、门禁零告警。
	// 新增族不在本表 → 由下方「响应 ⊆ 注册表」反向检查兜住（新增不红）；
	// cert-job: 是 task_runs 派生的动态行，不属于注册表。
	wantCategories := map[string]string{
		"threat":                    "安全防护",
		"crs":                       "安全防护",
		"ip2region":                 "安全防护",
		"crawlerbot-update":         "安全防护",
		"autoban":                   "安全防护",
		"cert-renewal-scan":         "证书",
		"cert-reconcile":            "证书",
		"cert-manual-poll":          "证书",
		"cert-waiting-ca":           "证书",
		"cert-issuance":             "证书",
		"auto-backup":               "备份",
		"cluster-sync":              "集群",
		"config-watchdog":           "系统",
		"log-cleanup":               "系统",
		"audit-retention":           "系统",
		"security-events-retention": "系统",
		"metrics-orphan-cleanup":    "系统",
		"security-events-ingestion": "系统",
		"startup:config-load":       "系统",
	}
	for id, wantCategory := range wantCategories {
		category, ok := got[id]
		if !ok {
			t.Fatalf("任务族 %s 缺失; got=%v", id, got)
		}
		if category != wantCategory {
			t.Fatalf("任务族 %s 分类=%q, want %q", id, category, wantCategory)
		}
	}
	metas := services.TaskEngine().DescribeAll()
	if len(metas) == 0 {
		t.Fatal("引擎注册表为空——任务族对账失效")
	}
	registered := make(map[string]struct{}, len(metas))
	for _, meta := range metas {
		registered[meta.ID] = struct{}{}
	}
	for id := range got {
		if strings.HasPrefix(id, "cert-job:") {
			continue
		}
		if _, ok := registered[id]; !ok {
			t.Fatalf("响应含引擎未注册的任务 %q（视图与注册表分叉）; got=%v", id, got)
		}
	}
	for _, tk := range payload.Data.Tasks {
		if tk.ID == "threat" && !tk.BusinessDriven {
			t.Error("threat 应标记 business_driven=true")
		}
		if tk.ID == "config-watchdog" && tk.BusinessDriven {
			t.Error("config-watchdog 不应标记 business_driven")
		}
	}
}

func TestInitTaskEngineForTest_replacesStoppedEngine(t *testing.T) {
	// Given：全局引擎已被直接 Stop（模拟跨测试 stopped 残留）。
	initTaskEngineForTest(t)
	services.TaskEngine().Stop()

	// When：再次经测试装配初始化。
	initTaskEngineForTest(t)

	// Then：必须替换为新实例，后续 Trigger 不得返回 ErrEngineStopped。
	if services.TaskEngine().IsStopped() {
		t.Fatal("initTaskEngineForTest 复用了 stopped 引擎")
	}
	if err := services.TaskEngine().Trigger("log-cleanup", "manual", ""); err != nil {
		t.Fatalf("重建后 Trigger 仍失败: %v", err)
	}
}

func TestTaskWriteHandlers_slaveRejectedConsistently(t *testing.T) {
	// Given：从节点 DB 实态 + RoleAny 任务（排除 RunsOn 差异）。
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
	router.POST("/system/tasks/:id/toggle", h.ToggleSystemTask)
	router.POST("/system/tasks/:id/cancel", h.CancelSystemTask)
	router.POST("/system/tasks/:id/control", h.ControlSystemTask)
	for _, tc := range []struct{ name, path, body string }{
		{name: "trigger", path: "/system/tasks/log-cleanup/trigger", body: ""},
		{name: "toggle", path: "/system/tasks/log-cleanup/toggle", body: `{"enabled":true}`},
		{name: "cancel", path: "/system/tasks/cluster-sync/cancel", body: ""},
		{name: "control", path: "/system/tasks/cluster-sync/control", body: `{"action":"restart"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// When/Then：四个写端点都必须同步返回 403，不得在引擎异步错误前假成功。
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			if response.Code != http.StatusForbidden {
				t.Fatalf("从节点写任务 status=%d body=%s，want 403", response.Code, response.Body.String())
			}
		})
	}
}

// 不可触发族 → 400；从节点 → 403。
func TestTriggerSystemTask_gatesAndMapping(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	// 类型派生（2026-10-11 用户裁定，取代 ManualRun 白名单）：config-watchdog
	//（循环）类型派生可触发 → 200；常驻族（cluster-sync daemon）恒不可触发 →
	// 400「不支持手动触发（常驻族启停即可/镜像族）」。
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/config-watchdog/trigger", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("config-watchdog（循环，类型派生可触发）触发应 200, got %d: %s", resp.Code, resp.Body.String())
	}
	respDaemon := httptest.NewRecorder()
	r.ServeHTTP(respDaemon, httptest.NewRequest(http.MethodPost, "/system/tasks/cluster-sync/trigger", nil))
	if respDaemon.Code != http.StatusBadRequest {
		t.Fatalf("cluster-sync（常驻族）触发应 400, got %d", respDaemon.Code)
	}
	if !strings.Contains(respDaemon.Body.String(), "不支持手动触发（常驻族启停即可/镜像族）") {
		t.Fatalf("应命中 !CanTrigger 分支文案（常驻族恒不可触发）: %s", respDaemon.Body.String())
	}

	// 从节点 → 403
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, httptest.NewRequest(http.MethodPost, "/system/tasks/crs/trigger", nil))
	if resp2.Code != http.StatusForbidden {
		t.Fatalf("从节点触发应 403, got %d", resp2.Code)
	}
}

// toggle：业务驱动任务只读——threat 调度开关由业务页自动更新控制，
// 任务监控不得反写业务配置或另开第二入口。
func TestToggleSystemTask_threatBusinessDrivenReadOnly(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1, threat_auto_update=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	services.InitThreatUpdateManager()
	te := services.TaskEngine()
	r, _ := taskMonitorRouter()
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/system/tasks/threat/toggle", strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("业务驱动任务 toggle 应 400 read-only, got %d body=%s", resp.Code, resp.Body.String())
	}
	if !te.IsRunning("threat") {
		t.Fatal("只读拒绝不得改变既有调度运行态")
	}
	if !services.ThreatAutoUpdateEnabled() {
		t.Fatal("只读拒绝不得反写业务自动更新")
	}
}

// cancel：未运行 → 409；不可取消族 → 409（引擎 Cancel 返 false——handler
// 不再有 400 分支，回退 switch 已删，无引擎时统一 503）。
func TestCancelSystemTask_semantics(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	// auto-backup Cancelable=false → 引擎 Cancel 返 false → 409
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/auto-backup/cancel", nil))
	if resp.Code != http.StatusConflict {
		t.Fatalf("auto-backup 取消（不可取消族）应 409, got %d", resp.Code)
	}

	// threat 未运行 → 409
	services.InitThreatUpdateManager()
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, httptest.NewRequest(http.MethodPost, "/system/tasks/threat/cancel", nil))
	if resp2.Code != http.StatusConflict {
		t.Fatalf("未运行取消应 409, got %d body=%s", resp2.Code, resp2.Body.String())
	}
}

// 导入窗口内取消必须 409 fast-fail，与 toggle/control 同门：导入/还原期间
// 协调器做的是 PauseScheduling+CancelInFlightRuns 的系统性排空，其语义是
// 「cancel(nil) 不消费已到期槽、恢复后补跑」；此时用户取消会走
// consumeCancelledSlotLocked 消费掉该自动槽，与排空语义相反——导入完成后
// 该族自动周期不会补跑。
func TestCancelSystemTask_blockedDuringImportWindow(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	closeWindow := beginImportWindowForTest(t)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/threat/cancel", nil))
	if resp.Code != http.StatusConflict {
		t.Fatalf("导入窗口内取消 status=%d body=%s, want 409", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "配置导入进行中") {
		t.Fatalf("body=%s, want 含导入窗口文案", resp.Body.String())
	}
	// 窗口关闭后门必须放行（同一请求落到「未运行 → 409」而非导入文案）
	closeWindow()
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, httptest.NewRequest(http.MethodPost, "/system/tasks/threat/cancel", nil))
	if resp2.Code != http.StatusConflict || strings.Contains(resp2.Body.String(), "配置导入进行中") {
		t.Fatalf("窗口关闭后 status=%d body=%s, want 非导入门 409", resp2.Code, resp2.Body.String())
	}
}

func TestToggleSystemTask_businessDrivenTasksReadOnly(t *testing.T) {
	cases := []struct {
		id    string
		table string
		col   string
	}{
		{"threat", "global_config", "threat_auto_update"},
		{"crs", "security_crs_version", "auto_update"},
		{"ip2region", "security_ip2region_version", "auto_update"},
		{"crawlerbot-update", "global_config", "crawler_auto_update"},
		{"auto-backup", "global_config", "auto_backup_enabled"},
		{"autoban", "global_config", "autoban_enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			initTaskEngineForTest(t)
			newBackupTestHandlers(t)
			r, _ := taskMonitorRouter()
			te := services.TaskEngine()
			te.StopLoop(tc.id)
			if tc.table != "global_config" {
				if _, err := db.DB.Exec(`INSERT OR IGNORE INTO ` + tc.table + ` (id,version,auto_update) VALUES (1,'test',0)`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.DB.Exec(`UPDATE ` + tc.table + ` SET ` + tc.col + `=0`); err != nil {
				t.Fatal(err)
			}

			// When：试图从任务监控改变业务驱动任务调度
			resp := httptest.NewRecorder()
			r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/"+tc.id+"/toggle", strings.NewReader(`{"enabled":true}`)))

			// Then：只读拒绝，业务字段与 loop_on 均不得被反写
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400 read-only", resp.Code, resp.Body.String())
			}
			var enabled int
			if err := db.DB.QueryRow(`SELECT ` + tc.col + ` FROM ` + tc.table).Scan(&enabled); err != nil {
				t.Fatal(err)
			}
			m, ok := te.Lookup(tc.id)
			if !ok {
				t.Fatalf("任务 %s 未注册", tc.id)
			}
			if enabled != 0 || m.LoopOn {
				t.Fatalf("只读语义被破坏: business=%d loop_on=%v", enabled, m.LoopOn)
			}
		})
	}
}

// 四个任务写端点的状态码统一——引擎未初始化 503、任务不存在 404
// （语义拒绝仍 400，见各端点既有用例）。
func TestTaskWriteHandlers_unifiedStatusCodes(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
	router.POST("/system/tasks/:id/toggle", h.ToggleSystemTask)
	router.POST("/system/tasks/:id/cancel", h.CancelSystemTask)
	router.POST("/system/tasks/:id/control", h.ControlSystemTask)

	writes := []struct{ name, path, body string }{
		{name: "trigger", path: "/system/tasks/no-such-task/trigger", body: ""},
		{name: "toggle", path: "/system/tasks/no-such-task/toggle", body: `{"enabled":true}`},
		{name: "cancel", path: "/system/tasks/no-such-task/cancel", body: ""},
		{name: "control", path: "/system/tasks/no-such-task/control", body: `{"action":"restart"}`},
	}

	// Given 引擎已初始化：未知任务 → 404
	for _, tc := range writes {
		t.Run("404/"+tc.name, func(t *testing.T) {
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			if resp.Code != http.StatusNotFound {
				t.Fatalf("未知任务 status=%d body=%s, want 404", resp.Code, resp.Body.String())
			}
		})
	}

	// Given 引擎未初始化：四个端点 → 503（统一「任务引擎未初始化」语义）
	services.StopTaskEngine()
	for _, tc := range writes {
		t.Run("503/"+tc.name, func(t *testing.T) {
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			if resp.Code != http.StatusServiceUnavailable {
				t.Fatalf("引擎未初始化 status=%d body=%s, want 503", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestSystemTaskLogPath_certJobAndFallbackShapes(t *testing.T) {
	// Given 普通任务、有效/空 rule_id 的 cert-job，以及缺失与畸形 job id。
	newBackupTestHandlers(t)
	var validJobID, emptyRuleJobID int
	if err := db.DB.QueryRow(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_path','path.example','queued') RETURNING id`).Scan(&validJobID); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('','empty.example','queued') RETURNING id`).Scan(&emptyRuleJobID); err != nil {
		t.Fatal(err)
	}

	// When/Then 单条入口保持既有路径语义，批量解析重构不得改变这些形状。
	if got, err := systemTaskLogPath("crs"); err != nil || got != taskengine.TaskLogPath("crs") {
		t.Fatalf("ordinary task path=%q err=%v, want %q", got, err, taskengine.TaskLogPath("crs"))
	}
	if got, err := systemTaskLogPath(fmt.Sprintf("cert-job:%d", validJobID)); err != nil || got != services.CertJobLogPath("lb_path") {
		t.Fatalf("cert job path=%q err=%v, want %q", got, err, services.CertJobLogPath("lb_path"))
	}
	for _, id := range []string{fmt.Sprintf("cert-job:%d", emptyRuleJobID), "cert-job:999999", "cert-job:not-a-number"} {
		if got, err := systemTaskLogPath(id); err != nil || got != "" {
			t.Fatalf("%s path=%q err=%v, want empty path", id, got, err)
		}
	}

	oldDB := db.DB
	db.DB = nil
	db.SetDB(nil)
	t.Cleanup(func() { db.DB = oldDB; db.SetDB(oldDB) })
	if got, err := systemTaskLogPath(fmt.Sprintf("cert-job:%d", validJobID)); err != nil || got != "" {
		t.Fatalf("nil DB path=%q err=%v, want empty path", got, err)
	}
}

// Given cert_jobs 不可读（路径解析失败）与日志目录不可搜索（stat 失败）两种内部故障。
// When 请求任务日志端点（业务读面：全部登录用户可读）。
// Then 500 + 固定文案；响应体不得回显驱动/schema/路径细节，原始错误只进应用日志。
func TestGetSystemTaskLogs_hidesInternalErrorDetails(t *testing.T) {
	applogs := &syncTaskMonitorLog{}
	oldWriter := log.Writer()
	log.SetOutput(applogs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	newBackupTestHandlers(t)
	router := gin.New()
	h := &Handlers{}
	router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)
	request := func(taskID string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/"+taskID+"/logs", nil))
		return response
	}

	// ① 路径解析失败：cert_jobs 查询错误（驱动原文含 schema 信息）。
	if _, err := db.DB.Exec(`ALTER TABLE cert_jobs RENAME TO cert_jobs_bak`); err != nil {
		t.Fatalf("rename cert_jobs: %v", err)
	}
	response := request("cert-job:1")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("路径解析失败 status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "任务日志路径解析失败") {
		t.Fatalf("响应文案=%s, want 固定文案「任务日志路径解析失败」", body)
	}
	for _, leaked := range []string{"no such table", "SQLITE", "cert_jobs", ".db"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("响应体回显内部细节 %q: %s", leaked, body)
		}
	}
	if !strings.Contains(applogs.String(), "任务日志路径解析失败（cert-job:1）") {
		t.Fatalf("原始错误未进应用日志: %s", applogs.String())
	}
	if _, err := db.DB.Exec(`ALTER TABLE cert_jobs_bak RENAME TO cert_jobs`); err != nil {
		t.Fatalf("restore cert_jobs: %v", err)
	}

	// ② 读取失败：日志目录不可搜索（stat 报权限错误）。
	// root 不受文件权限位约束（容器 CI 常见）：chmod 0 后 stat 仍成功 → 用例
	// 必红，且会被误读为产品回归。①的路径解析断言已在上面执行完。
	if os.Geteuid() == 0 {
		t.Skip("root 不受文件权限限制，无法构造 stat 失败")
	}
	dir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatalf("chmod log dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })
	// 权限位之外还可能被挂载选项/ACL 放宽（只读挂载、容器内 uid 映射）：
	// 以「目录内路径 stat 是否真的失败」为夹具自检，不成立就跳过而不是误红。
	if _, err := os.Stat(filepath.Join(dir, "probe")); err == nil {
		t.Skip("当前环境不受目录权限位约束，stat 失败语义无法构造")
	}
	applogs.Reset()
	response = request("crs")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("读取失败 status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body = response.Body.String()
	if !strings.Contains(body, "任务日志读取失败") {
		t.Fatalf("响应文案=%s, want 固定文案「任务日志读取失败」", body)
	}
	for _, leaked := range []string{"permission denied", "no such file", dir} {
		if strings.Contains(body, leaked) {
			t.Fatalf("响应体回显内部细节 %q: %s", leaked, body)
		}
	}
	if !strings.Contains(applogs.String(), "任务日志读取失败（crs, stat）") {
		t.Fatalf("原始错误未进应用日志: %s", applogs.String())
	}
}

// 无写端 FIFO 不得把任务日志请求永久阻塞在 open(2)；与运行日志端点
// 同口径，必须非阻塞打开并在已打开 fd 上拒绝非常规文件。
func TestGetSystemTaskLogs_fifoDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	if err := syscall.Mkfifo(filepath.Join(dir, "crs.log"), 0o600); err != nil {
		t.Skipf("mkfifo 不可用: %v", err)
	}
	h := &Handlers{}
	router := gin.New()
	router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/system/tasks/crs/logs", nil))
		done <- rec
	}()
	select {
	case rec := <-done:
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "任务日志读取失败") {
			t.Fatalf("status=%d body=%s, want 500 固定文案", rec.Code, rec.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("任务日志 FIFO 打开被阻塞")
	}
}

// 任务日志只读尾窗；偏移起点的残段（含整窗无换行的
// 巨型行）统一经 tailLogWindow 丢弃，小文件保持原样。
func TestGetSystemTaskLogs_boundedTailDropsPartialFirstLine(t *testing.T) {
	dir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	h := &Handlers{}
	router := gin.New()
	router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)

	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "small unchanged", content: "first\nsecond\n", want: "first\nsecond\n"},
		{name: "partial line dropped", content: strings.Repeat("x", 256<<10) + "\ncomplete\n", want: "complete\n"},
		{name: "giant line window empty", content: strings.Repeat("x", (256<<10)+32), want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(taskengine.TaskLogPath("bounded"), []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/bounded/logs", nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var payload struct {
				Data map[string]string `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if got := payload.Data["content"]; got != tc.want {
				t.Fatalf("content length=%d value=%q, want length=%d %q", len(got), got, len(tc.want), tc.want)
			}
		})
	}
}

func TestGetSystemTaskLogs_rotationBudgetDropsPartialOldestLine(t *testing.T) {
	dir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	path := taskengine.TaskLogPath("rotation-partial")
	rotationLine := "轮转-" + strings.Repeat("r", 296) + "\n"
	activeLine := "active-line-123456789\n"
	if err := os.WriteFile(path+".1", []byte(strings.Repeat(rotationLine, 1000)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(activeLine, 9001)), 0o644); err != nil {
		t.Fatal(err)
	}

	h := &Handlers{}
	router := gin.New()
	router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/rotation-partial/logs", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	content := payload.Data["content"]
	if !utf8.ValidString(content) || strings.ContainsRune(content, utf8.RuneError) {
		t.Fatal("响应首行切断 UTF-8 字符")
	}
	if !strings.HasPrefix(content, rotationLine) {
		t.Fatalf("响应首行不是完整日志行: prefix=%q", content[:min(len(content), 80)])
	}
	if !strings.Contains(content, activeLine) {
		t.Fatal("响应丢失活动日志尾窗")
	}
}

func TestGetSystemTaskLogs_rotationBudgetUsesConcatenatedTail(t *testing.T) {
	const tail = 256 << 10
	fetchContent := func(t *testing.T, h *Handlers, taskID string) string {
		t.Helper()
		router := gin.New()
		router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/"+taskID+"/logs", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		var payload struct {
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		return payload.Data["content"]
	}

	t.Run("plain task rotation is included in 256KiB budget", func(t *testing.T) {
		dir := t.TempDir()
		oldLogDir := taskengine.LogDir()
		taskengine.SetLogDir(dir)
		t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
		path := taskengine.TaskLogPath("budget")
		rotation := strings.Repeat("old-line-0123456789\n", 200)
		active := strings.Repeat("active-line-123456789\n", 12000) + "ACTIVE-END\n"
		if err := os.WriteFile(path+".1", []byte(rotation), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(active), 0o644); err != nil {
			t.Fatal(err)
		}
		content := fetchContent(t, &Handlers{}, "budget")
		if len(content) > tail {
			t.Fatalf("content=%d bytes, want ≤%d", len(content), tail)
		}
		if !strings.Contains(content, "ACTIVE-END") || strings.Contains(content, "old-line-") {
			t.Fatalf("want latest active tail only; len=%d", len(content))
		}
	})

	t.Run("cert-job five rotations share the same budget", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		dir := t.TempDir()
		oldLogDir := taskengine.LogDir()
		taskengine.SetLogDir(dir)
		t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
		var jobID int
		if err := db.DB.QueryRow(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_budget','budget.example','queued') RETURNING id`).Scan(&jobID); err != nil {
			t.Fatal(err)
		}
		path := services.CertJobLogPath("lb_budget")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		rotation := func(n int) string {
			return fmt.Sprintf("FILE%d-FIRST\n", n) + strings.Repeat(fmt.Sprintf("file%d-line-%s\n", n, strings.Repeat("x", 4800)), 20)
		}
		for i := 1; i <= 5; i++ {
			if err := os.WriteFile(fmt.Sprintf("%s.%d", path, i), []byte(rotation(i)), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		active := "ACTIVE-FIRST\n" + strings.Repeat("active-line-"+strings.Repeat("y", 4800)+"\n", 20) + "ACTIVE-END\n"
		if err := os.WriteFile(path, []byte(active), 0o644); err != nil {
			t.Fatal(err)
		}
		content := fetchContent(t, h, fmt.Sprintf("cert-job:%d", jobID))
		if len(content) > tail {
			t.Fatalf("cert-job content=%d bytes, want ≤%d", len(content), tail)
		}
		if !strings.Contains(content, "ACTIVE-END") || strings.Contains(content, "FILE5-FIRST") || strings.Contains(content, "FILE4-FIRST") {
			t.Fatalf("want newest tail across five rotations; len=%d", len(content))
		}
	})

	t.Run("short rotations preserved verbatim", func(t *testing.T) {
		dir := t.TempDir()
		oldLogDir := taskengine.LogDir()
		taskengine.SetLogDir(dir)
		t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
		path := taskengine.TaskLogPath("short")
		rotation := strings.Repeat("short-old-line\n", 200)
		active := "short-active-first\nshort-active-last\n"
		if err := os.WriteFile(path+".1", []byte(rotation), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(active), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, want := fetchContent(t, &Handlers{}, "short"), rotation+active; got != want {
			t.Fatalf("short content length=%d, want %d", len(got), len(want))
		}
	})
}

// 普通任务写侧只保留 1 份轮转副本，读侧不得按证书任务
// 扫描 .1～.5；仅最近 .1 前置到活动日志，避免读取不存在/越权保留代。
func TestGetSystemTaskLogs_includesOnlyLatestOrdinaryRotation(t *testing.T) {
	dir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	path := taskengine.TaskLogPath("rotated")
	if err := os.WriteFile(path, []byte("current\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", path, i), []byte(fmt.Sprintf("archive-%d\n", i)), 0644); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handlers{}
	router := gin.New()
	router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/rotated/logs", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	want := "archive-1\ncurrent\n"
	if got := payload.Data["content"]; got != want {
		t.Fatalf("content=%q, want %q", got, want)
	}
}

// 同一响应的活动文件+轮转副本合计仍受 256KB 文档容量约束。
func TestGetSystemTaskLogs_rotationContentStaysWithinTailBudget(t *testing.T) {
	dir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	path := taskengine.TaskLogPath("budgeted")
	line := strings.Repeat("a", 1023) + "\n"
	lastLine := strings.Repeat("b", 1024-len("active-tail\n")) + "active-tail\n"
	active := strings.Repeat(line, 255) + lastLine // 恰好 256KB，且均为完整行
	if len(active) != 256<<10 {
		t.Fatalf("fixture size=%d", len(active))
	}
	if err := os.WriteFile(path, []byte(active), 0644); err != nil {
		t.Fatal(err)
	}
	for i, content := range []string{"", "archive-one\n", "archive-two\n"} {
		if i == 0 {
			continue
		}
		if err := os.WriteFile(fmt.Sprintf("%s.%d", path, i), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handlers{}
	router := gin.New()
	router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/budgeted/logs", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	content := payload.Data["content"]
	if len(content) > 256<<10 {
		t.Fatalf("活动+轮转内容=%d bytes, want <= %d", len(content), 256<<10)
	}
	if !strings.Contains(content, "active-tail\n") {
		t.Fatal("容量截断不得丢失活动文件最新完整行")
	}
}

// 并发双击下「触发」审计行数必须等于实际 manual task_runs 行数——
// 审计只在 Trigger 成功后记录，CAS 落败者不得留下孤儿「触发」行。
func TestTriggerSystemTask_triggerAuditMatchesManualRuns(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	te := services.TaskEngine()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	if err := te.Register(taskengine.Descriptor{
		ID: "audit-race-probe", Family: "t", Name: "审计竞态探针", Kind: taskengine.KindOneshot,
		Run: func(taskengine.RunContext) error {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	r, _ := taskMonitorRouter()

	before := countTriggerAudit(t)
	rec1, rec2 := httptest.NewRecorder(), httptest.NewRecorder()
	done := make(chan struct{}, 2)
	go func() {
		r.ServeHTTP(rec1, httptest.NewRequest(http.MethodPost, "/system/tasks/audit-race-probe/trigger", nil))
		done <- struct{}{}
	}()
	go func() {
		r.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/system/tasks/audit-race-probe/trigger", nil))
		done <- struct{}{}
	}()
	for i := range 2 {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("第 %d 个触发请求未返回", i+1)
		}
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("manual Run 未进入")
	}
	close(release)

	var manualRuns int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id='audit-race-probe' AND trigger='manual'`).Scan(&manualRuns); err == nil && manualRuns > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if manualRuns != 1 {
		t.Fatalf("并发双击实际 manual task_runs=%d, want 1", manualRuns)
	}
	// 不再固定等待 200ms。
	got := 0
	deadline = time.Now().Add(2 * time.Second)
	for {
		got = countTriggerAudit(t) - before
		if got == 1 && manualRuns == 1 {
			break
		}
		if got > manualRuns || time.Now().After(deadline) {
			t.Fatalf("「触发」审计=%d 与实际 manual task_runs=%d 不一致（孤儿/缺失审计）", got, manualRuns)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Given waiting_ca/failed/queued/issued/disabled 证书任务行（含冷却已到期的
// 历史行）。When GET /system/tasks。
// Then 每行恒带 retry_cooldown_seconds：下发「此刻剩余秒」（0=现在即可运行，
// null=永久不可重试）。waiting_ca 取 CA 退避剩余、通用冷却按 updated_at 扣减
// （已到期行=0），disabled=null，非证书行=0——前端任务行「运行」按钮的冷却
// 判定与证书任务列表（/certificates/jobs）同源同判据。
func TestListSystemTasks_exposesRetryCooldownSeconds(t *testing.T) {
	newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	caWindow := time.Now().UTC().Add(2 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id, rule_id, domain, status, message, ca_available_after, created_at, updated_at)
		VALUES (1,'lb_ca','ca.example','waiting_ca','',?,datetime('now'),datetime('now')),
		       (2,'lb_ok','ok.example','issued','',NULL,datetime('now'),datetime('now')),
		       (3,'lb_failed','failed.example','failed','',NULL,datetime('now'),datetime('now')),
		       (4,'lb_failed_old','failed-old.example','failed','',NULL,datetime('now','-6 minutes'),datetime('now','-6 minutes')),
		       (5,'lb_queued','queued.example','queued','',NULL,datetime('now'),datetime('now')),
		       (6,'lb_queued_old','queued-old.example','queued','',NULL,datetime('now','-16 minutes'),datetime('now','-16 minutes')),
		       (7,'lb_disabled','disabled.example','disabled','',NULL,datetime('now'),datetime('now'))`, caWindow); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}
	r, _ := taskMonitorRouter()
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/system/tasks", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Data struct {
			Tasks []map[string]json.RawMessage `json:"tasks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Tasks) == 0 {
		t.Fatal("任务列表为空，断言失效")
	}
	// 字段必须恒下发：前端用 0 判「无冷却」，omitempty 会让缺键与可运行同形
	// 但解析侧拿到零值尚可，缺键在严格 schema/展示层会退化为「未知」。
	for _, row := range payload.Data.Tasks {
		rawID, ok := row["id"]
		if !ok {
			t.Fatal("任务行缺少 id")
		}
		var id string
		if err := json.Unmarshal(rawID, &id); err != nil {
			t.Fatal(err)
		}
		if _, ok := row["retry_cooldown_seconds"]; !ok {
			t.Fatalf("任务行 %s 缺少 retry_cooldown_seconds（该字段不得 omitempty）", id)
		}
	}
	cooldownOf := func(id string) *int64 {
		t.Helper()
		for _, row := range payload.Data.Tasks {
			var rowID string
			if err := json.Unmarshal(row["id"], &rowID); err != nil {
				t.Fatal(err)
			}
			if rowID != id {
				continue
			}
			if string(row["retry_cooldown_seconds"]) == "null" {
				return nil
			}
			var seconds int64
			if err := json.Unmarshal(row["retry_cooldown_seconds"], &seconds); err != nil {
				t.Fatalf("任务行 %s retry_cooldown_seconds 解析失败: %v", id, err)
			}
			return &seconds
		}
		t.Fatalf("任务行 %s 不存在", id)
		return nil
	}
	wantCooldown := func(id string, want int64) {
		t.Helper()
		got := cooldownOf(id)
		if got == nil {
			t.Fatalf("任务行 %s 冷却=null, want %d", id, want)
		}
		if want == 0 {
			if *got != 0 {
				t.Fatalf("任务行 %s 冷却=%d, want 0（已过期/无冷却必须精确为零）", id, *got)
			}
			return
		}
		// 造行时间 datetime('now') 是秒级截断：恰好跨秒时剩余窗口比完整时长少
		// 1 秒。按区间断言，避免慢机/-race 下偶发假红（与证书任务列表同口径）。
		if *got > want || *got < want-1 {
			t.Fatalf("任务行 %s 冷却=%d, want %d（容许 1 秒秒级截断误差）", id, *got, want)
		}
	}
	if got := cooldownOf("cert-job:1"); got == nil || *got < 7100 || *got > 7200 {
		t.Fatalf("waiting_ca 行冷却=%v, want ≈7200（CA 退避剩余秒）", got)
	}
	wantCooldown("cert-job:2", 0)   // issued：无通用冷却。
	wantCooldown("cert-job:3", 300) // failed：刚更新，剩余完整窗口。
	wantCooldown("cert-job:4", 0)   // failed：updated_at 早于冷却窗口 → 已可重试。
	wantCooldown("cert-job:5", 900) // queued：刚更新。
	wantCooldown("cert-job:6", 0)   // queued：已过期。
	if got := cooldownOf("cert-job:7"); got != nil {
		t.Fatalf("disabled 行冷却=%d, want null（永久不可重试不得表达为 0=现在可重试）", *got)
	}
	wantCooldown("threat", 0) // 非证书任务行：无证书重试冷却概念。
}

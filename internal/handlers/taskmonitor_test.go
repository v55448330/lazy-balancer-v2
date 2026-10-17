package handlers

// 任务监控 handlers 测试（v2.3.4）：聚合形状、触发映射、取消语义、暂停开关、
// 主节点门。直接 handler 调用（与既有测试同模式——鉴权由路由组中间件承担，
// 此处测 handler 内的门与映射）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func initTaskEngineForTest(t *testing.T) {
	t.Helper()
	if services.TaskEngine() == nil || services.TaskEngine().IsStopped() {
		oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
		if err := db.Initialize(t.TempDir()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			services.StopTaskEngine()
			_ = db.Close()
			db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA
		})
		services.InitTaskEngine("", t.TempDir()+"/app.log")
	}
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
	// U10-F06：任务视图只承载 loop_on，不暴露诊断字段 enabled。
	if strings.Contains(resp.Body.String(), `"enabled"`) {
		t.Error("任务列表 JSON 不应含 enabled 键（调度语义只由 loop_on 表达）")
	}
	got := map[string]string{}
	for _, tk := range payload.Data.Tasks {
		got[tk.ID] = tk.Category
	}
	want := []string{"threat", "crs", "ip2region", "auto-backup", "cluster-sync", "config-watchdog", "audit-retention", "security-events-ingestion", "log-cleanup", "cert-renewal-scan", "startup:config-load"}
	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Fatalf("任务族 %s 缺失; got=%v", id, got)
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
	if got["threat"] != "安全防护" || got["cert-renewal-scan"] != "证书" || got["startup:config-load"] != "系统" {
		t.Fatalf("分类错配: %v", got)
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
// 不再有 400 分支，R63 回退 switch 已删，无引擎时统一 503）。
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
			m, _ := te.Lookup(tc.id)
			if enabled != 0 || m.LoopOn {
				t.Fatalf("只读语义被破坏: business=%d loop_on=%v", enabled, m.LoopOn)
			}
		})
	}
}

// U10-F07：四个任务写端点的状态码统一——引擎未初始化 503、任务不存在 404
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

// U10-F12：并发双击下「触发」审计行数必须等于实际 manual task_runs 行数——
// 审计只在 Trigger 成功后记录，CAS 落败者不得留下孤儿「触发」行。
func TestTriggerSystemTask_triggerAuditMatchesManualRuns(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	te := services.TaskEngine()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
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
	<-done
	<-done
	<-entered
	close(release)

	var manualRuns int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id='audit-race-probe' AND trigger='manual'`).Scan(&manualRuns); err == nil && manualRuns > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// 等待异步审计落库稳定（Trigger 返回后才写审计）。
	time.Sleep(200 * time.Millisecond)
	got := countTriggerAudit(t) - before
	if got != manualRuns {
		t.Fatalf("「触发」审计=%d 与实际 manual task_runs=%d 不一致（孤儿/缺失审计）", got, manualRuns)
	}
}

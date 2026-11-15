package handlers

// V2（用户裁定）：手动触发统一经任务引擎——/security/crs/update、
// /security/ip2region/update、/security/threat-lib/update 三端点曾直调
// manager.StartUpdate（rc.RunID=0）：task_runs 零记录，
// 手动更新在任务历史不可见、引擎单飞/主节点门被旁路。修复=端点内体改
// TriggerSystemTask 同型（IsTaskInFlight 409 + 异步 te.Trigger）。

import (
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

// waitTaskRunManualSuccess 等最新一条 task_runs 落定为 manual/success。
func waitTaskRunManualSuccess(t *testing.T, taskID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var trigger, status string
	for time.Now().Before(deadline) {
		trigger, status = "", ""
		err := db.DB.QueryRow(`SELECT COALESCE(trigger,''), COALESCE(status,'') FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT 1`, taskID).Scan(&trigger, &status)
		if err == nil && trigger == "manual" && status == "success" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("task_runs(task_id=%s) 未在 3s 内落定 manual/success（trigger=%q status=%q）——手动触发未经引擎或任务体失败", taskID, trigger, status)
}

// Given 引擎在场且三库任务注册为**成功桩**。
// When 调三个更新端点。
// Then 200 running 且 task_runs 落 trigger=manual + status=success（只数行数
// 无法区分「引擎记录了口径」与「任务体失败但留了一行」）。
func TestSecurityUpdateEndpoints_scheduleViaEngine(t *testing.T) {
	newBackupTestHandlers(t)
	services.StopTaskEngine()
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	services.SetTaskEngineForTest(te)
	t.Cleanup(services.StopTaskEngine)
	for _, id := range []string{"crs", "ip2region", "threat"} {
		if err := te.Register(taskengine.Descriptor{
			ID: id, Family: "security", Name: "更新任务（成功桩）", Category: "安全防护",
			Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly,
			NextSlotFn: func() time.Time { return time.Now().Add(24 * time.Hour) }, // 未来槽——调度器不自动点火
			Run:        func(taskengine.RunContext) error { return nil },
		}); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}

	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	r := gin.New()
	r.POST("/security/crs/update", h.StartCRSUpdate)
	r.POST("/security/ip2region/update", h.StartIP2RegionUpdate)
	r.POST("/security/threat-lib/update", h.StartThreatLibUpdate)

	cases := []struct {
		path   string
		taskID string
	}{
		{"/security/crs/update", "crs"},
		{"/security/ip2region/update", "ip2region"},
		{"/security/threat-lib/update", "threat"},
	}
	for _, tc := range cases {
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, tc.path, nil))
		if resp.Code != http.StatusOK {
			t.Fatalf("%s 应 200（经引擎触发）, got %d %s", tc.path, resp.Code, resp.Body.String())
		}
		waitTaskRunManualSuccess(t, tc.taskID)
	}
}

// 回归形状：引擎在跑时端点同步 409（单飞归引擎口径，与 TriggerSystemTask 一致）。
// 确定性在跑构造——独立引擎只注册 crs 阻塞桩
// 占住单飞，第二次调用恒 409；放行后第三次恒 200（反向对照，证明 409 源自
// 单飞占位而非其他分支）。测试结束 StopTaskEngine 归零全局引擎。
func TestSecurityUpdateEndpoints_conflictWhileInFlight(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)

	services.StopTaskEngine()
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	services.SetTaskEngineForTest(te)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	if err := te.Register(taskengine.Descriptor{
		ID: "crs", Family: "security", Name: "CRS 规则库更新", Category: "安全防护",
		Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, NextSlotFn: func() time.Time { return time.Now().Add(24 * time.Hour) }, // 未来槽——调度器永不自动点火
		Run: func(rc taskengine.RunContext) error {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-rc.Ctx.Done(): // 引擎 Stop 取消兜底（测试中途失败不挂死）
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("注册阻塞桩: %v", err)
	}
	t.Cleanup(func() { services.StopTaskEngine() }) // 桩注册随全局引擎销毁（隔离闭环）

	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	r := gin.New()
	r.POST("/security/crs/update", h.StartCRSUpdate)

	// Given 占住 crs 单飞的一次在跑执行
	go func() { _ = te.Trigger("crs", "manual", "test") }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("引擎 3s 内未进入在跑态")
	}

	// When 在跑期间第二次调用端点
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/security/crs/update", nil))

	// Then 恒 409（不再允许 200——409 映射分支被必然触发）
	if resp.Code != http.StatusConflict {
		t.Fatalf("在跑期间应恒 409, got %d %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "任务运行中") {
		t.Fatalf("409 文案应为「任务运行中」, got %s", resp.Body.String())
	}

	// 放行并等在跑态清零（不留异步尾巴）；反向对照：占位解除后同端点恢复 200
	close(release)
	for i := 0; i < 60 && te.IsTaskInFlight("crs"); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if te.IsTaskInFlight("crs") {
		t.Fatal("放行后 3s 内未退出在跑态")
	}
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/security/crs/update", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("占位解除后应 200, got %d %s", resp.Code, resp.Body.String())
	}
}

// 任务引擎未装配时，库更新触发端点统一 503（引擎缺失
// =服务暂不可用，非内部错误）。此前 CRS/IP2Region/威胁库三处 + 爬虫库触发
// 500，与 taskmonitor 的 503 家族口径漂移；爬虫库状态读端点同族收敛。
func TestLibraryUpdateEndpoints_engineUnavailableReturns503(t *testing.T) {
	newBackupTestHandlers(t)
	services.StopTaskEngine()
	t.Cleanup(services.StopTaskEngine)

	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	r := gin.New()
	r.POST("/security/crs/update", h.StartCRSUpdate)
	r.POST("/security/ip2region/update", h.StartIP2RegionUpdate)
	r.POST("/security/threat-lib/update", h.StartThreatLibUpdate)
	r.POST("/security/crawler-lib/update", h.StartCrawlerLibUpdate)
	r.GET("/security/crawler-lib/update/status", h.GetCrawlerLibUpdateStatus)

	for _, path := range []string{
		"/security/crs/update",
		"/security/ip2region/update",
		"/security/threat-lib/update",
		"/security/crawler-lib/update",
	} {
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, path, nil))
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status=%d body=%s, want 503", path, resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), "任务引擎未初始化") {
			t.Fatalf("%s body=%s, want 引擎未初始化文案", path, resp.Body.String())
		}
	}

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/crawler-lib/update/status", nil))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("crawler status=%d body=%s, want 503", resp.Code, resp.Body.String())
	}
}

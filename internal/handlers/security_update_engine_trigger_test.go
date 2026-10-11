package handlers

// V2（第 67 轮用户裁定）：手动触发统一经任务引擎——/security/crs/update、
// /security/ip2region/update、/security/threat-lib/update 三端点曾直调
// manager.StartUpdate（rc.RunID=0）：task_runs 零记录（R63 单写方=引擎），
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

// countTaskRunsByID 统计指定任务的 task_runs 行数。
func countTaskRunsByID(t *testing.T, taskID string) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id=?`, taskID).Scan(&n); err != nil {
		t.Fatalf("count task_runs: %v", err)
	}
	return n
}

// waitTaskRun 轮询等待任务行落库（引擎异步触发）。
func waitTaskRun(t *testing.T, taskID string) {
	t.Helper()
	for i := 0; i < 60; i++ {
		if countTaskRunsByID(t, taskID) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("task_runs 3s 内未落行（task_id=%s）——手动触发未经引擎", taskID)
}

// Given 主节点+引擎在场（manager 未初始化——引擎 Run 体对 nil manager no-op 成功）。
// When 调三个更新端点。
// Then 200 running 且 task_runs 落行（trigger=manual）——现实现 500+零行（RED）。
func TestSecurityUpdateEndpoints_scheduleViaEngine(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)

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
		waitTaskRun(t, tc.taskID)
	}
}

// 回归形状：引擎在跑时端点同步 409（单飞归引擎口径，与 TriggerSystemTask 一致）。
// SEC-B-GAP-U1（第 69 轮）：重写为确定性在跑构造——旧版「允许 200/409」是
// 空气断言（Run 体 nil manager 立即完成，生产 409 分支从不被必然触发）。现经
// te.Register 重注册 crs 为阻塞桩占住单飞，第二次调用恒 409；放行后第三次恒
// 200（反向对照，证明 409 源自单飞占位而非其他分支）。测试结束 StopTaskEngine
// 归零全局引擎（桩注册随之销毁），后续用例经 initTaskEngineForTest 重建真实接线。
func TestSecurityUpdateEndpoints_conflictWhileInFlight(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)

	te := services.TaskEngine()
	if te == nil {
		t.Fatal("引擎未初始化")
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	if err := te.Register(taskengine.Descriptor{
		ID: "crs", Family: "security", Name: "CRS 规则库更新", Category: "安全防护",
		Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, ManualRun: true,
		NextSlotFn: func() time.Time { return time.Now().Add(24 * time.Hour) }, // 未来槽——调度器永不自动点火
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

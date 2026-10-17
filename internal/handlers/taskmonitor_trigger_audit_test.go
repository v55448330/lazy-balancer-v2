package handlers

// U1-P3-1（第 67 轮审计，P3）：7/12 可手动触发族手动触发在 audit_log 无痕——
// AuditPolicySkip 的前提「任务体 defer 单记审计」（R63 时仅 3 自记族）随 v2.0
// 可触发族扩容失效：现 12 族中 5 族自记（threat/crs/ip2region 任务体 defer +
// auto-backup 执行器 + startup:config-load 载入审计），7 族任务体零审计
// （log-cleanup/audit-retention/security-events-retention/cert-renewal-scan/
// cert-reconcile/cert-manual-poll/cert-waiting-ca）。自动执行有审计（自记族）
// 而手动（更高特权）反而无痕的倒挂随 trigger 路由整族豁免固化。
// 修复口径：trigger handler 对非自记族显式补记「触发/任务监控」，自记族复记
// 会违反 U1-P3-2 单记裁定（2026-09-29 用户裁定），必须跳过。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// countTriggerAudit 统计「触发/任务监控」审计行数。
func countTriggerAudit(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='触发' AND resource='任务监控'`).Scan(&n); err != nil {
		t.Fatalf("count trigger audit: %v", err)
	}
	return n
}

// Given 非自记族 log-cleanup（任务体零 RecordAuditLog）与主节点库。
// When POST /system/tasks/log-cleanup/trigger 手动触发。
// Then audit_log 必须留痕（动作「触发」/对象「任务监控」）——现实现零记录（RED）。
func TestTriggerSystemTask_nonSelfRecordingTriggerLeavesAudit(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/log-cleanup/trigger", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("log-cleanup 手动触发应 200, got %d %s", resp.Code, resp.Body.String())
	}
	// U10-F12：审计在 goroutine 内于 Trigger 成功后记录——轮询落库。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countTriggerAudit(t) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("手动触发非自记族 log-cleanup 在 audit_log 无痕——高特权操作零追责")
}

// 回归形状：自记族 auto-backup（执行器注入点，测试环境未注入→任务体立即失败
// 且零审计）手动触发时 handler 不得复记——否则与任务体 defer/执行器审计构成
// 双记，违反 U1-P3-2（2026-09-29 用户裁定）的单记口径。
func TestTriggerSystemTask_selfRecordingTriggerSkipsHandlerAudit(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/auto-backup/trigger", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("auto-backup 手动触发应 200, got %d %s", resp.Code, resp.Body.String())
	}
	// U10-F12：异步审计落库窗口后再断言零复记（自记族恒零 handler 审计）。
	time.Sleep(200 * time.Millisecond)
	if n := countTriggerAudit(t); n != 0 {
		t.Fatalf("自记族 auto-backup 的 handler 复记会产生双审计（U1-P3-2 单记裁定）, got %d 行", n)
	}
}

// countTriggerFailAudit 统计「触发失败」补偿审计行数。
func countTriggerFailAudit(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='触发失败'`).Scan(&n); err != nil {
		t.Fatalf("count trigger-fail audit: %v", err)
	}
	return n
}

// F-U3-01+F-U1-1（第 68 轮）：四处 go 闭包 te.Trigger 错误被吞——非自记族已
// 补记「触发」但 Trigger 失败时任务未执行，审计只剩孤儿行；自记族零痕迹。
// 修复：go 内 err 非 nil 时补记「触发失败」审计+日志（operator 闭包外预取——
// gin.Context 在 handler 返回后被复用，闭包内读是竞态）。
//
// Given 自动备份执行器未注入（测试环境任务体立即失败→te.Trigger 回传错误）。
// When POST /system/tasks/auto-backup/trigger 手动触发。
// Then 必须补记「触发失败」补偿审计（现实现零——RED）。
func TestTriggerSystemTask_triggerFailureLeavesCompensationAudit(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/auto-backup/trigger", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("auto-backup 手动触发应 200, got %d %s", resp.Code, resp.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if countTriggerFailAudit(t) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Trigger 失败路径零补偿审计——任务未执行/失败无痕（孤儿审计）")
}

// TASK-2（第 70 轮 P3）：手动触发 409 预检（IsTaskInFlight）与异步 goroutine
// Trigger 之间无原子性——并发双击两请求均可过预检，后到者在引擎 CAS 落败拿
// ErrAlreadyRunning：任务实际已由先到请求启动，落「触发失败」审计是语义
// 失真（用户看到失败而任务在跑）。修复：该错误在 goroutine 内静默。
//
// 竞态窗口窄，测试用「同线程背靠背双发 + 重试直至成形」驱动：两请求均 200
// 且胜者已进入 Run 才算成形（非空跑），成形后断言零「触发失败」审计。
func TestTriggerSystemTask_doubleClickRaceNoMisleadingFailAudit(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()
	te := services.TaskEngine()

	waitNotInFlight := func(taskID string) {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if !te.IsTaskInFlight(taskID) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	materialized := false
	for attempt := 0; attempt < 50 && !materialized; attempt++ {
		taskID := fmt.Sprintf("t-race-%d", attempt)
		before := countTriggerFailAudit(t)
		entered := make(chan struct{})
		release := make(chan struct{})
		if err := te.Register(taskengine.Descriptor{
			ID: taskID, Family: "t", Name: "双击竞态", Kind: taskengine.KindOneshot,
			Run: func(taskengine.RunContext) error {
				close(entered)
				<-release
				return nil
			},
		}); err != nil {
			t.Fatal(err)
		}
		rec1, rec2 := httptest.NewRecorder(), httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodPost, "/system/tasks/"+taskID+"/trigger", nil)
		req2 := httptest.NewRequest(http.MethodPost, "/system/tasks/"+taskID+"/trigger", nil)
		done := make(chan struct{}, 2)
		go func() { r.ServeHTTP(rec1, req1); done <- struct{}{} }()
		go func() { r.ServeHTTP(rec2, req2); done <- struct{}{} }()
		<-done
		<-done
		if rec1.Code != http.StatusOK || rec2.Code != http.StatusOK {
			// 预检已拦（其一 409）——竞态未成形，释放后重试
			close(release)
			waitNotInFlight(taskID)
			continue
		}
		select {
		case <-entered: // 两请求均 200 且胜者已进 Run——败者必拿 ErrAlreadyRunning
			materialized = true
		case <-time.After(2 * time.Second):
			close(release)
			waitNotInFlight(taskID)
			continue
		}
		time.Sleep(200 * time.Millisecond) // 败者补偿路径（审计/日志）落库
		if got := countTriggerFailAudit(t) - before; got != 0 {
			close(release)
			t.Fatalf("并发双击第二请求落了 %d 条「触发失败」审计——任务实际已启动（语义失真）", got)
		}
		close(release)
		waitNotInFlight(taskID)
	}
	if !materialized {
		t.Skip("50 次尝试内双击竞态未成形（预检均拦截）——未验证到目标分支")
	}
}

// LNK71-1（第 71 轮 P5）：手动触发落在 skipped 终态时仍落「触发失败」审计
// ——threat/crs/ip2region Run 体 demote 中止返回 ErrTaskSkipped（TASK-L5
// 哨兵，task_runs 已落 skipped 行），TASK-2 修 ErrAlreadyRunning 时同族扫描
// 未延伸到该哨兵。skipped=「非故障放弃」，复记「触发失败」是语义失真
// （用户看到失败而任务体明确声明放弃）。修复：goroutine 内静默
// （镜像 ErrAlreadyRunning 分支）。
func TestTriggerSystemTask_skippedTerminalNoFailAudit(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	te := services.TaskEngine()
	if err := te.Register(taskengine.Descriptor{
		ID: "skip-probe", Family: "测试", Name: "跳过探针", Kind: taskengine.KindOneshot,
		Run: func(taskengine.RunContext) error { return taskengine.ErrTaskSkipped },
	}); err != nil {
		t.Fatal(err)
	}
	before := countTriggerFailAudit(t)
	r, _ := taskMonitorRouter()
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/skip-probe/trigger", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("手动触发应 200, got %d %s", resp.Code, resp.Body.String())
	}
	// Trigger→runNow 同步执行：轮询 task_runs 落 skipped 终态（证明任务体
	// 已执行且哨兵已回传 handler goroutine 的 Trigger 调用方）。
	deadline := time.Now().Add(3 * time.Second)
	skipped := false
	for time.Now().Before(deadline) {
		var status string
		if err := db.DB.QueryRow(`SELECT status FROM task_runs WHERE task_id='skip-probe' ORDER BY id DESC LIMIT 1`).Scan(&status); err == nil && status == "skipped" {
			skipped = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !skipped {
		t.Fatal("skip-probe 未落 skipped 终态——任务未执行")
	}
	// 补偿路径（审计/日志）落库窗口（与双击竞态测试同手法）
	time.Sleep(200 * time.Millisecond)
	if got := countTriggerFailAudit(t) - before; got != 0 {
		t.Fatalf("skipped 终态（非故障放弃）落了 %d 条「触发失败」审计——语义失真", got)
	}
}

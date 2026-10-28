package handlers

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func TestImportFailureAuditDescriptionReflectsFailurePhase(t *testing.T) {
	tests := []struct {
		name  string
		phase importPhase
		want  string
	}{
		{name: "queue recovery after commit is partial", phase: importPhaseQueue, want: "导入部分失败"},
		{name: "Caddy validation preserves database", phase: importPhaseCaddy, want: "数据库未变更"},
		{name: "certificate failure identifies preparation", phase: importPhaseCertificate, want: "证书准备失败"},
		{name: "commit failure does not claim unchanged database", phase: importPhaseCommit, want: "数据库提交结果不确定"},
		{name: "in-transaction cleanup preparation identifies rollback", phase: importPhasePrepare, want: "数据库未变更"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			err := &importCoordinatorError{phase: test.phase, err: errors.New("injected")}

			// When
			detail := importFailureAuditDescription(err)

			// Then
			if !strings.Contains(detail, test.want) {
				t.Fatalf("detail=%q want fragment=%q", detail, test.want)
			}
		})
	}
}

// assertNoConfigImportWindowLeak 把「导入窗口泄漏」钉到真正的前序用例：
// configImportBeginMu 是包级全局，异步导入 goroutine 若在本用例开始前仍未
// 收尾，无关写端点会收到 409「配置导入进行中」而非真实业务码——原形态表现
// 为随机假红（无法归因）。入口显式失败，消息直指泄漏源。
func assertNoConfigImportWindowLeak(t *testing.T) {
	t.Helper()
	if configImportBusy() {
		t.Fatal("导入窗口泄漏：导入会话未释放（窗口计数非零）")
	}
}

// beginImportWindowForTest 以显式窗口计数模拟「导入会话进行中」（与生产
// 会话同一个事实源）。不得用 Lock 真实会话锁模拟：持锁者不一定是导入会话，
// 且真实锁只用于串行化，不得兼任可观测状态。
func beginImportWindowForTest(t *testing.T) func() {
	t.Helper()
	importWindowActive.Add(1)
	closed := false
	closeWindow := func() {
		if closed {
			return
		}
		closed = true
		importWindowActive.Add(-1)
	}
	t.Cleanup(closeWindow)
	return closeWindow
}

// 并发导入必须串行；第二个会话在第一个
// close 前不得已执行 Pause，否则第一个 Resume 会让它失去排空保护。
func TestBeginConfigImport_serializesConcurrentSessions(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	if err := te.Register(taskengine.Descriptor{
		ID: "import-serial-probe", Family: "test", Name: "Import serialization probe",
		Kind: taskengine.KindOneshot,
		Run:  func(taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	first, err := h.beginConfigImport(context.Background(), "导入")
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		session *configImportSession
		err     error
	}
	secondAttempt := make(chan struct{})
	var attemptOnce sync.Once
	oldAttemptHook := configImportBeginAttemptHook
	configImportBeginAttemptHook = func() { attemptOnce.Do(func() { close(secondAttempt) }) }
	t.Cleanup(func() { configImportBeginAttemptHook = oldAttemptHook })
	secondDone := make(chan result, 1)
	go func() {
		session, err := h.beginConfigImport(context.Background(), "导入")
		secondDone <- result{session: session, err: err}
	}()
	// 第二个会话已确证在首个 close 前到达会话锁入口；无需猜测 100ms 是否
	// 足以让旧实现先 Pause。
	select {
	case <-secondAttempt:
	case <-time.After(5 * time.Second):
		first.close()
		t.Fatal("second import did not reach session lock")
	}
	first.close()
	var second result
	select {
	case second = <-secondDone:
	case <-time.After(5 * time.Second):
		t.Fatal("second import did not begin after first closed")
	}
	if second.err != nil {
		t.Fatalf("second begin: %v", second.err)
	}
	err = te.Trigger("import-serial-probe", "manual", "test")
	if !errors.Is(err, taskengine.ErrSchedulingPaused) {
		second.session.close()
		t.Fatalf("second import session is not paused (trigger err=%v)", err)
	}
	second.session.close()
}

// Resume 必须先于串行会话锁释放；否则后到导入可先 Pause，
// 再被前一代 Resume 覆盖，在调度恢复状态下执行事务。
func TestConfigImportSessionClose_resumesBeforeReleasingSerialization(t *testing.T) {
	h := &Handlers{}
	h.caddyOpMu.Lock()
	events := make([]string, 0, 2)
	session := &configImportSession{
		h:        h,
		finished: true,
		releaseBeforeLock: func() {
			events = append(events, "release")
		},
		resumeEngine: func() {
			events = append(events, "resume")
		},
	}

	session.close()

	if got := strings.Join(events, ","); got != "resume,release" {
		t.Fatalf("close 锁序=%s, want resume,release", got)
	}
}

func TestConfigImportSessionClose_releasesLocksWhenAbortPanics(t *testing.T) {
	h := &Handlers{caddyService: &services.CaddyService{}}
	h.caddyOpMu.Lock()
	oldDB := db.DB
	db.DB = nil // 让 abort 的已提交视图投影回滚确定性 panic。
	t.Cleanup(func() {
		db.DB = oldDB
		h.caddyOpMu.TryLock()
		h.caddyOpMu.Unlock()
	})
	resumed, released := 0, 0
	session := &configImportSession{
		h:                 h,
		resumeEngine:      func() { resumed++ },
		releaseBeforeLock: func() { released++ },
	}

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		session.close()
	}()
	if recovered != nil {
		t.Fatalf("close 未兜住 abort panic: %v", recovered)
	}

	if !h.caddyOpMu.TryLock() {
		t.Fatal("abort panic 后 caddyOpMu 仍被占用")
	}
	h.caddyOpMu.Unlock()
	if resumed != 1 || released != 1 {
		t.Fatalf("panic 收尾 resume/release=%d/%d, want 1/1", resumed, released)
	}
}

func TestConfigImportSessionClose_idempotent(t *testing.T) {
	h := &Handlers{}
	h.caddyOpMu.Lock()
	session := &configImportSession{h: h, finished: true}

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		session.close()
		session.close()
	}()
	if recovered != nil {
		t.Fatalf("重复 close panic: %v", recovered)
	}

	if !h.caddyOpMu.TryLock() {
		t.Fatal("重复 close 后 caddyOpMu 状态异常")
	}
	h.caddyOpMu.Unlock()
}

// ctx-blind 在途任务超过排空预算后不得继续全量导入；
// 必须恢复调度、释放会话锁并返回可重试 409，而非留下 last-writer-wins 窗口。
func TestBeginConfigImport_taskDrainTimeoutAbortsBeforeTransaction(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	oldTimeout := importInFlightDrainTimeout
	importInFlightDrainTimeout = 20 * time.Millisecond
	t.Cleanup(func() { importInFlightDrainTimeout = oldTimeout })
	te := services.TaskEngine()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	if err := te.Register(taskengine.Descriptor{
		ID: "import-drain-blocker", Family: "test", Name: "导入排空阻塞", Kind: taskengine.KindOneshot, RunsOn: taskengine.RoleAny,
		Run: func(taskengine.RunContext) error {
			close(entered)
			<-release // 故意不消费 rc.Ctx，模拟既有 ctx-blind 扫描
			close(done)
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := te.Register(taskengine.Descriptor{
		ID: "import-drain-resumed", Family: "test", Name: "导入拒绝后调度恢复", Kind: taskengine.KindOneshot, RunsOn: taskengine.RoleAny,
		Run: func(taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if err := te.RunAsync("import-drain-blocker", "manual", "tester"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("阻塞任务未进入")
	}

	session, err := h.beginConfigImport(context.Background(), "导入")
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("阻塞任务未退出")
	}
	if session != nil {
		session.close()
	}
	if err == nil {
		t.Fatal("在途 ctx-blind 任务未排空时仍允许导入，必须返回拒绝")
	}
	if !strings.Contains(err.Error(), "在途任务") {
		t.Fatalf("err=%v, want 在途任务排空原因", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	respondImportBeginError(ctx, err)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("排空失败 HTTP status=%d body=%s, want 409", recorder.Code, recorder.Body.String())
	}
	var action, detail string
	if queryErr := db.AuditDB.QueryRow(`SELECT action,detail FROM audit_log WHERE resource='配置备份' ORDER BY id DESC LIMIT 1`).Scan(&action, &detail); queryErr != nil {
		t.Fatal(queryErr)
	}
	if action != "导入失败" || !strings.Contains(detail, "未执行") {
		t.Fatalf("排空失败审计 action=%q detail=%q, want 导入失败/未执行", action, detail)
	}
	if err := te.Trigger("import-drain-resumed", "manual", "tester"); err != nil {
		t.Fatalf("排空拒绝后调度未恢复: %v", err)
	}
}

func TestBeginConfigImport_preservesStoppedCAQueue(t *testing.T) {
	// Given：cert-issuance 已被停止，CA 队列为 inactive。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	// 本用例刻意把单例留在 inactive：不登记收尾的话，后续用例的发证入队会拿到
	// 「证书签发任务未运行」（409）而不是各自的预期失败，全包结果随顺序变红。
	t.Cleanup(services.ResetCAQueueManagerForTest)
	services.InitCAQueueManager(func() error { return nil })
	services.GetCAQueueManager().Start()
	manager := services.GetCAQueueManager()
	manager.PauseAndDrain()
	if manager.IsActive() {
		t.Fatal("前置态错误：CA 队列应为 inactive")
	}

	// When：执行导入 begin/close（含 PauseAndDrain 与恢复收尾）。
	session, err := h.beginConfigImport(context.Background(), "导入")
	if err != nil {
		t.Fatal(err)
	}
	session.close()

	// Then：恢复不得把 inactive 队列重新激活或启动真实签发。
	if manager.IsActive() {
		t.Fatal("导入恢复了用户停止的 CA 队列（cert-issuance 生命周期被旁路）")
	}
}

// 证书队列排空超时（409）与建会话失败的 500 同属「高危操作被拒」的复盘面：
// 与在途任务排空分支对称，必须留 warn 运行日志与失败审计，不能只在响应里出现。
func TestBeginConfigImport_certQueueDrainTimeoutAudits(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	services.ResetCAQueueManagerForTest()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	services.InitCAQueueManager(func() error { return nil })
	services.GetCAQueueManager().Start()
	// 执行中且不响应取消的条目：PauseAndDrain 退役队列后 active 仍非空。
	services.GetCAQueueManager().MarkJobRunningForTest("rule-drain", 4242)

	var logs strings.Builder
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldOutput) })

	session, err := h.beginConfigImport(context.Background(), "还原")
	if session != nil {
		session.close()
	}
	if !errors.Is(err, errCertQueueDrainIncomplete) {
		t.Fatalf("err=%v, want 证书队列排空未完成", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	respondImportBeginError(ctx, err)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("排空失败 status=%d body=%s, want 409", recorder.Code, recorder.Body.String())
	}

	var action, detail string
	if queryErr := db.AuditDB.QueryRow(`SELECT action,detail FROM audit_log WHERE resource='配置备份' ORDER BY id DESC LIMIT 1`).Scan(&action, &detail); queryErr != nil {
		t.Fatalf("证书排空失败必须写审计: %v", queryErr)
	}
	if action != "还原失败" {
		t.Fatalf("审计 action=%q, want 还原失败（动作词必须跟随调用方）", action)
	}
	if !strings.Contains(detail, "证书任务执行中") || !strings.Contains(detail, "未执行") {
		t.Fatalf("审计 detail=%q, want 证书任务执行中/未执行", detail)
	}
	if !strings.Contains(logs.String(), "WARNING:") || !strings.Contains(logs.String(), "证书任务执行中") {
		t.Fatalf("运行日志缺少 warn 留痕: %q", logs.String())
	}
}

// 建会话的两条 500 分支（读现有规则/开导入事务）同样必须留痕：事务内失败走
// failImportAbort，事务外失败若静默，操作审计页对高危操作被拒零记录。
func TestBeginConfigImport_ruleReadFailureAudits(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	services.ResetCAQueueManagerForTest()
	t.Cleanup(services.ResetCAQueueManagerForTest)

	oldRead := importRuleIDsForBegin
	importRuleIDsForBegin = func(context.Context) ([]string, error) { return nil, errors.New("injected read failure") }
	t.Cleanup(func() { importRuleIDsForBegin = oldRead })

	session, err := h.beginConfigImport(context.Background(), "导入")
	if session != nil {
		session.close()
	}
	if err == nil || !strings.Contains(err.Error(), "读取现有规则") {
		t.Fatalf("err=%v, want 读取现有规则失败", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	respondImportBeginError(ctx, err)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", recorder.Code)
	}
	if body := recorder.Body.String(); strings.Contains(body, "injected read failure") || !strings.Contains(body, "建立导入会话失败，请稍后重试") {
		t.Fatalf("500 响应泄露底层错误或缺少固定文案: %s", body)
	}
	var action, detail string
	if queryErr := db.AuditDB.QueryRow(`SELECT action,detail FROM audit_log WHERE resource='配置备份' ORDER BY id DESC LIMIT 1`).Scan(&action, &detail); queryErr != nil {
		t.Fatalf("读规则失败必须写审计: %v", queryErr)
	}
	if action != "导入失败" || !strings.Contains(detail, "读取现有规则") || !strings.Contains(detail, "未执行") {
		t.Fatalf("审计 action=%q detail=%q, want 导入失败/读取现有规则/未执行", action, detail)
	}

	// 失败收尾必须恢复调度与串行锁：下一次 begin 能正常建立会话。
	importRuleIDsForBegin = oldRead
	retry, retryErr := h.beginConfigImport(context.Background(), "导入")
	if retryErr != nil {
		t.Fatalf("失败收尾后调度/锁未释放: %v", retryErr)
	}
	retry.close()
}

func TestBeginConfigImport_beginTxFailureAudits(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	services.ResetCAQueueManagerForTest()
	t.Cleanup(services.ResetCAQueueManagerForTest)

	oldBegin := importBeginTx
	importBeginTx = func(context.Context) (*sql.Tx, error) { return nil, errors.New("injected tx failure") }
	t.Cleanup(func() { importBeginTx = oldBegin })

	session, err := h.beginConfigImport(context.Background(), "还原")
	if session != nil {
		session.close()
	}
	if err == nil || !strings.Contains(err.Error(), "开始导入事务") {
		t.Fatalf("err=%v, want 开始导入事务失败", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	respondImportBeginError(ctx, err)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", recorder.Code)
	}
	if body := recorder.Body.String(); strings.Contains(body, "injected tx failure") || !strings.Contains(body, "建立导入会话失败，请稍后重试") {
		t.Fatalf("500 响应泄露底层错误或缺少固定文案: %s", body)
	}
	var action, detail string
	if queryErr := db.AuditDB.QueryRow(`SELECT action,detail FROM audit_log WHERE resource='配置备份' ORDER BY id DESC LIMIT 1`).Scan(&action, &detail); queryErr != nil {
		t.Fatalf("开事务失败必须写审计: %v", queryErr)
	}
	if action != "还原失败" || !strings.Contains(detail, "开启导入事务") || !strings.Contains(detail, "未执行") {
		t.Fatalf("审计 action=%q detail=%q, want 还原失败/开启导入事务/未执行", action, detail)
	}

	importBeginTx = oldBegin
	retry, retryErr := h.beginConfigImport(context.Background(), "还原")
	if retryErr != nil {
		t.Fatalf("失败收尾后调度/锁未释放: %v", retryErr)
	}
	retry.close()
}

func TestConfigImport_mapsCaddyTransportAndRejectionDifferently(t *testing.T) {
	const v1Backup = `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	for _, format := range []string{"v2", "v1"} {
		for _, rejected := range []bool{false, true} {
			name := format + " transport"
			if rejected {
				name = format + " rejection"
			}
			t.Run(name, func(t *testing.T) {
				h := newBackupTestHandlers(t)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if r.Method == http.MethodPost && r.URL.Path == "/load" {
						if rejected {
							w.WriteHeader(http.StatusBadRequest)
							_, _ = w.Write([]byte("rejected"))
							return
						}
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Errorf("hijack Caddy response: %v", err)
							return
						}
						_ = conn.Close()
						return
					}
					_, _ = w.Write([]byte(`{}`))
				}))
				t.Cleanup(server.Close)
				h.caddyService = services.NewCaddyService(server.URL)
				router := gin.New()
				path, body := "/config/import", buildBackup(t, backupFixtureOptions{FillAll: true, Tables: nil, Config: nil, Sections: nil, EmptyConfigIfNil: true})
				if format == "v1" {
					path, body = "/config/import/v1", v1Backup
					router.POST(path, h.ImportV1Config)
				} else {
					router.POST(path, h.ImportConfigBackup)
				}

				response := httptest.NewRecorder()
				request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(response, request)

				want := http.StatusInternalServerError
				if rejected {
					want = http.StatusBadRequest
				}
				if response.Code != want {
					t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), want)
				}
				if !rejected && strings.Contains(response.Body.String(), "未通过 Caddy 验证") {
					t.Fatalf("transport failure mislabeled as validation rejection: %s", response.Body.String())
				}
			})
		}
	}
}

func TestConfigImportAbort_restoresCommittedLKGWhenRuntimeRestoreFails(t *testing.T) {
	// Given an import that already attempted the uncommitted Caddy apply.
	harness := newImportRollbackHarness(t)
	h := harness.handler
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		VALUES ('lb_lkg','lkg','http','committed.example.test',18441,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb_lkg','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	lkgPath := filepath.Join(t.TempDir(), "last-good.json")
	h.caddyService.SetLastGoodPath(lkgPath)
	session, err := h.beginConfigImport(context.Background(), "导入")
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()
	session.runtime = &importRuntimeSnapshot{caddyConfig: map[string]interface{}{"marker": "before-import"}}
	session.runtimeApplyAttempted = true
	if _, err := session.tx.Exec(`UPDATE lb_rules SET domain='uncommitted.example.test' WHERE caddy_id='lb_lkg'`); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lkgPath, []byte(`{"apps":{"uncommitted":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	harness.failRestore()

	// When aborting while the runtime restore /load is also rejected.
	abortErr := session.abort(errors.New("injected commit failure"))

	// Then LKG still converges to committed bytes even though runtime recovery failed.
	if abortErr == nil {
		t.Fatal("abort must preserve the injected and restore errors")
	}
	lkg, err := os.ReadFile(lkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lkg), "committed.example.test") || strings.Contains(string(lkg), "uncommitted") {
		t.Fatalf("LKG did not converge to committed view: %s", lkg)
	}
}

func TestImportConfigBackup_invalidatesTaskLogCacheAndCancelsInFlightRuns(t *testing.T) {
	// Given import side-effect spies.
	h := newBackupTestHandlers(t)
	oldInvalidate, oldCancel := invalidateImportTaskLogCache, cancelImportInFlightRuns
	invalidations, cancellations := 0, 0
	invalidateImportTaskLogCache = func() { invalidations++ }
	cancelImportInFlightRuns = func() { cancellations++ }
	t.Cleanup(func() {
		invalidateImportTaskLogCache, cancelImportInFlightRuns = oldInvalidate, oldCancel
	})
	body := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"users": {{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
	}, Config: map[string]any{"task_log_size_mb": 20}, Sections: []string{"users"}, EmptyConfigIfNil: true})

	// When committing an import that writes task_log_size_mb.
	rec := importBackupShared(h, t, body)

	// Then the task log TTL cache is invalidated and in-flight engine runs are canceled.
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}
	if invalidations != 1 || cancellations != 1 {
		t.Fatalf("invalidations=%d cancellations=%d, want 1/1", invalidations, cancellations)
	}
}

// 导入窗口的可观测状态必须只由真实会话驱动：串行化锁被任意持锁者占住
// （含其他测试的模拟）不得让无关写端点误报 409。锁生命周期与窗口状态是
// 两个事实，读侧不得用 TryLock 推测。
func TestConfigImportBusy_ignoresSessionLockHeldWithoutSession(t *testing.T) {
	configImportBeginMu.Lock()
	defer configImportBeginMu.Unlock()

	if configImportBusy() {
		t.Fatal("仅持串行化锁（无导入会话）不得判定为导入窗口")
	}
}

func TestConfigImportBusy_tracksRealSessionLifecycle(t *testing.T) {
	h := newBackupTestHandlers(t)
	if configImportBusy() {
		t.Fatal("前置失败：窗口应在初始关闭态")
	}
	session, err := h.beginConfigImport(context.Background(), "导入")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if !configImportBusy() {
		session.close()
		t.Fatal("会话建立后窗口必须开启")
	}
	session.close()
	if configImportBusy() {
		t.Fatal("会话关闭后窗口必须关闭")
	}
}

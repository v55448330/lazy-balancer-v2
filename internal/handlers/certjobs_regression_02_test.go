package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// certJobRereadFailingConnector 返回一个按语句路由的假 db.DB：任务行 SELECT 正常
// 返回在途态行，CAS UPDATE 命中 0 行（模拟 worker 并发推进状态），重读 SELECT
// 注入瞬时 DB 故障（同 假连接器模式）。
type certJobRereadFailingConnector struct{}

func (certJobRereadFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return certJobRereadFailingConn{}, nil
}

func (certJobRereadFailingConnector) Driver() driver.Driver { return certJobRereadFailingDriver{} }

type certJobRereadFailingDriver struct{}

func (certJobRereadFailingDriver) Open(string) (driver.Conn, error) {
	return certJobRereadFailingConn{}, nil
}

type certJobRereadFailingConn struct{}

func (certJobRereadFailingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (certJobRereadFailingConn) Close() error { return nil }

func (certJobRereadFailingConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (certJobRereadFailingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "rule_id, domain, status"):
		// 自此 DeleteCertJob 的首个 SELECT 同时扫 cert_pem/key_pem（6 列）。
		return &fakeQueryRows{values: [][]driver.Value{{"lb_reread_500", "reread.example.test", "validating", int64(1), "", ""}}}, nil
	case strings.Contains(query, "SELECT status FROM cert_jobs"):
		return nil, errors.New("注入的重读故障")
	case strings.Contains(query, "SELECT COUNT(1) FROM lb_rules"):
		return &fakeQueryRows{values: [][]driver.Value{{int64(0)}}}, nil
	default:
		return &fakeQueryRows{}, nil
	}
}

func (certJobRereadFailingConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "UPDATE cert_jobs SET status='disabled'") {
		return certJobZeroRowsResult{}, nil
	}
	return nil, errors.New("unexpected exec: " + query)
}

type certJobZeroRowsResult struct{}

func (certJobZeroRowsResult) LastInsertId() (int64, error) { return 0, nil }

func (certJobZeroRowsResult) RowsAffected() (int64, error) { return 0, nil }

func TestDeleteCertJob_reread_failure_returns_500(t *testing.T) {
	// CAS 命中 0 行后的归因重读本身失败（瞬时 DB 故障）是
	// 新增的第三分支——必须显式 500（读取任务状态失败），不得误报 409/404。
	// Given
	h := newBackupTestHandlers(t)
	fake := sql.OpenDB(certJobRereadFailingConnector{})
	t.Cleanup(func() { _ = fake.Close() })
	orig := db.DB
	db.DB = fake
	t.Cleanup(func() { db.DB = orig })
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/7", nil))

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（重读失败不得误报 409/404）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "读取任务状态失败") {
		t.Fatalf("body=%s, want 读取任务状态失败", response.Body.String())
	}
}

func TestDeleteCertJob_concurrent_status_change_returns_409(t *testing.T) {
	// 在途态任务（放行的 escape-hatch 对象）删除时，worker 在
	// SELECT 与 disabled 翻转之间推进状态（如 validating→validated），CAS
	// 命中 0 行属并发竞争而非服务器故障——必须重读区分归因并返回 409
	// 刷新重试文案（对齐 RetryCertJob 模式），不得返回误导性 500。
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_cas','cas.example.test','validating')`); err != nil {
		t.Fatalf("seed in-flight job: %v", err)
	}
	oldHook := deleteCertJobPreDisableHook
	deleteCertJobPreDisableHook = func(jobID int) {
		if _, err := db.DB.Exec("UPDATE cert_jobs SET status='validated', updated_at=datetime('now') WHERE id=?", jobID); err != nil {
			t.Errorf("simulate worker transition: %v", err)
		}
	}
	t.Cleanup(func() { deleteCertJobPreDisableHook = oldHook })
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))

	// Then
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（并发状态变更不得报 500）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "任务状态已变更，请刷新后重试") {
		t.Fatalf("body=%s, want 并发状态变更文案", response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "validated" {
		t.Fatalf("status=%q, want validated（worker 流转结果不应被删除流程覆盖）", status)
	}
}

func TestDeleteCertJob_row_disappearing_before_disable_returns_404(t *testing.T) {
	// CAS 命中 0 行且重读发现行已不存在（并发删除），按 handler 对
	// 缺失任务的既有语义返回 404，而非 500「Failed to verify disabled job」。
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_gone','gone.example.test','validating')`); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	oldHook := deleteCertJobPreDisableHook
	deleteCertJobPreDisableHook = func(jobID int) {
		if _, err := db.DB.Exec("DELETE FROM cert_jobs WHERE id=?", jobID); err != nil {
			t.Errorf("simulate row disappearing: %v", err)
		}
	}
	t.Cleanup(func() { deleteCertJobPreDisableHook = oldHook })
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))

	// Then
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Job not found") {
		t.Fatalf("body=%s, want Job not found", response.Body.String())
	}
}

func TestDeleteCertJob_restore_skips_when_row_left_disabled(t *testing.T) {
	// 删除窗口内行被并发移离 disabled（如 worker 重新排队）时，恢复不得把
	// 已推进的状态覆写回原态；RowsAffected=0 须并入 deleteErr 上抛 500。
	// Given：failed 任务 + DELETE 恒失败（触发器注入）
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_restore','restore.example.test','failed')`); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER certjob_delete_abort BEFORE DELETE ON cert_jobs BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("DROP TRIGGER IF EXISTS certjob_delete_abort") })
	oldHook := deleteCertJobPreRestoreHook
	deleteCertJobPreRestoreHook = func(jobID int) {
		// 模拟 worker 在删除窗口内把行重新排队（移离 disabled）
		if _, err := db.DB.Exec("UPDATE cert_jobs SET status='queued', updated_at=datetime('now') WHERE id=?", jobID); err != nil {
			t.Errorf("simulate worker requeue: %v", err)
		}
	}
	t.Cleanup(func() { deleteCertJobPreRestoreHook = oldHook })
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))

	// Then：500 上抛；行状态不被恢复覆写（保持 queued）
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（恢复跳过须并入 deleteErr 上抛）", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "queued" {
		t.Fatalf("status=%q, want queued（行已移离 disabled，恢复不得覆写）", status)
	}
}

func TestDeleteCertJob_restore_failedFallbackKeepsRowLeftDisabled(t *testing.T) {
	// 恢复 else 分支（排队/等待态）的 failed 回退必须与另三分支同构带
	// status='disabled' 守卫：行在删除窗口内被并发移离 disabled（worker 接管）
	// 时不得覆写其新状态，RowsAffected=0 并入 deleteErr 上抛 500。
	// Given：queued 任务（无规则，删除放行）+ DELETE 恒失败
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_fallback','fallback.example.test','queued')`); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER certjob_delete_abort_fallback BEFORE DELETE ON cert_jobs BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("DROP TRIGGER IF EXISTS certjob_delete_abort_fallback") })
	oldHook := deleteCertJobPreRestoreHook
	deleteCertJobPreRestoreHook = func(jobID int) {
		if _, err := db.DB.Exec("UPDATE cert_jobs SET status='issued', updated_at=datetime('now') WHERE id=?", jobID); err != nil {
			t.Errorf("simulate concurrent worker takeover: %v", err)
		}
	}
	t.Cleanup(func() { deleteCertJobPreRestoreHook = oldHook })
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "issued" {
		t.Fatalf("status=%q, want issued（failed 回退不得覆写已移离 disabled 的并发状态）", status)
	}
}

func TestDeleteCertJob_restore_failedFallbackMarksFailedWhenStillDisabled(t *testing.T) {
	// 守卫的正向契约：行仍处 disabled（无并发接管）时，恢复失败回退照常落
	// failed + 删除仍 500。
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_fallback_ok','fallbackok.example.test','waiting_ca')`); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER certjob_delete_abort_fallback_ok BEFORE DELETE ON cert_jobs BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("DROP TRIGGER IF EXISTS certjob_delete_abort_fallback_ok") })
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed（恢复失败回退在行仍 disabled 时必须落 failed）", status)
	}
}

// 两条证书清单端点（/certificates 与 /certificates/jobs）对同一坏行必须同语义：
// 单行读失败即 fail-visible 500（此前聚合清单是 warn+continue：本页少一行而
// total 仍按 COUNT(*) 计入，翻页集合与 total 不闭合，且运维只能从应用日志发现；
// 任务列表同一坏行是显式 500）。
// 钉：单行 scan 失败 → 500 + 固定文案（不回显底层错误/坏行内容）。
func TestListCertificates_scanFailureFailsVisible(t *testing.T) {
	// Given：假驱动首行 id 列类型错误（Scan 必然失败），次行正常；
	// COUNT(*) 分页统计单独路由（子串匹配随机顺序，两条查询须用互斥前缀）。
	h := newBackupTestHandlers(t)
	fakeDB(t, map[string]driver.Rows{
		"SELECT COUNT(*) FROM cert_jobs": &fakeQueryRows{values: [][]driver.Value{{int64(2)}}},
		"SELECT j.id": &fakeQueryRows{values: [][]driver.Value{
			{"bad-id", "lb_bad", "bad.example.test", "ok", "", "", "", ""},
			{int64(2), "lb_good", "good.example.test", "ok", "", "", "", ""},
		}},
	})
	captureLog(t)
	router := gin.New()
	router.GET("/certificates", h.ListCertificates)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/certificates", nil))

	// Then：500 + 统一文案，且不泄漏坏行/正常行数据（部分结果不得随 5xx 下发）。
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（坏行必须 fail-visible，与 /certificates/jobs 同语义）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "读取证书任务失败") {
		t.Fatalf("body=%s, want 固定失败文案", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "bad.example.test") || strings.Contains(response.Body.String(), "good.example.test") {
		t.Fatalf("body=%s, 5xx 不得下发部分结果", response.Body.String())
	}
}

// 对照形状：全部行健康时照常 200 且行内容完整（fail-visible 不得变成有行即 500）。
func TestListCertificates_healthyRowsStillReturn200(t *testing.T) {
	h := newBackupTestHandlers(t)
	fakeDB(t, map[string]driver.Rows{
		"SELECT COUNT(*) FROM cert_jobs": &fakeQueryRows{values: [][]driver.Value{{int64(1)}}},
		"SELECT j.id": &fakeQueryRows{values: [][]driver.Value{
			// expires_at 取 NULL（列的真实空值形态）；空串不是 DATETIME 列的
			// 合法形态，会被 NullTime 扫描拒绝（与任务列表同口径）。
			{int64(1), "lb_good", "good.example.test", "issued", "", nil, "", ""},
		}},
	})
	router := gin.New()
	router.GET("/certificates", h.ListCertificates)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/certificates", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "good.example.test") {
		t.Fatalf("body=%s, want 正常行返回", response.Body.String())
	}
}

// assertCaddyOpLockFree 断言全局 Caddy 写锁当前空闲：TryLock 成功即证明
// DeleteCertJob 的该出口已配对释放（持锁泄漏会让后续规则/配置写与 Caddy
// 启停全部挂起，只能重启进程）。
func assertCaddyOpLockFree(t *testing.T, exit string) {
	t.Helper()
	if !services.CaddyOpLock.TryLock() {
		t.Fatalf("%s 出口后 caddyOpMu 仍被持有——DeleteCertJob 必须在所有出口释放全局写锁", exit)
	}
	services.CaddyOpLock.Unlock()
}

// DeleteCertJob 每个出口都必须释放 caddyOpMu：表驱动探针逐个出口断言
// TryLock 成功（成功路径、404、409、500 全覆盖）。
func TestDeleteCertJob_releasesCaddyOpLockOnEveryExit(t *testing.T) {
	seedActiveACMEJob := func(t *testing.T) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
			VALUES ('lb_lockprobe','lockprobe','http','lockprobe.example.test',8080,1,1,'acme_dns');
			INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_lockprobe','lockprobe.example.test','failed')`); err != nil {
			t.Fatalf("seed rule and job: %v", err)
		}
	}
	seedRetiredJob := func(t *testing.T) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status)
			VALUES ('lb_lockprobe_disabled','lockprobe.example.test','disabled')`); err != nil {
			t.Fatalf("seed retired job: %v", err)
		}
	}

	cases := []struct {
		name string
		url  string
		// setup 在夹具后运行（含钩子/触发器），返回期望状态码。
		setup func(t *testing.T) int
	}{
		{
			name: "200 deleted",
			url:  "/jobs/1",
			setup: func(t *testing.T) int {
				seedRetiredJob(t)
				return http.StatusOK
			},
		},
		{
			name: "404 job not found",
			url:  "/jobs/424242",
			setup: func(t *testing.T) int {
				return http.StatusNotFound
			},
		},
		{
			name: "409 guarded active rule",
			url:  "/jobs/1",
			setup: func(t *testing.T) int {
				seedActiveACMEJob(t)
				return http.StatusConflict
			},
		},
		{
			name: "409 state changed between read and flip",
			url:  "/jobs/1",
			setup: func(t *testing.T) int {
				seedRetiredJob(t)
				previous := deleteCertJobPreDisableHook
				deleteCertJobPreDisableHook = func(id int) {
					// worker 在 SELECT 与 disabled 翻转之间推进状态 → CAS 0 行。
					_, _ = db.DB.Exec("UPDATE cert_jobs SET status='validated' WHERE id=?", id)
				}
				t.Cleanup(func() { deleteCertJobPreDisableHook = previous })
				return http.StatusConflict
			},
		},
		{
			name: "404 row disappears before flip",
			url:  "/jobs/1",
			setup: func(t *testing.T) int {
				seedRetiredJob(t)
				previous := deleteCertJobPreDisableHook
				deleteCertJobPreDisableHook = func(id int) {
					_, _ = db.DB.Exec("DELETE FROM cert_jobs WHERE id=?", id)
				}
				t.Cleanup(func() { deleteCertJobPreDisableHook = previous })
				return http.StatusNotFound
			},
		},
		{
			name: "500 disable failure",
			url:  "/jobs/1",
			setup: func(t *testing.T) int {
				seedRetiredJob(t)
				if _, err := db.DB.Exec(`CREATE TRIGGER lockprobe_block_disable BEFORE UPDATE ON cert_jobs
					WHEN NEW.status='disabled' BEGIN SELECT RAISE(ABORT,'模拟禁用写失败'); END`); err != nil {
					t.Fatalf("install abort trigger: %v", err)
				}
				return http.StatusInternalServerError
			},
		},
		{
			name: "500 delete failure with recovery",
			url:  "/jobs/1",
			setup: func(t *testing.T) int {
				seedRetiredJob(t)
				if _, err := db.DB.Exec(`CREATE TRIGGER lockprobe_block_delete BEFORE DELETE ON cert_jobs
					BEGIN SELECT RAISE(ABORT,'模拟删除失败'); END`); err != nil {
					t.Fatalf("install abort trigger: %v", err)
				}
				return http.StatusInternalServerError
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assertCaddyOpLockFree(t, "前置")
			h := newBackupTestHandlers(t)
			wantStatus := tt.setup(t)
			router := gin.New()
			router.DELETE("/jobs/:id", h.DeleteCertJob)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, tt.url, nil))

			if response.Code != wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), wantStatus)
			}
			assertCaddyOpLockFree(t, tt.name)
		})
	}
}

// 临界区内发生 panic（钩子/运行时错误）时，defer 兜底必须释放全局写锁——
// 手动配对的下一次回归（新增出口忘记 Unlock）会在这里锁死整条 Caddy 写链。
func TestDeleteCertJob_releasesCaddyOpLockOnPanic(t *testing.T) {
	assertCaddyOpLockFree(t, "前置")
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status)
		VALUES ('lb_lockprobe_panic','panic.example.test','disabled')`); err != nil {
		t.Fatalf("seed retired job: %v", err)
	}
	previous := deleteCertJobPreDisableHook
	deleteCertJobPreDisableHook = func(int) { panic("模拟临界区内的运行时 panic") }
	t.Cleanup(func() { deleteCertJobPreDisableHook = previous })
	router := gin.New() // 无 Recovery 中间件：panic 直接上抛到测试
	router.DELETE("/jobs/:id", h.DeleteCertJob)

	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("期望 panic 上抛（夹具前提：无 Recovery 中间件）")
			}
		}()
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
	}()

	assertCaddyOpLockFree(t, "panic 展开")
}

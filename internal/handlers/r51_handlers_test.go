package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// R51 发现1（回归）：drain 超时 abort 路径下补偿已成功启动并接管租约，
// 处理程序返回后 defer 不得释放该租约——提前释放会让补偿 goroutine 的
// enqueueCompensation 见租约缺失而永久退避（每轮重新 drain+restore，
// 反复打断该规则合法签发）。租约必须由补偿 goroutine 自身在完成时释放。
func TestDeleteRule_keeps_block_lease_when_compensation_started_after_drain_timeout(t *testing.T) {
	// Given：drain 首次超时（abort），补偿 goroutine 的二次 drain 被测试闸住，
	// 保证处理程序返回时补偿仍在运行、尚未到达自释放点。
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_abort_lease", "abort-lease", "abort-lease.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_abort_lease")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldTimeout := cancelRuleJobsTimeout
	cancelRuleJobsTimeout = 10 * time.Millisecond
	t.Cleanup(func() { cancelRuleJobsTimeout = oldTimeout })
	oldCancel := cancelRuleJobs
	releaseCompensationDrain := make(chan struct{})
	var calls atomic.Int32
	cancelRuleJobs = func(ctx context.Context, _ *services.CAQueueManager, _ string) error {
		if calls.Add(1) == 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		<-releaseCompensationDrain
		return nil
	}
	t.Cleanup(func() { cancelRuleJobs = oldCancel })
	router := gin.New()
	router.DELETE("/rules/:caddy_id", handler.DeleteRule)
	response := httptest.NewRecorder()

	// When：drain 超时 → 补偿启动成功 → 处理程序返回 500，补偿仍在 drain 中。
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/rules/lb_abort_lease", nil))

	// Then：租约必须仍由补偿持有（规则保持屏障），不得被 defer 提前释放。
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("delete status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	manager := services.GetCAQueueManager()
	if !manager.IsRuleBlocked("lb_abort_lease") {
		t.Fatal("block lease released prematurely: compensation started after drain timeout but rule is not blocked")
	}

	// 补偿完成后租约由补偿自身释放（闭环验证：唯一属主转移而非丢失）。
	close(releaseCompensationDrain)
	deadline := time.Now().Add(2 * time.Second)
	for manager.IsRuleBlocked("lb_abort_lease") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if manager.IsRuleBlocked("lb_abort_lease") {
		t.Fatal("compensation did not release the lease after completion")
	}
}

// R51 发现1（panic 窗口）：drain 前/中 panic 时 gin Recovery 只恢复 HTTP 栈、
// 不清理 blockedRules——租约 defer 必须登记在 drain 之前，否则屏障滞留到下一次
// Stop，该规则证书任务被静默永久拦截。
func TestDeleteRule_releases_block_lease_when_drain_panics(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_drain_panic", "drain-panic", "drain-panic.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_drain_panic")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldCancel := cancelRuleJobs
	cancelRuleJobs = func(context.Context, *services.CAQueueManager, string) error {
		panic("drain exploded")
	}
	t.Cleanup(func() { cancelRuleJobs = oldCancel })
	router := gin.New()
	router.Use(gin.Recovery())
	router.DELETE("/rules/:caddy_id", handler.DeleteRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/rules/lb_drain_panic", nil))

	// Then：Recovery 返回 500，租约不得滞留
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("delete status=%d body=%s, want 500 from Recovery", response.Code, response.Body.String())
	}
	if services.GetCAQueueManager().IsRuleBlocked("lb_drain_panic") {
		t.Fatal("block lease leaked: drain panicked but rule stays blocked until Stop")
	}
}

// R51 发现3(a)：CreateRule 不得落库 enable_tls+acme_dns 而未选证书配置的规则——
// 该状态在主节点单规则损坏（签发按单任务失败），却会让从节点快照校验整包拒绝、
// 瘫痪整个集群同步。必须在写入侧 400 拒绝。
func TestCreateRule_rejects_acme_dns_without_certificate_config(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{"name":"acme-no-config","protocol":"http","domain":"no-config.example.test","listen_port":8080,"enable_tls":true,"tls_source":"acme_dns","upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DNS 提供商配置") {
		t.Fatalf("create status=%d body=%s, want 400 点名 DNS 提供商配置", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE domain='no-config.example.test'").Scan(&count); err != nil {
		t.Fatalf("read rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected rule persisted, count=%d", count)
	}
}

// R51 发现3(a)：UpdateRule 的 0=保留现值语义下，合并后生效状态为
// enable_tls+acme_dns 且 acme_config_id=0 时同样必须 400——覆盖
// 「切换到 acme_dns 但未选配置」与「存量坏规则（导入残留）被编辑」两种路径。
func TestUpdateRule_rejects_acme_dns_without_certificate_config(t *testing.T) {
	t.Run("switching to acme_dns without config", func(t *testing.T) {
		// Given：存量 manual 规则无证书配置，请求切换到 acme_dns 且不带 acme_config_id
		handler, _, _ := newAuditRuleHandlers(t, 0)
		seedAuditRule(t, "lb_switch_no_config", "before", "switch-no-config.example.test", 8080, true, "manual", false)
		seedAuditUpstream(t, "lb_switch_no_config")
		router := gin.New()
		router.PUT("/rules/:caddy_id", handler.UpdateRule)
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_switch_no_config", strings.NewReader(`{"enable_tls":true,"tls_source":"acme_dns"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()

		// When
		router.ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DNS 提供商配置") {
			t.Fatalf("update status=%d body=%s, want 400 点名 DNS 提供商配置", response.Code, response.Body.String())
		}
	})

	t.Run("editing imported bad rule keeps rejection visible", func(t *testing.T) {
		// Given：导入残留的坏规则（acme_dns + acme_config_id=0），请求只改名称
		//（0=保留现值合并后生效配置仍为 0，拒绝迫使用户显式修复坏状态）
		handler, _, _ := newAuditRuleHandlers(t, 0)
		seedAuditRule(t, "lb_bad_import_edit", "before", "bad-import.example.test", 8080, true, "acme_dns", true)
		seedAuditUpstream(t, "lb_bad_import_edit")
		router := gin.New()
		router.PUT("/rules/:caddy_id", handler.UpdateRule)
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_bad_import_edit", strings.NewReader(`{"name":"after"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()

		// When
		router.ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DNS 提供商配置") {
			t.Fatalf("update status=%d body=%s, want 400 点名 DNS 提供商配置", response.Code, response.Body.String())
		}
	})
}

// R51 发现3(a) 对照组：保留现值合并出非零配置时必须放行（0=保留现值语义不被误伤）。
func TestUpdateRule_allows_acme_dns_edit_when_config_preserved(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_preserved_config", 0, false)
	seedAuditRule(t, "lb_preserved_config", "before", "preserved.example.test", 8080, false, "acme_dns", true)
	seedAuditUpstream(t, "lb_preserved_config")
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=1 WHERE caddy_id='lb_preserved_config'"); err != nil {
		t.Fatalf("seed ACME config: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_preserved_config", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200（保留现值合并不应被误拒）", response.Code, response.Body.String())
	}
}

package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestUpdateRule_ReleasesBlockLeaseWhenCancelWindowPanics(t *testing.T) {
	// Given an enabled ACME rule whose certificate cancellation window panics.
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_update_lease_panic", "update-lease-panic", "update-lease-panic.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_update_lease_panic")
	acmeConfigID := seedR52CertificateConfig(t)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET acme_config_id=? WHERE caddy_id='lb_update_lease_panic'`, acmeConfigID); err != nil {
		t.Fatalf("bind acme config: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at)
		VALUES ('lb_update_lease_panic','update-lease-panic.example.test','issued','CERT-PEM','KEY-PEM',datetime('now','+30 days'))`); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)

	oldHook := updateRuleLockWindowHook
	updateRuleLockWindowHook = func(_ string, window int) {
		if window == 1 {
			panic("update cancel window exploded")
		}
	}
	t.Cleanup(func() { updateRuleLockWindowHook = oldHook })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	response := httptest.NewRecorder()

	// When gin recovers the request panic.
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_update_lease_panic", strings.NewReader(`{"enabled":false}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then the queue barrier must not outlive the failed request.
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("update status=%d body=%s, want 500 from gin.Recovery", response.Code, response.Body.String())
	}
	if services.GetCAQueueManager().IsRuleBlocked("lb_update_lease_panic") {
		t.Fatal("block lease leaked after update cancellation panic")
	}
}

// 域名迁移取消费窗口 panic 时，入口 defer 仍应只看到一次配对的 Unlock。
// 旧实现的裸 Unlock→cancel→Lock 会触发不可恢复的二次 Unlock fatal，因此用
// 子进程隔离验证；修复后 gin.Recovery 返回 500 且全局锁可再次获取。
func TestUpdateRule_domainMigrationCancelPanicRestoresLock(t *testing.T) {
	const helperEnv = "LB_TEST_DOMAIN_MIGRATION_CANCEL_PANIC"
	if os.Getenv(helperEnv) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestUpdateRule_domainMigrationCancelPanicRestoresLock$", "-test.count=1")
		command.Env = append(os.Environ(), helperEnv+"=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("domain migration panic helper failed: %v\n%s", err, output)
		}
		return
	}

	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedWindow2Rule(t, "lb_migration_lease_panic", "migration-panic", "migration-panic-old.example.test", 18015)
	startRuleLockWindowQueue(t)
	oldCancel := cancelCertJob
	cancelCertJob = func(int) { panic("domain migration cancel exploded") }
	t.Cleanup(func() { cancelCertJob = oldCancel })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	response := doPutUpdateRule(router, "lb_migration_lease_panic", `{"domain":"migration-panic-new.example.test"}`)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500 from gin.Recovery", response.Code, response.Body.String())
	}
	if !handler.caddyOpMu.TryLock() {
		t.Fatal("Caddy operation lock was not restored after migration cancellation panic")
	}
	handler.caddyOpMu.Unlock()
}

func TestDisableRule_ReleasesBlockLeaseWhenCancelWindowPanics(t *testing.T) {
	// Given an enabled ACME rule whose certificate cancellation window panics.
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_disable_lease_panic", "disable-lease-panic", "disable-lease-panic.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_disable_lease_panic")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)

	oldHook := disableRuleLockWindowHook
	disableRuleLockWindowHook = func(string) { panic("disable cancel window exploded") }
	t.Cleanup(func() { disableRuleLockWindowHook = oldHook })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.POST("/rules/:caddy_id/disable", handler.DisableRule)
	response := httptest.NewRecorder()

	// When gin recovers the request panic.
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_disable_lease_panic/disable", nil))

	// Then the queue barrier must not outlive the failed request.
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("disable status=%d body=%s, want 500 from gin.Recovery", response.Code, response.Body.String())
	}
	if services.GetCAQueueManager().IsRuleBlocked("lb_disable_lease_panic") {
		t.Fatal("block lease leaked after disable cancellation panic")
	}
}

// 正常路径：取消窗口结束（无 panic）后屏障必须已释放。租约收口到窗口内 defer
// 时最易犯的回归是把「窗口后释放」改成「只处理 panic」——那样每次成功更新/禁用
// 都会留下屏障，该规则续期被永久拦到下一次 Stop。
func TestRuleWriteLeases_releasedOnNormalCancelWindowExit(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		// Given：manual TLS 使「离开 ACME」分支打开取消窗口
		handler, _, _ := newAuditRuleHandlers(t, 0)
		seedAuditRule(t, "lb_update_lease_ok", "update-lease-ok", "update-lease-ok.example.test", 18021, true, "manual", false)
		seedAuditUpstream(t, "lb_update_lease_ok")
		startRuleLockWindowQueue(t)
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.PUT("/rules/:caddy_id", handler.UpdateRule)

		// When
		response := doPutUpdateRule(router, "lb_update_lease_ok", `{"name":"renamed"}`)

		// Then
		if response.Code != http.StatusOK {
			t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		if services.GetCAQueueManager().IsRuleBlocked("lb_update_lease_ok") {
			t.Fatal("block lease leaked on update success path")
		}
	})

	t.Run("disable", func(t *testing.T) {
		// Given
		handler, _, _ := newAuditRuleHandlers(t, 0)
		seedAuditRule(t, "lb_disable_lease_ok", "disable-lease-ok", "disable-lease-ok.example.test", 18022, true, "acme_dns", true)
		seedAuditUpstream(t, "lb_disable_lease_ok")
		startRuleLockWindowQueue(t)
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/rules/:caddy_id/disable", handler.DisableRule)
		response := httptest.NewRecorder()

		// When
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_disable_lease_ok/disable", nil))

		// Then
		if response.Code != http.StatusOK {
			t.Fatalf("disable status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		if services.GetCAQueueManager().IsRuleBlocked("lb_disable_lease_ok") {
			t.Fatal("block lease leaked on disable success path")
		}
	})
}

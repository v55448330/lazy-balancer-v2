package handlers

// 真实 /load 已发生后的并发/删除中止出口必须补「重载」审计：中止只跳过
// 补偿与成功收尾（LKG 补写/清横幅），不撤销「本次请求已经把配置下发到
// Caddy」这一事实。审计按操作日志重建配置变化时，缺失的重载行会让真实
// 下发从时间线上消失；反过来把中止当成功走 finalize 会清掉失败横幅并把
// 不合当前 DB 视图的载荷写进 LKG——两者不得混用。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// startRuleLockWindowQueue 装配队列管理器：放锁窗口只在队列管理器在场时打开。
func startRuleLockWindowQueue(t *testing.T) {
	t.Helper()
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
}

// reloadAuditRows 返回指定来源（渲染后的中文来源标签，如「更新规则」）的
// 「重载/Caddy服务」审计条数。
func reloadAuditRows(t *testing.T, sourceLabel string) int {
	t.Helper()
	var count int
	if err := db.AuditDB.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务' AND detail LIKE ?`,
		"%来源："+sourceLabel+"%").Scan(&count); err != nil {
		t.Fatalf("read reload audit: %v", err)
	}
	return count
}

// assertReloadAuditedOnce 断言中止请求留下了恰好一条对应来源的重载审计。
func assertReloadAuditedOnce(t *testing.T, sourceLabel string) {
	t.Helper()
	if got := reloadAuditRows(t, sourceLabel); got != 1 {
		t.Fatalf("重载审计=%d, want 1（真实 /load 已发生，冲突中止也必须留痕）", got)
	}
}

func assertNoSuccessAudit(t *testing.T, action string, want int) {
	t.Helper()
	var count int
	if err := db.AuditDB.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action=? AND resource='负载规则'`, action).Scan(&count); err != nil {
		t.Fatalf("read %s audit: %v", action, err)
	}
	if count != want {
		t.Fatalf("%s 审计=%d, want %d（冲突中止不得写成功留痕）", action, count, want)
	}
}

func doPutUpdateRule(router *gin.Engine, caddyID, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// seedWindow2Rule 播种「启用中 ACME 规则 + 已签发任务行」：域名迁移放锁窗口
// （window=2）只在存在证书任务行时打开。
func seedWindow2Rule(t *testing.T, caddyID, name, domain string, port int) {
	t.Helper()
	seedAuditRule(t, caddyID, name, domain, port, true, "acme_dns", true)
	seedAuditUpstream(t, caddyID)
	acmeConfigID := seedR52CertificateConfig(t)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET acme_config_id=? WHERE caddy_id=?`, acmeConfigID, caddyID); err != nil {
		t.Fatalf("bind acme config: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at)
		VALUES (?,?,'issued','CERT-PEM','KEY-PEM',datetime('now','+30 days'))`, caddyID, domain); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
}

// 第 1 个中止出口：UpdateRule 证书取消窗口内规则被并发删除。
func TestUpdateRule_reloadAuditedWhenRuleDeletedInCancelWindow(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_rl_w1_del", "rlw1del", "rlw1del.example.test", 18011, true, "manual", false)
	seedAuditUpstream(t, "lb_rl_w1_del")
	startRuleLockWindowQueue(t)
	updateRuleLockWindowHook = func(caddyID string, window int) {
		if window != 1 {
			return
		}
		if _, err := db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
			t.Errorf("delete rule in lock window: %v", err)
		}
	}
	t.Cleanup(func() { updateRuleLockWindowHook = nil })
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	response := doPutUpdateRule(router, "lb_rl_w1_del", `{"name":"mine"}`)

	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "已被删除") {
		t.Fatalf("status=%d body=%s, want 409 已被删除", response.Code, response.Body.String())
	}
	assertReloadAuditedOnce(t, "更新规则")
	assertNoSuccessAudit(t, "更新", 0)
}

// assertConcurrencyAbortSaysCommitted 断言并发复核的 409 与审计都点明「本次变更
// 已保存」：两条出口都在 commitTx 与真实 /load 之后，库与运行配置已是本请求结果，
// 「本次操作已中止」会让操作者以为什么都没落库。
func assertConcurrencyAbortSaysCommitted(t *testing.T, body, action string) {
	t.Helper()
	if !strings.Contains(body, "本次变更已保存") {
		t.Fatalf("body=%s, want 点明本次变更已保存且已应用", body)
	}
	if strings.Contains(body, "本次操作已中止") {
		t.Fatalf("body=%s, 不得声称本次操作已中止（提交与 /load 均已发生）", body)
	}
	var detail string
	if err := db.AuditDB.QueryRow(
		`SELECT detail FROM audit_log WHERE action=? AND resource='负载规则' ORDER BY id DESC LIMIT 1`, action).Scan(&detail); err != nil {
		t.Fatalf("read %s abort audit: %v", action, err)
	}
	if !strings.Contains(detail, "本次变更已保存") {
		t.Fatalf("审计 detail=%q, want 点明已保存", detail)
	}
}

// 第 2 个中止出口：UpdateRule 证书取消窗口内规则被并发修改。
func TestUpdateRule_reloadAuditedWhenConcurrentlyModifiedInCancelWindow(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_rl_w1_mod", "rlw1mod", "rlw1mod.example.test", 18012, true, "manual", false)
	seedAuditUpstream(t, "lb_rl_w1_mod")
	startRuleLockWindowQueue(t)
	updateRuleLockWindowHook = func(caddyID string, window int) {
		if window != 1 {
			return
		}
		if _, err := db.DB.Exec("UPDATE lb_rules SET name='concurrent' WHERE caddy_id = ?", caddyID); err != nil {
			t.Errorf("concurrent update in lock window: %v", err)
		}
	}
	t.Cleanup(func() { updateRuleLockWindowHook = nil })
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	response := doPutUpdateRule(router, "lb_rl_w1_mod", `{"name":"mine"}`)

	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "并发修改") {
		t.Fatalf("status=%d body=%s, want 409 并发修改", response.Code, response.Body.String())
	}
	assertConcurrencyAbortSaysCommitted(t, response.Body.String(), "更新失败")
	assertReloadAuditedOnce(t, "更新规则")
	assertNoSuccessAudit(t, "更新", 0)
}

// 第 3 个中止出口：UpdateRule 域名迁移取消窗口内规则被并发删除。
func TestUpdateRule_reloadAuditedWhenRuleDeletedInMigrationWindow(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedWindow2Rule(t, "lb_rl_w2_del", "rlw2del", "rlw2del-old.example.test", 18013)
	startRuleLockWindowQueue(t)
	updateRuleLockWindowHook = func(caddyID string, window int) {
		if window != 2 {
			return
		}
		if _, err := db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
			t.Errorf("delete rule in migration window: %v", err)
		}
	}
	t.Cleanup(func() { updateRuleLockWindowHook = nil })
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	response := doPutUpdateRule(router, "lb_rl_w2_del", `{"domain":"rlw2del-new.example.test"}`)

	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "已被删除") {
		t.Fatalf("status=%d body=%s, want 409 已被删除", response.Code, response.Body.String())
	}
	assertReloadAuditedOnce(t, "更新规则")
	assertNoSuccessAudit(t, "更新", 0)
}

// 第 4 个中止出口：UpdateRule 域名迁移取消窗口内规则被并发修改。
func TestUpdateRule_reloadAuditedWhenConcurrentlyModifiedInMigrationWindow(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedWindow2Rule(t, "lb_rl_w2_mod", "rlw2mod", "rlw2mod-old.example.test", 18014)
	startRuleLockWindowQueue(t)
	updateRuleLockWindowHook = func(caddyID string, window int) {
		if window != 2 {
			return
		}
		if _, err := db.DB.Exec("UPDATE lb_rules SET name='concurrent' WHERE caddy_id = ?", caddyID); err != nil {
			t.Errorf("concurrent update in migration window: %v", err)
		}
	}
	t.Cleanup(func() { updateRuleLockWindowHook = nil })
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	response := doPutUpdateRule(router, "lb_rl_w2_mod", `{"domain":"rlw2mod-new.example.test"}`)

	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "并发修改") {
		t.Fatalf("status=%d body=%s, want 409 并发修改", response.Code, response.Body.String())
	}
	assertConcurrencyAbortSaysCommitted(t, response.Body.String(), "更新失败")
	assertReloadAuditedOnce(t, "更新规则")
	assertNoSuccessAudit(t, "更新", 0)
}

// 第 5 个中止出口：DisableRule 证书取消窗口内规则被并发删除。
func TestDisableRule_reloadAuditedWhenRuleDeletedInLockWindow(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_rl_dis_del", "rldisdel", "rldisdel.example.test", 18015, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_rl_dis_del")
	startRuleLockWindowQueue(t)
	disableRuleLockWindowHook = func(caddyID string) {
		if _, err := db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
			t.Errorf("delete rule in lock window: %v", err)
		}
	}
	t.Cleanup(func() { disableRuleLockWindowHook = nil })
	router := gin.New()
	router.POST("/rules/:caddy_id/disable", handler.DisableRule)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_rl_dis_del/disable", nil))

	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "已被删除") {
		t.Fatalf("status=%d body=%s, want 409 已被删除", response.Code, response.Body.String())
	}
	assertReloadAuditedOnce(t, "禁用规则")
	assertNoSuccessAudit(t, "禁用", 0)
}

// 第 6 个中止出口：DisableRule 证书取消窗口内规则被并发修改（启用/更新）。
func TestDisableRule_reloadAuditedWhenConcurrentlyModifiedInLockWindow(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_rl_dis_mod", "rldismod", "rldismod.example.test", 18016, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_rl_dis_mod")
	startRuleLockWindowQueue(t)
	disableRuleLockWindowHook = func(caddyID string) {
		if _, err := db.DB.Exec("UPDATE lb_rules SET name='concurrent' WHERE caddy_id = ?", caddyID); err != nil {
			t.Errorf("concurrent update in lock window: %v", err)
		}
	}
	t.Cleanup(func() { disableRuleLockWindowHook = nil })
	router := gin.New()
	router.POST("/rules/:caddy_id/disable", handler.DisableRule)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_rl_dis_mod/disable", nil))

	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "并发修改") {
		t.Fatalf("status=%d body=%s, want 409 并发修改", response.Code, response.Body.String())
	}
	assertConcurrencyAbortSaysCommitted(t, response.Body.String(), "禁用失败")
	assertReloadAuditedOnce(t, "禁用规则")
	assertNoSuccessAudit(t, "禁用", 0)
}

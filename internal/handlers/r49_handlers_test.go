package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// R49 A-N1（drain 失败分支）：降级竞态下 Stop 已清空 blockedRules 后 block 才创建，
// drain 失败且补偿无法启动（manager 已停止）时租约必须当场释放——否则节点重新
// 提升后该规则的证书任务被屏障永久拦截，静默停发直到下一次 Stop。
func TestDeleteRule_releases_block_lease_when_compensation_start_fails_on_drain_failure(t *testing.T) {
	// Given：一条规则 + 已停止（模拟 BecomeSlave 完成降级）的 CA 队列管理器，
	// drain 被强制失败，使 StartRuleDeletionCompensation 命中 stopped 拒绝分支。
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_lease_drain", "lease-drain", "lease-drain.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_lease_drain")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	manager := services.GetCAQueueManager()
	manager.Stop()
	oldCancel := cancelRuleJobs
	cancelRuleJobs = func(_ context.Context, _ *services.CAQueueManager, _ string) error {
		return errors.New("drain refused")
	}
	t.Cleanup(func() { cancelRuleJobs = oldCancel })
	router := gin.New()
	router.DELETE("/rules/:caddy_id", handler.DeleteRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/rules/lb_lease_drain", nil))

	// Then：500 且租约已释放（补偿启动失败即无人持有该 token）
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("delete status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if manager.IsRuleBlocked("lb_lease_drain") {
		t.Fatal("block lease orphaned: compensation failed to start on stopped manager but rule stays blocked")
	}
}

// R49 A-N1（deferred 分支）：drain 成功（stopped manager 上 CancelJobsForRule 为
// 无操作返回 nil）后 Caddy 应用失败，deferred 补偿同样无法启动，租约必须释放，
// 规则与证书任务保持回滚后的原状。
func TestDeleteRule_releases_block_lease_when_compensation_start_fails_after_apply_failure(t *testing.T) {
	// Given：failedLoads=1 使 ApplyConfigFromTx 的首次 /load 被拒（恢复用的第二次放行）
	handler, _, _ := newAuditRuleHandlers(t, 1)
	seedAuditRule(t, "lb_lease_apply", "lease-apply", "lease-apply.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_lease_apply")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	manager := services.GetCAQueueManager()
	manager.Stop()
	router := gin.New()
	router.DELETE("/rules/:caddy_id", handler.DeleteRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/rules/lb_lease_apply", nil))

	// Then：删除回滚（规则保留）且租约已释放
	if response.Code != http.StatusBadRequest {
		t.Fatalf("delete status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	var ruleCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_lease_apply'").Scan(&ruleCount); err != nil {
		t.Fatalf("read preserved rule: %v", err)
	}
	if ruleCount != 1 {
		t.Fatalf("rule count=%d, want preserved after failed apply", ruleCount)
	}
	if manager.IsRuleBlocked("lb_lease_apply") {
		t.Fatal("block lease orphaned: deferred compensation failed to start on stopped manager but rule stays blocked")
	}
}

// R49 C-#2：security_policy_bindings 无外键，手造备份可绑定不存在的策略——导入后
// 该规则 WAF/限流/GeoIP 静默失效（loadSecurityPolicyContext 查不到策略即无策略渲染）。
// 导入前校验须 400 点名行号与悬挂 id，与保存侧「策略必须存在」同严。
func TestImportConfigBackup_rejects_security_policy_binding_with_dangling_policy(t *testing.T) {
	// Given：第 2 条绑定指向不存在的策略 99
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":          {{"caddy_id": "lb_bound", "name": "bound", "protocol": "http", "domain": "bound.example.test", "listen_port": 8080, "enabled": 1}},
		"security_policies": {{"id": 7, "name": "policy-7", "mode": "detection"}},
		"security_policy_bindings": {
			{"rule_caddy_id": "lb_bound", "policy_id": 7},
			{"rule_caddy_id": "lb_bound", "policy_id": 99},
		},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：400 点名表、行号与悬挂策略 id，且零写入（校验先于任何事务，
	// 拒绝时 lb_rules/security_policies/security_policy_bindings 均不得落库）
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	for _, want := range []string{"security_policy_bindings", "第 2 行", "99"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("rejection must name %q: %s", want, response.Body.String())
		}
	}
	// R50-N4：零写入断言扩充到校验涉及的全部表，固化「校验不过零写入」不变量
	for _, table := range []string{"lb_rules", "security_policies", "security_policy_bindings"} {
		var count int
		if err := db.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("rejected backup must not persist %s, got %d rows", table, count)
		}
	}
}

// R49 C-#2：悬挂 rule_caddy_id 同样拒绝；经预览端点验证 ValidateConfigImport
// 与导入路径同序继承该校验（Valid=false 而非预览放行、导入才 400）。
func TestValidateConfigImport_rejects_security_policy_binding_with_dangling_rule(t *testing.T) {
	// Given：绑定指向备份中不存在的规则 lb_ghost
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":                 {{"caddy_id": "lb_bound", "name": "bound", "protocol": "http", "domain": "bound.example.test", "listen_port": 8080, "enabled": 1}},
		"security_policies":        {{"id": 7, "name": "policy-7", "mode": "detection"}},
		"security_policy_bindings": {{"rule_caddy_id": "lb_ghost", "policy_id": 7}},
	})
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：预览 Valid=false 且点名行号与悬挂规则 id
	var envelope struct {
		Data importValidateResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode validation response: %v", err)
	}
	if envelope.Data.Valid {
		t.Fatalf("validation accepted dangling binding: %s", response.Body.String())
	}
	for _, want := range []string{"security_policy_bindings", "第 1 行", "lb_ghost"} {
		if !strings.Contains(envelope.Data.Error, want) {
			t.Fatalf("validation error must name %q: %q", want, envelope.Data.Error)
		}
	}
}

// R49 C-#2 对照组：引用完整的绑定导入成功并落库。
func TestImportConfigBackup_accepts_valid_security_policy_bindings(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":                 {{"caddy_id": "lb_bound", "name": "bound", "protocol": "http", "domain": "bound.example.test", "listen_port": 8080, "enabled": 1}},
		"security_policies":        {{"id": 7, "name": "policy-7", "mode": "detection"}},
		"security_policy_bindings": {{"rule_caddy_id": "lb_bound", "policy_id": 7}},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var policyID int
	if err := db.DB.QueryRow("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id='lb_bound'").Scan(&policyID); err != nil {
		t.Fatalf("read imported binding: %v", err)
	}
	if policyID != 7 {
		t.Fatalf("imported binding policy_id=%d, want 7", policyID)
	}
}

// R50-N1：空域名 HTTP 规则被软跳过时，其 security_policy_bindings 行（规则列名
// rule_caddy_id，与 upstreams/path_rules/cert_jobs 的 rule_id 不同）必须一并
// 跳过——skip 先于 validateBackupRuleReferences 执行，绑定若不随规则移除会命中
// 「引用了不存在的规则」整包 400，与 R38 C-3「软跳过+警告」语义冲突。
func TestImportConfigBackup_skips_bindings_of_empty_domain_rules(t *testing.T) {
	// Given：一条空域名 HTTP 规则带绑定，一条正常规则带绑定
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_empty_bound", "name": "empty-bound", "protocol": "http", "domain": "", "listen_port": 8451, "enabled": 1},
			{"caddy_id": "lb_valid_bound", "name": "valid-bound", "protocol": "http", "domain": "valid-bound.example.test", "listen_port": 8452, "enabled": 1},
		},
		"security_policies": {{"id": 7, "name": "policy-7", "mode": "detection"}},
		"security_policy_bindings": {
			{"rule_caddy_id": "lb_empty_bound", "policy_id": 7},
			{"rule_caddy_id": "lb_valid_bound", "policy_id": 7},
		},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：软跳过成功（200），空域名规则与其绑定一并丢弃并告警，正常规则与绑定落库
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 (soft-skip, not rejection)", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "域名为空") {
		t.Fatalf("import response missing skip warning: %s", response.Body.String())
	}
	// R51-C-2：绑定跳过警告文案必须同步断言——文案被误删/拼错时测试不得仍绿。
	if !strings.Contains(response.Body.String(), "安全策略绑定") {
		t.Fatalf("import response missing binding-skip warning: %s", response.Body.String())
	}
	var skippedRule, droppedBinding, keptBinding int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_empty_bound'").Scan(&skippedRule); err != nil {
		t.Fatalf("count skipped rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_empty_bound'").Scan(&droppedBinding); err != nil {
		t.Fatalf("count dropped bindings: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_valid_bound'").Scan(&keptBinding); err != nil {
		t.Fatalf("count kept bindings: %v", err)
	}
	if skippedRule != 0 || droppedBinding != 0 || keptBinding != 1 {
		t.Fatalf("after import: skipped-rule=%d dropped-binding=%d kept-binding=%d, want 0/0/1", skippedRule, droppedBinding, keptBinding)
	}
}

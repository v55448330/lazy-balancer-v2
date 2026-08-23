package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// newCustomRuleRouter 构造仅挂自定义规则更新端点的路由（R66 B-N1 测试用）。
func newCustomRuleRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.PUT("/security/custom-rules/:id", h.UpdateSecurityCustomRule)
	return router
}

// R66 B-N1：PUT /security/custom-rules/:id 省略 enabled 不得静默禁用规则——
// 指针部分更新语义（nil=保持现值），MCP 无约束 body 的部分更新不再把零值
// false 直写落库；显式 false 仍可正常禁用。
func TestUpdateSecurityCustomRule_partialUpdateKeepsEnabled(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ginRouter := newCustomRuleRouter(t)

	// Given 一条启用的自定义规则
	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, description, conditions, action, score, enabled) VALUES ('keep-enabled', '旧描述', '[{"target":"uri","operator":"contains","pattern":"a"}]', 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	id, _ := res.LastInsertId()

	put := func(body any) int {
		t.Helper()
		recorder := putJSON(t, ginRouter, fmt.Sprintf("/security/custom-rules/%d", id), body)
		return recorder.Code
	}

	// When 仅提交 name 的部分更新（MCP 部分更新形态，省略 enabled）
	if code := put(map[string]any{"name": "改名后"}); code != http.StatusOK {
		t.Fatalf("partial update status=%d, want 200", code)
	}

	// Then enabled 保持 1，name 已更新
	var enabled int
	var name string
	if err := db.DB.QueryRow("SELECT enabled, name FROM security_custom_rules WHERE id=?", id).Scan(&enabled, &name); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 {
		t.Fatalf("enabled=%d, want 1（省略不得静默禁用——WAF 拦截规则丢失且审计无痕迹）", enabled)
	}
	if name != "改名后" {
		t.Fatalf("name=%q, want 更新值", name)
	}

	// And 显式 enabled=false 正常禁用（合法操作不受阻）
	if code := put(map[string]any{"enabled": false}); code != http.StatusOK {
		t.Fatalf("explicit disable status=%d, want 200", code)
	}
	if err := db.DB.QueryRow("SELECT enabled FROM security_custom_rules WHERE id=?", id).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatalf("explicit disable enabled=%d, want 0", enabled)
	}

	// And 显式 enabled=true 恢复
	if code := put(map[string]any{"enabled": true}); code != http.StatusOK {
		t.Fatalf("re-enable status=%d, want 200", code)
	}
	if err := db.DB.QueryRow("SELECT enabled FROM security_custom_rules WHERE id=?", id).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 {
		t.Fatalf("re-enable enabled=%d, want 1", enabled)
	}
}

// R66 B-N1 契约补充：合并后的有效形态仍须过统一校验——省略字段不得成为
// 绕过 name/action/score/conditions 校验的通道（校验输入=现值+覆盖）。
func TestUpdateSecurityCustomRule_mergedShapeStillValidated(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ginRouter := newCustomRuleRouter(t)

	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('valid', '[{"target":"uri","operator":"contains","pattern":"a"}]', 'block', 5, 1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	// 显式提交非法 action 仍被 400 拒绝
	recorder := putJSON(t, ginRouter, fmt.Sprintf("/security/custom-rules/%d", id), map[string]any{"action": "invalid"})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid action status=%d, want 400", recorder.Code)
	}

	// 显式提交非法 score 仍被 400 拒绝
	recorder = putJSON(t, ginRouter, fmt.Sprintf("/security/custom-rules/%d", id), map[string]any{"score": 7})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid score status=%d, want 400", recorder.Code)
	}

	// 不存在的规则 404（原 200-then-404 语义保留）
	recorder = putJSON(t, ginRouter, "/security/custom-rules/99999", map[string]any{"name": "x"})
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing rule status=%d, want 404", recorder.Code)
	}
}

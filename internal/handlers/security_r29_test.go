package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func securityR29Router(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.DELETE("/security/custom-rules/:id", h.DeleteSecurityCustomRule)
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.PUT("/security/policies/:id", h.UpdateSecurityPolicy)
	return router
}

func TestDeleteSecurityCustomRule_rejectsWhenReferencedByEnabledPolicy(t *testing.T) {
	// Given：一条自定义规则被一个启用策略以 ID 数组引用
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)
	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('被引用规则', '[]', 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	ruleID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, custom_rules, enabled) VALUES ('引用策略', ?, 1)`, fmt.Sprintf("[%d]", ruleID)); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// When：删除被引用的规则
	recorder := deleteRequest(t, router, fmt.Sprintf("/security/custom-rules/%d", ruleID))

	// Then：409 拒绝并提示先解绑，规则保留
	if recorder.Code != http.StatusConflict {
		t.Fatalf("delete status=%d body=%s, want 409", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "该自定义规则正被 1 个启用的安全策略使用") {
		t.Fatalf("body=%s, want reference-count message", recorder.Body.String())
	}
	var rules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_custom_rules WHERE id=?", ruleID).Scan(&rules); err != nil {
		t.Fatal(err)
	}
	if rules != 1 {
		t.Fatalf("custom rule rows=%d, want 1（被引用时不得删除）", rules)
	}
}

func TestDeleteSecurityCustomRule_allowsDisabledOrEmbeddedReferences(t *testing.T) {
	// Given：规则甲仅被停用策略引用，规则乙仅被内嵌对象形状引用
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)
	seedRule := func(name string) int64 {
		t.Helper()
		res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES (?, '[]', 'block', 5, 1)`, name)
		if err != nil {
			t.Fatalf("seed rule %s: %v", name, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	disabledRuleID := seedRule("停用引用规则")
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, custom_rules, enabled) VALUES ('停用策略', ?, 0)`, fmt.Sprintf("[%d]", disabledRuleID)); err != nil {
		t.Fatalf("seed disabled policy: %v", err)
	}
	embeddedRuleID := seedRule("内嵌引用规则")
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, custom_rules, enabled) VALUES ('内嵌策略', '[{"id":1,"name":"x","enabled":true,"target":"uri","operator":"contains","pattern":"/x"}]', 1)`); err != nil {
		t.Fatalf("seed embedded policy: %v", err)
	}

	// When：删除两条规则
	// Then：均放行——停用策略不产生拦截配置，内嵌对象不构成 ID 引用
	for _, id := range []int64{disabledRuleID, embeddedRuleID} {
		recorder := deleteRequest(t, router, fmt.Sprintf("/security/custom-rules/%d", id))
		if recorder.Code != http.StatusOK {
			t.Fatalf("delete rule %d status=%d body=%s, want 200", id, recorder.Code, recorder.Body.String())
		}
	}
}

func TestCreateSecurityPolicy_rejectsNonexistentBlockPage(t *testing.T) {
	// Given：拦截页表为空（仅默认页 #1 由初始化种子写入）
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)

	// When：创建策略引用不存在的拦截页 999
	recorder := postJSON(t, router, "/security/policies", map[string]any{"name": "坏拦截页", "block_page_id": 999})

	// Then：400 拒绝并指出不存在的 id
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "拦截页面不存在") {
		t.Fatalf("body=%s, want 拦截页面不存在 message", recorder.Body.String())
	}
}

func TestCreateSecurityPolicy_rejectsNonexistentCustomRuleID(t *testing.T) {
	// Given：自定义规则表为空
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)

	// When：创建策略以 ID 数组引用不存在的规则 9999
	recorder := postJSON(t, router, "/security/policies", map[string]any{"name": "坏规则引用", "custom_rules": "[9999]"})

	// Then：400 拒绝并指出缺失的 id
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "自定义规则不存在") {
		t.Fatalf("body=%s, want 自定义规则不存在 message", recorder.Body.String())
	}

	// And：引用真实存在的规则时创建成功
	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('真实规则', '[]', 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	id, _ := res.LastInsertId()
	recorder = postJSON(t, router, "/security/policies", map[string]any{"name": "好规则引用", "custom_rules": fmt.Sprintf("[%d]", id)})
	if recorder.Code != http.StatusOK {
		t.Fatalf("valid create status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateSecurityPolicy_rejectsNonexistentReferences(t *testing.T) {
	// Given：一个已存在的策略
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)
	id := createTestPolicy(t, router, map[string]any{"name": "待更新引用"})

	// When：更新把 block_page_id 指向不存在的拦截页
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"block_page_id": 999})
	// Then：400 拒绝
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("update block_page_id status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "拦截页面不存在") {
		t.Fatalf("body=%s, want 拦截页面不存在 message", recorder.Body.String())
	}

	// When：更新把 custom_rules 指向不存在的规则
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"custom_rules": "[8888]"})
	// Then：400 拒绝
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("update custom_rules status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "自定义规则不存在") {
		t.Fatalf("body=%s, want 自定义规则不存在 message", recorder.Body.String())
	}
}

func TestCreateSecurityPolicy_geoipUnknownProvinceAllowedWhileCacheEmpty(t *testing.T) {
	// Given：ip2region 未加载（无缓存文件，GetCachedProvinces 仅返回 ["海外"]）
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)

	// When：创建策略使用任意非空省份名
	recorder := postJSON(t, router, "/security/policies", map[string]any{"name": "启动期省份", "geoip_countries": `["未知省"]`})

	// Then：放行——启动期无法判定条目归属，跳过成员校验只查非空，避免误拒
	if recorder.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateSecurityPolicy_normalizesEmptyCustomRulesToArray(t *testing.T) {
	// Given：一个已存在的策略
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)
	id := createTestPolicy(t, router, map[string]any{"name": "归一策略"})

	// When：显式传 custom_rules="" 更新
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"custom_rules": ""})

	// Then：200 且库内存储 "[]"（与 Create 口径一致，不落字面空串）
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT custom_rules FROM security_policies WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "[]" {
		t.Fatalf("stored custom_rules=%q, want \"[]\"", stored)
	}
}

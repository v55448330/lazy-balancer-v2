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

func TestCreateSecurityPolicy_geoipUnknownProvinceRejectedWhileCacheEmpty(t *testing.T) {
	// Given：ip2region 未加载（无缓存文件，live 与缓存兜底均只返回 ["海外"]）
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)

	// When：创建策略使用任意非空省份名
	recorder := postJSON(t, router, "/security/policies", map[string]any{"name": "启动期省份", "geoip_countries": `["未知省"]`})

	// Then：400 拒绝并提示未加载——fail-closed，避免 deny 模式地域拦截静默失效
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "未加载") {
		t.Fatalf("body=%s, want 未加载 message", recorder.Body.String())
	}
	// And（R72 二十七次 N5，用户裁决覆盖 R29 放行语义）："海外" 同样依赖 live
	// searcher 设置占位变量（缺库时 CEL 求值恒假、海外拦截零强制）——未加载
	// 时一并拒绝，待 IP 库更新后恢复。
	recorder = postJSON(t, router, "/security/policies", map[string]any{"name": "海外放行", "geoip_countries": `["海外"]`})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create 海外 status=%d body=%s, want 400（未加载时海外也拒绝）", recorder.Code, recorder.Body.String())
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

func TestUpdateSecurityPolicy_normalizesEmptyIPListsToArray(t *testing.T) {
	// Given：一个已存在的策略
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)
	id := createTestPolicy(t, router, map[string]any{"name": "归一 IP 列表"})

	// When：显式传三个 IP 列表字段为空串更新
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"ip_acl_list":  "",
		"ip_whitelist": "",
		"ip_blacklist": "",
	})

	// Then：200 且库内三个字段均存储 "[]"（与 Create/custom_rules 口径一致）
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	for _, col := range []string{"ip_acl_list", "ip_whitelist", "ip_blacklist"} {
		var stored string
		if err := db.DB.QueryRow(`SELECT `+col+` FROM security_policies WHERE id=?`, id).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != "[]" {
			t.Fatalf("stored %s=%q, want \"[]\"", col, stored)
		}
	}
}

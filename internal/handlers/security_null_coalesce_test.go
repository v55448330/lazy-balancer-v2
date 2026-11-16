package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// NULL 容忍残余：handler 端点裸扫描可空列，
// 一行 NULL → 该端点 500。本文件三测试分别钉住三处修复：
//   GetSecurityPolicyBindings 逐策略查询改用 securityPolicySelectColumns
//   DeleteSecurityCustomRule 引用检查 COALESCE(custom_rules,'[]')
//   List/Update 自定义规则与拦截页裸扫描列 COALESCE（对齐 cluster_snapshot dump 侧）

// newNullCoalesceRouter 注册本文件三测试所需的全部端点。
func newNullCoalesceRouter(t *testing.T) *gin.Engine {
	t.Helper()
	h := newFakeCaddyHandlers(t)
	router := gin.New()
	router.GET("/security/rules/:caddy_id/policy", h.GetSecurityPolicyBindings)
	router.GET("/security/custom-rules", h.ListSecurityCustomRules)
	router.PUT("/security/custom-rules/:id", h.UpdateSecurityCustomRule)
	router.DELETE("/security/custom-rules/:id", h.DeleteSecurityCustomRule)
	router.GET("/security/block-pages", h.ListSecurityBlockPages)
	router.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)
	router.DELETE("/security/block-pages/:id", h.DeleteSecurityBlockPage)
	return router
}

// GetSecurityPolicyBindings 的逐策略查询与 securityPolicySelectColumns
// 同 41 列但无 COALESCE——绑定策略任一可空列（如 description）为 NULL 时整列表 500。
// 修复后按常量投影返回 200 与该策略的默认值形态。
func TestGetSecurityPolicyBindings_nullPolicyColumnsReturn200(t *testing.T) {
	// Given：一条 HTTP 规则绑定一条 description（及其余可空列）为 NULL 的启用策略
	setupSecurityPolicyTestDB(t)
	router := newNullCoalesceRouter(t)
	seedHTTPRule(t, "lb_null_bind")
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, description, enabled) VALUES ('null策略', NULL, 1)`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_null_bind', ?)`, policyID); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// When：读取该规则的策略绑定列表
	recorder := getRequest(t, router, "/security/rules/lb_null_bind/policy")

	// Then：200 且返回该策略（可空列按 COALESCE 默认值呈现），不得 500
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET bindings status=%d body=%s, want 200（NULL 可空列不得拖垮整接口）", recorder.Code, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(strconv.FormatInt(policyID, 10))) {
		t.Fatalf("body=%s, want 含策略 #%d", recorder.Body.String(), policyID)
	}
}

// DeleteSecurityCustomRule 引用检查裸扫 custom_rules——任一启用
// 策略该列为 NULL 时扫描报错 500，全部自定义规则删除被阻断。修复后 COALESCE '[]'
// 落入既有的「不可解析→跳过」分支，删除按引用检查通过放行。
func TestDeleteSecurityCustomRule_nullCustomRulesPolicyDoesNot500(t *testing.T) {
	// Given：一条自定义规则 + 一条 custom_rules=NULL 的启用策略（不构成 ID 引用）
	setupSecurityPolicyTestDB(t)
	router := newNullCoalesceRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('待删规则', '[]', 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	ruleID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, custom_rules, enabled) VALUES ('null引用策略', NULL, 1)`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// When：删除该自定义规则
	recorder := deleteRequest(t, router, fmt.Sprintf("/security/custom-rules/%d", ruleID))

	// Then：引用检查通过（NULL 按 '[]' 处理、无 ID 引用），删除放行 200，不得 500
	if recorder.Code == http.StatusInternalServerError {
		t.Fatalf("delete status=500 body=%s（NULL custom_rules 不得阻断删除）", recorder.Body.String())
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}

// List/Update 自定义规则与拦截页的裸扫描可空列，一行 NULL →
// 对应端点 500。修复后四个端点对同一 NULL 种子行均不得 500（List 返默认值 200，
// Update 读-合并-写放行 200）。
func TestSecurityEntityEndpoints_nullColumnsDoNot500(t *testing.T) {
	// Given：一条 description/action 为 NULL 的自定义规则 + 一条 description/is_default
	// 为 NULL 的拦截页（action/is_default 的 NULL 是 Update 读路径今天 500 的根因；
	// conditions 保持有效数组使修复后 Update 合并结果通过校验返回 200）
	setupSecurityPolicyTestDB(t)
	router := newNullCoalesceRouter(t)
	ruleRes, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, description, conditions, action, score, enabled) VALUES ('null规则', NULL, '[{"target":"uri","operator":"contains","pattern":"/x"}]', NULL, 5, 1)`)
	if err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	ruleID, err := ruleRes.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	pageRes, err := db.DB.Exec(`INSERT INTO security_block_pages (name, description, content, is_default) VALUES ('null拦截页', NULL, NULL, NULL)`)
	if err != nil {
		t.Fatalf("seed block page: %v", err)
	}
	pageID, err := pageRes.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	// When/Then：四个端点均返回 200，且投影/落库值为 COALESCE 归一默认值
	//（仅排除 500 会放过「非 500 的任意错误码」与「零值悄悄丢字段」两种漂移）。
	listRules := getRequest(t, router, "/security/custom-rules")
	if listRules.Code != http.StatusOK {
		t.Fatalf("GET /security/custom-rules status=%d body=%s, want 200", listRules.Code, listRules.Body.String())
	}
	var rulesPayload struct {
		Data []models.SecurityCustomRule `json:"data"`
	}
	if err := json.Unmarshal(listRules.Body.Bytes(), &rulesPayload); err != nil {
		t.Fatalf("解析自定义规则列表: %v", err)
	}
	foundRule := false
	for _, rule := range rulesPayload.Data {
		if rule.ID != int(ruleID) {
			continue
		}
		foundRule = true
		if rule.Description != "" || rule.Action != "block" {
			t.Fatalf("NULL 列投影 description=%q action=%q, want \"\"/block（COALESCE 默认值）", rule.Description, rule.Action)
		}
	}
	if !foundRule {
		t.Fatalf("自定义规则列表未包含 #%d", ruleID)
	}

	listPages := getRequest(t, router, "/security/block-pages")
	if listPages.Code != http.StatusOK {
		t.Fatalf("GET /security/block-pages status=%d body=%s, want 200", listPages.Code, listPages.Body.String())
	}
	var pagesPayload struct {
		Data []models.SecurityBlockPage `json:"data"`
	}
	if err := json.Unmarshal(listPages.Body.Bytes(), &pagesPayload); err != nil {
		t.Fatalf("解析拦截页列表: %v", err)
	}
	foundPage := false
	for _, page := range pagesPayload.Data {
		if page.ID != int(pageID) {
			continue
		}
		foundPage = true
		if page.Description != "" || page.Content != "" || page.IsDefault {
			t.Fatalf("NULL 列投影 description=%q content=%q is_default=%v, want \"\"/\"\"/false",
				page.Description, page.Content, page.IsDefault)
		}
		if page.ContentType != models.DefaultBlockPageContentType {
			t.Fatalf("NULL content_type 投影=%q, want 默认 %q", page.ContentType, models.DefaultBlockPageContentType)
		}
	}
	if !foundPage {
		t.Fatalf("拦截页列表未包含 #%d", pageID)
	}

	if rec := putJSON(t, router, fmt.Sprintf("/security/custom-rules/%d", ruleID), map[string]any{"name": "null规则改名"}); rec.Code != http.StatusOK {
		t.Fatalf("PUT custom rule status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var ruleDescription, ruleAction sql.NullString
	if err := db.DB.QueryRow(`SELECT description, action FROM security_custom_rules WHERE id=?`, ruleID).Scan(&ruleDescription, &ruleAction); err != nil {
		t.Fatal(err)
	}
	// 读-合并-写必须把归一值落回库：NULL 不得继续留在列里（否则下次裸扫描
	// 的消费方仍会 500）。
	if !ruleDescription.Valid || ruleDescription.String != "" {
		t.Fatalf("自定义规则 description 落库=%v, want 非 NULL 空串", ruleDescription)
	}
	if !ruleAction.Valid || ruleAction.String != "block" {
		t.Fatalf("自定义规则 action 落库=%v, want 非 NULL \"block\"", ruleAction)
	}

	if rec := putJSON(t, router, fmt.Sprintf("/security/block-pages/%d", pageID), map[string]any{"name": "null拦截页改名", "content": "x"}); rec.Code != http.StatusOK {
		t.Fatalf("PUT block page status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var pageDescription, pageContent, pageContentType sql.NullString
	if err := db.DB.QueryRow(`SELECT description, content, content_type FROM security_block_pages WHERE id=?`, pageID).
		Scan(&pageDescription, &pageContent, &pageContentType); err != nil {
		t.Fatal(err)
	}
	if !pageDescription.Valid || pageDescription.String != "" {
		t.Fatalf("拦截页 description 落库=%v, want 非 NULL 空串", pageDescription)
	}
	if !pageContent.Valid || pageContent.String != "x" {
		t.Fatalf("拦截页 content 落库=%v, want \"x\"", pageContent)
	}
	if !pageContentType.Valid || pageContentType.String != models.DefaultBlockPageContentType {
		t.Fatalf("拦截页 content_type 落库=%v, want 非 NULL %q", pageContentType, models.DefaultBlockPageContentType)
	}
	// is_default 不在 Update 的可写字段面内：该列的 NULL 由列表投影的
	// COALESCE(is_default,0) 吸收（上面已断言投影为 false），此处不再要求落库归一。
}

// 事件列表投影补齐 COALESCE——rule_name/
// policy_name/duration_us/precheck_us/request_headers/request_body 均为可空
// 列（schema 仅 DEFAULT 无 NOT NULL），带外/异常写入显式 NULL 时旧实现整页 500。
func TestListSecurityEvents_nullProjectionColumnsReturn200(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events
		(event_time, client_ip, method, uri, event_type, rule_triggered, action,
		 rule_name, policy_name, duration_us, precheck_us, request_headers, request_body)
		VALUES ('2026-10-19 10:00:00', '93.184.216.9', 'GET', '/null', 'crs', '942100', 'blocked',
		 NULL, NULL, NULL, NULL, NULL, NULL)`); err != nil {
		t.Fatalf("seed null event: %v", err)
	}

	recorder := getRequest(t, router, "/security/events")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（NULL 可空列按零值投影）", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"total":1`) {
		t.Fatalf("body=%s, want total:1", recorder.Body.String())
	}
}

// handlers 侧投影 securityPolicySelectColumns 的人机/CC COALESCE 回退值必须
// 绑 db.Default* 治理常量（与 services/security.go securityPolicyRowColumns
// 的 TestSecurityPolicyRowColumns_bindsGovernedDefaults 同口径——该钉只解析
// services/security.go，不覆盖 handlers 本地副本）：私抄字面量会在 DDL
// DEFAULT/启动回填调整后与读侧静默分叉（UI 与引擎看到两套默认值）。
func TestSecurityPolicySelectColumns_bindsGovernedDefaults(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "security.go", nil, 0)
	if err != nil {
		t.Fatalf("parse security.go: %v", err)
	}
	seen := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		declared := false
		for _, name := range spec.Names {
			if name.Name == "securityPolicySelectColumns" {
				declared = true
			}
		}
		if !declared {
			return true
		}
		ast.Inspect(spec, func(inner ast.Node) bool {
			if sel, ok := inner.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "db" {
					seen[sel.Sel.Name] = true
				}
			}
			return true
		})
		return false
	})
	for _, want := range []string{
		"DefaultHumanVerifyType", "DefaultHumanVerifyTTL",
		"DefaultCCRPSLimit", "DefaultCCRPSWindow",
		"DefaultCC4xxRatio", "DefaultCCSessionUAThreshold",
	} {
		if !seen[want] {
			t.Fatalf("securityPolicySelectColumns 未绑定 db.%s（COALESCE 回退值私抄为字面量）", want)
		}
	}
	// 运行期形态仍须与常量同值（拼接/引号位置正确）。
	for _, want := range []string{
		"'" + db.DefaultHumanVerifyType + "'",
		strconv.Itoa(db.DefaultHumanVerifyTTL),
		strconv.Itoa(db.DefaultCCRPSLimit),
		strconv.Itoa(db.DefaultCCRPSWindow),
		strconv.Itoa(db.DefaultCC4xxRatio),
		strconv.Itoa(db.DefaultCCSessionUAThreshold),
	} {
		if !strings.Contains(securityPolicySelectColumns, want) {
			t.Fatalf("securityPolicySelectColumns 缺默认值形态 %q: %s", want, securityPolicySelectColumns)
		}
	}
}

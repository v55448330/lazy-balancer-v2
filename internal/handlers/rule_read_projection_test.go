package handlers

// 规则读投影（lbRuleColumns + scanLbRules，ListRules/GetRule/DuplicateRule/
// loadRulesForConfigValidation 共用）必须覆盖写侧 specs 全集业务列——写侧
// 加列而读投影漏改时，GET→PUT 回写与复制会静默丢列（认证网关四列曾缺席读
// 投影：UI 任意无关编辑把运行中的认证网关关闭、副本丢网关）。本文件把
// 「读投影列集 = services.LbRuleInsertColumns 全集」变成机械护栏（含负向
// 变异），并以真实往返钉住认证网关四列的读回形态。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// seedForwardAuthRule 直改 DB 写入一条认证网关启用的 HTTP 规则（保存链会
// 归一 uri/身份头，此处按写侧终态形态播种），返回规则模型供往返比对。
func seedForwardAuthRule(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,
		forward_auth_enabled,forward_auth_upstream,forward_auth_uri,forward_auth_copy_headers)
		VALUES ('lb_fa_read','fa-read','http','fa-read.example.test',13021,1,
		1,'http://gw.internal:7000','/verify','Remote-User,Remote-Email')`); err != nil {
		t.Fatalf("seed forward auth rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_fa_read','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
}

func getRuleResponse(t *testing.T, handler *Handlers, caddyID string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.GET("/rules/:caddy_id", handler.GetRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules/"+caddyID, nil))
	return response
}

// GetRule/ListRules 必须原样读回认证网关四列（读投影漏列时恒回零值：UI
// 表单显示「网关未启用」，任意无关编辑回写即静默关闭运行中的认证）。
func TestGetRule_roundTripsForwardAuthColumns(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedForwardAuthRule(t)

	response := getRuleResponse(t, handler, "lb_fa_read")
	if response.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var resp struct {
		Code int           `json:"code"`
		Data models.LbRule `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, response.Body.String())
	}
	if resp.Data.ForwardAuthEnabled != 1 {
		t.Fatalf("forward_auth_enabled=%d, want 1（读投影丢列会让编辑回写静默关闭网关）", resp.Data.ForwardAuthEnabled)
	}
	if resp.Data.ForwardAuthUpstream != "http://gw.internal:7000" {
		t.Fatalf("forward_auth_upstream=%q, want http://gw.internal:7000", resp.Data.ForwardAuthUpstream)
	}
	if resp.Data.ForwardAuthURI != "/verify" {
		t.Fatalf("forward_auth_uri=%q, want /verify", resp.Data.ForwardAuthURI)
	}
	if resp.Data.ForwardAuthCopyHeaders != "Remote-User,Remote-Email" {
		t.Fatalf("forward_auth_copy_headers=%q, want Remote-User,Remote-Email", resp.Data.ForwardAuthCopyHeaders)
	}

	// ListRules 走派生投影（lbRuleListColumns），同一扫描必须同样携带四列。
	router := gin.New()
	router.GET("/rules", handler.ListRules)
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, httptest.NewRequest(http.MethodGet, "/rules", nil))
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s, want 200", listResponse.Code, listResponse.Body.String())
	}
	var listResp struct {
		Code int             `json:"code"`
		Data []models.LbRule `json:"data"`
	}
	if err := json.Unmarshal(listResponse.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	var found bool
	for _, rule := range listResp.Data {
		if rule.CaddyID == "lb_fa_read" {
			found = true
			if rule.ForwardAuthEnabled != 1 || rule.ForwardAuthUpstream != "http://gw.internal:7000" ||
				rule.ForwardAuthURI != "/verify" || rule.ForwardAuthCopyHeaders != "Remote-User,Remote-Email" {
				t.Fatalf("list forward auth=%d/%q/%q/%q, want 1/网关地址/校验路径/身份头", rule.ForwardAuthEnabled,
					rule.ForwardAuthUpstream, rule.ForwardAuthURI, rule.ForwardAuthCopyHeaders)
			}
		}
	}
	if !found {
		t.Fatal("list response missing lb_fa_read")
	}
}

// 复制路径的启用预检与渲染分叉根治：副本必须携带认证网关四列（读投影丢列
// 时副本恒 0——网关被静默丢弃，未认证请求直达副本后端）。
func TestDuplicateRule_carriesForwardAuthColumns(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedForwardAuthRule(t)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", func(c *gin.Context) {
		c.Set("user_id", 1)
		handler.DuplicateRule(c)
	})
	request := httptest.NewRequest(http.MethodPost, "/rules/lb_fa_read/duplicate", nil)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK && response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s, want 2xx", response.Code, response.Body.String())
	}
	var enabled int
	var upstream, uri, headers string
	if err := db.DB.QueryRow(`SELECT COALESCE(forward_auth_enabled,0), COALESCE(forward_auth_upstream,''), COALESCE(forward_auth_uri,''), COALESCE(forward_auth_copy_headers,'')
		FROM lb_rules WHERE name='fa-read（副本）'`).Scan(&enabled, &upstream, &uri, &headers); err != nil {
		t.Fatalf("read duplicate rule: %v", err)
	}
	if enabled != 1 || upstream != "http://gw.internal:7000" || uri != "/verify" || headers != "Remote-User,Remote-Email" {
		t.Fatalf("duplicate forward auth=%d/%q/%q/%q, want 1/网关地址/校验路径/身份头（副本不得丢网关）", enabled, upstream, uri, headers)
	}
}

// 读投影列集机械护栏：与 services.LbRuleInsertColumns() 全集双向相等（无豁免——
// 读投影携带全部列含审计四列）；负向变异验证「临时删列必须被判定点名」。
func TestLbRuleReadProjection_parityWithInsertSpec(t *testing.T) {
	if gaps := lbRuleReadProjectionParityGaps(lbRuleReadProjectionColumns(), services.LbRuleInsertColumns()); len(gaps) != 0 {
		t.Fatalf("读投影全集断言失败: %v", gaps)
	}
	// 列表派生投影与完整投影同列集（仅证书两列置空占位）。
	if gaps := lbRuleReadProjectionParityGaps(lbRuleListProjectionColumns(), services.LbRuleInsertColumns()); len(gaps) != 0 {
		t.Fatalf("列表派生投影全集断言失败: %v", gaps)
	}

	// 负向变异：临时删列 → 判定必须点名缺失列（init panic 用同一判定）。
	mutated := lbRuleReadProjectionColumns()
	for i, column := range mutated {
		if column == "forward_auth_enabled" {
			mutated = append(mutated[:i], mutated[i+1:]...)
			break
		}
	}
	gaps := lbRuleReadProjectionParityGaps(mutated, services.LbRuleInsertColumns())
	if len(gaps) == 0 {
		t.Fatal("临时删列未被全集断言捕获")
	}
	if !strings.Contains(strings.Join(gaps, "；"), "forward_auth_enabled") {
		t.Fatalf("断言未点名缺失列: %v", gaps)
	}
}

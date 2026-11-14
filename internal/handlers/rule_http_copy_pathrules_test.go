package handlers

// HTTP 复制对「自定义路由开关=0 + 残留 path_rules」的带外行必须自愈
//（TCP 分支已无条件清空 PathRules，HTTP 分支此前缺失）：残留行原样进入
// validateRuleFeatures 的「自定义路径规则未启用，不能提交路径规则」门 →
// 复制恒 400 死端，用户看不到该字段、无自救路径。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestDuplicateRule_httpCopyClearsResidualPathRulesWhenSwitchOff(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	// Given：HTTP 源行 custom_routes_enabled=0 但带外残留 path_rules。
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,custom_routes_enabled)
		VALUES ('lb_httproutesoff','http-routes-off','','http','routesoff.test',18840,'weighted_round_robin',1,0)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_httproutesoff','up.test',80,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path) VALUES ('lb_httproutesoff',0,'prefix','/api','/v1')`); err != nil {
		t.Fatalf("seed residual path rule: %v", err)
	}

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_httproutesoff/duplicate", nil))

	// Then：复制成功（残留行被清空，不进保存门），副本不携带路径规则。
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201（switch=0 残留 path_rules 必须自愈，不得 400 死端）", response.Code, response.Body.String())
	}
	var copyID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name='http-routes-off（副本）'`).Scan(&copyID); err != nil {
		t.Fatalf("read copy: %v", err)
	}
	var pathCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id=?`, copyID).Scan(&pathCount); err != nil {
		t.Fatal(err)
	}
	if pathCount != 0 {
		t.Fatalf("副本携带 %d 条路径规则（switch=0 不得复制残留行）", pathCount)
	}
	// 源行残留不被改写（复制只投影，不动源）。
	var srcCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_httproutesoff'`).Scan(&srcCount); err != nil {
		t.Fatal(err)
	}
	if srcCount != 1 {
		t.Fatalf("源行残留被改写: %d, want 1", srcCount)
	}
}

// 对照：switch=1 的合法路径规则必须原样复制（自愈不得误伤正常形态）。
func TestDuplicateRule_httpCopyKeepsPathRulesWhenSwitchOn(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,custom_routes_enabled)
		VALUES ('lb_httprouteson','http-routes-on','','http','routeson.test',18841,'weighted_round_robin',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_httprouteson','up.test',80,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path) VALUES ('lb_httprouteson',0,'prefix','/api','/v1')`); err != nil {
		t.Fatalf("seed path rule: %v", err)
	}

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_httprouteson/duplicate", nil))
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var copyID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name='http-routes-on（副本）'`).Scan(&copyID); err != nil {
		t.Fatalf("read copy: %v", err)
	}
	var pathCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id=?`, copyID).Scan(&pathCount); err != nil {
		t.Fatal(err)
	}
	if pathCount != 1 {
		t.Fatalf("switch=1 副本路径规则=%d, want 1（正常形态必须原样复制）", pathCount)
	}
}

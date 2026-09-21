package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"

	"github.com/gin-gonic/gin"
)

// 上游 path 改写校验切片：非空时须以 / 开头且不含空格与 ? #（query/fragment
// 不允许），违规 400；空串放行（原样转发，现状语义）。
func TestValidateRuleFeatures_upstreamPath(t *testing.T) {
	tests := []struct {
		name         string
		upstreamPath string
		wantError    string
	}{
		{name: "missing leading slash", upstreamPath: "v1", wantError: "上游 path 必须以 / 开头"},
		{name: "query character", upstreamPath: "/v1?x=1", wantError: "上游 path 不能包含空格 ? # 字符"},
		{name: "fragment character", upstreamPath: "/v1#frag", wantError: "上游 path 不能包含空格 ? # 字符"},
		{name: "space character", upstreamPath: "/v 1", wantError: "上游 path 不能包含空格 ? # 字符"},
		{name: "valid path", upstreamPath: "/v1", wantError: ""},
		{name: "empty passes", upstreamPath: "", wantError: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := ruleFeatureInput{
				Protocol:            "http",
				CustomRoutesEnabled: true,
				PathRules: []models.PathRule{{
					MatchType:    "prefix",
					Path:         "/api",
					UpstreamPath: test.upstreamPath,
					Upstreams:    []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 9090, Weight: 1}},
				}},
			}

			err := validateRuleFeatures(input)

			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateRuleFeatures() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateRuleFeatures() error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}

func TestUpdateRule_upstreamPath_invalidRejected400_validPersistedAndEchoed(t *testing.T) {
	// Given
	handler, postedConfig := newRuleFeatureTestHandlersWithCapture(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress) VALUES ('lb_uppath','uppath','','http','uppath.example.test',8080,'weighted_round_robin','',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_uppath','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	router.GET("/rules/:caddy_id", handler.GetRule)

	// When：非法 upstream_path（缺 / 前缀）
	invalid := httptest.NewRequest(http.MethodPut, "/rules/lb_uppath",
		strings.NewReader(`{"custom_routes_enabled":true,"path_rules":[{"sort_order":0,"match_type":"prefix","path":"/api","upstream_path":"v1","upstreams":null}]}`))
	invalid.Header.Set("Content-Type", "application/json")
	invalidResponse := httptest.NewRecorder()
	router.ServeHTTP(invalidResponse, invalid)

	// Then：400 且零写入
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid upstream_path status=%d body=%s, want 400", invalidResponse.Code, invalidResponse.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_uppath'`).Scan(&count); err != nil {
		t.Fatalf("count path rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("invalid save must not write rows, got %d", count)
	}

	// When：合法 upstream_path
	valid := httptest.NewRequest(http.MethodPut, "/rules/lb_uppath",
		strings.NewReader(`{"custom_routes_enabled":true,"path_rules":[{"sort_order":0,"match_type":"prefix","path":"/api","upstream_path":"/v1","upstreams":null}]}`))
	valid.Header.Set("Content-Type", "application/json")
	validResponse := httptest.NewRecorder()
	router.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusOK {
		t.Fatalf("valid upstream_path status=%d body=%s", validResponse.Code, validResponse.Body.String())
	}

	// Then：落库存活
	var stored string
	if err := db.DB.QueryRow(`SELECT upstream_path FROM path_rules WHERE rule_id='lb_uppath'`).Scan(&stored); err != nil {
		t.Fatalf("read upstream_path: %v", err)
	}
	if stored != "/v1" {
		t.Fatalf("stored upstream_path=%q, want /v1", stored)
	}

	// Then：详情回读回显
	detail := httptest.NewRequest(http.MethodGet, "/rules/lb_uppath", nil)
	detailResponse := httptest.NewRecorder()
	router.ServeHTTP(detailResponse, detail)
	if detailResponse.Code != http.StatusOK {
		t.Fatalf("get rule status=%d body=%s", detailResponse.Code, detailResponse.Body.String())
	}
	var payload struct {
		Data struct {
			PathRules []models.PathRule `json:"path_rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(detailResponse.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode rule detail: %v", err)
	}
	if len(payload.Data.PathRules) != 1 || payload.Data.PathRules[0].UpstreamPath != "/v1" {
		t.Fatalf("rule detail upstream_path=%+v, want /v1", payload.Data.PathRules)
	}

	// Then：渲染配置携带改写 handler（回归钉，引擎实证另附）
	if !strings.Contains(*postedConfig, `"uri":"/v1{http.request.uri}"`) {
		t.Fatalf("posted Caddy config missing upstream path rewrite: %s", *postedConfig)
	}
}

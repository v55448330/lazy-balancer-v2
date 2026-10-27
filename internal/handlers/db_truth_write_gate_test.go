package handlers

// 库值唯一真相（批 1+2）写侧门钉测：类型①值型字段 0/空 → 400（前端表单
// 初值=默认，清空提交被拦）；类型②省略型（upstream_keepalive_timeout 0=继承
// Caddy/Go Transport 默认 2 分钟，用户裁定）仅拒负数。导入/快照链归一门
// 见 config_backup/cluster_apply（传输归一 normalizeRuleForTransport 由
// services 侧 TestSnapshot_rulesInvalidHealthColumns_normalizedByTransportGate 钉测）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func truthSettingsRouter(t *testing.T) (*gin.Engine, *Handlers) {
	t.Helper()
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	return router, handler
}

func TestUpdateConfig_rejectsZeroValueTypedGlobals(t *testing.T) {
	router, _ := truthSettingsRouter(t)
	cases := []struct {
		name string
		body string
		hint string
	}{
		{"request_body_max_size_mb", `{"request_body_max_size_mb":0}`, "1-1024"},
		{"http_read_timeout", `{"http_read_timeout":0}`, "http_read_timeout"},
		{"http_write_timeout", `{"http_write_timeout":0}`, "http_write_timeout"},
		{"http_idle_timeout", `{"http_idle_timeout":0}`, "http_idle_timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("%s=0 must 400, got %d body=%s", tc.name, response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), tc.hint) {
				t.Fatalf("body %s must mention %q", response.Body.String(), tc.hint)
			}
		})
	}
}

func TestUpdateConfig_keepaliveZeroStillOmissionSemantics(t *testing.T) {
	// 类型②回归钉：upstream_keepalive_timeout=0 是合法库值（省略=引擎默认）
	router, _ := truthSettingsRouter(t)
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"upstream_keepalive_timeout":0}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("keepalive=0 must stay legal (type-② omission), got %d body=%s", response.Code, response.Body.String())
	}
}

func TestCreateRule_rejectsZeroHealthColumns(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	cases := []struct {
		name string
		body string
		hint string
	}{
		{"interval", `{"name":"zero-hc","protocol":"tcp","listen_port":17501,"health_check_interval":0,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, "间隔"},
		{"timeout", `{"name":"zero-hc","protocol":"tcp","listen_port":17502,"health_check_interval":10,"health_check_timeout":0,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, "超时"},
		{"unhealthy", `{"name":"zero-hc","protocol":"tcp","listen_port":17503,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":0,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, "失败阈值"},
		{"healthy", `{"name":"zero-hc","protocol":"tcp","listen_port":17504,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":0,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, "恢复阈值"},
		{"try_interval", `{"name":"zero-hc","protocol":"tcp","listen_port":17505,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"tcp_try_duration":3000,"tcp_try_interval":0,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, "重试间隔"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("%s=0 must 400, got %d body=%s", tc.name, response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), tc.hint) {
				t.Fatalf("body %s must mention %q", response.Body.String(), tc.hint)
			}
		})
	}
}

func TestV2ImportBackfillsInvalidRuleAndGlobalColumns(t *testing.T) {
	// 导入归一门：旧备份行级 0 值与全局 0 值在 validateV2BackupRules/钳制链
	// 写回归治理默认（restoreTable 直写后库恒有效）。
	tables := map[string][]map[string]any{
		"lb_rules": {
			{
				"caddy_id": "lb_imp_truth", "name": "imp", "protocol": "http", "domain": "imp-truth.test", "listen_port": int64(19601),
				"health_check_interval": int64(0), "health_check_timeout": int64(0),
				"health_check_unhealthy_threshold": int64(0), "health_check_healthy_threshold": int64(0),
				"tcp_try_interval": int64(0),
			},
		},
	}
	if err := validateV2BackupRules(tables); err != nil {
		t.Fatalf("import validation must normalize-and-pass: %v", err)
	}
	row := tables["lb_rules"][0]
	if row["health_check_interval"] != int64(10) || row["health_check_timeout"] != int64(2) ||
		row["health_check_unhealthy_threshold"] != int64(3) || row["health_check_healthy_threshold"] != int64(2) ||
		row["tcp_try_interval"] != int64(250) {
		t.Fatalf("rule row not backfilled to governed defaults: %v", row)
	}
}

func TestUpdateRuleExplicitZeroThresholdRejected(t *testing.T) {
	// UpdateRule：指针阈值列 nil=沿用存量（合法），显式 0=直达 <1 门 400。
	handler, caddyID := newUpdateAuditRuleHandlersForTruth(t)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(`{"health_check_unhealthy_threshold":0}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("explicit zero threshold must 400, got %d body=%s", response.Code, response.Body.String())
	}
}

// newUpdateAuditRuleHandlersForTruth 复用审计域 seed 形态（启用规则+上游）。
func newUpdateAuditRuleHandlersForTruth(t *testing.T) (*Handlers, string) {
	t.Helper()
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedAuditRule(t, "lb_truth_upd", "truth-upd", "truth-upd.example.test", 19602, true, "manual", false)
	seedAuditUpstream(t, "lb_truth_upd")
	return handler, "lb_truth_upd"
}

package handlers

// LBS-A-L1（第 69 轮 P1）：HTTP 规则混合 http/https 上游池在 Caddy 无逐上游
// 协议概念（shouldUseTLS 传输级+except_ports 例外表，v2.11.6 httptransport.go:
// 674-680）——任一 https 上游使池级 TLS 传输生效，http 上游明文打 TLS 端口
// 静默全灭 502。保存/导入侧显式拒绝混布（用户裁定修法①）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRulePayload_rejectsMixedHttpHttpsUpstreamPool(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	cases := []struct {
		name      string
		upstreams string
		wantCode  int
	}{
		{"混合 http+https 拒绝", `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":true}]`, http.StatusBadRequest},
		{"纯 http 池放行（回归）", `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8081,"protocol":"http","enabled":true}]`, http.StatusCreated},
		{"纯 https 池放行（回归）", `[{"host":"10.0.0.1","port":8443,"protocol":"https","enabled":true},{"host":"10.0.0.2","port":8444,"protocol":"https","enabled":true}]`, http.StatusCreated},
		{"单 https 上游放行（回归）", `[{"host":"10.0.0.1","port":8443,"protocol":"https","enabled":true}]`, http.StatusCreated},
		{"混合但 https 上游禁用放行（禁用不参与渲染）", `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":false}]`, http.StatusCreated},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"name":"mixpool-%d","protocol":"http","domain":"mix-%d.test","listen_port":%d,"upstreams":%s}`,
				i, i, 19300+i, tc.upstreams)
			req := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status=%d, want %d; body=%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantCode == http.StatusBadRequest && !strings.Contains(rec.Body.String(), "协议") {
				t.Fatalf("body must mention 协议, got %s", rec.Body.String())
			}
		})
	}
}

// 备份侧同门（R62 C3-F2 同位）：手造备份带混布池须 400。
func TestValidateBackupRuleReferences_rejectsMixedHttpHttpsPool(t *testing.T) {
	tables := map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_mixbak", "protocol": "http"}},
		"upstreams": {
			{"rule_id": "lb_mixbak", "protocol": "http", "enabled": true},
			{"rule_id": "lb_mixbak", "protocol": "https", "enabled": true},
		},
	}
	err := validateBackupRuleReferences(tables)
	if err == nil || !strings.Contains(err.Error(), "混布") && !strings.Contains(err.Error(), "混合") {
		t.Fatalf("mixed pool backup must be rejected, got %v", err)
	}
}

// 同族（路径规则自定义上游池，R-12 收敛面）：路径级自定义上游混布同样拒绝。
func TestRulePayload_rejectsMixedPathRuleUpstreamPool(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	body := `{"name":"mixpath","protocol":"http","domain":"mixpath.test","listen_port":19320,"custom_routes_enabled":true,` +
		`"upstreams":[{"host":"10.0.0.1","port":9000,"enabled":true}],` +
		`"path_rules":[{"sort_order":0,"match_type":"prefix","path":"/api/","upstreams":[` +
		`{"address":"10.0.0.1","port":8080,"protocol":"http"},{"address":"10.0.0.2","port":8443,"protocol":"https"}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "混布") {
		t.Fatalf("path-rule mixed pool must 400, got %d %s", rec.Code, rec.Body.String())
	}
}

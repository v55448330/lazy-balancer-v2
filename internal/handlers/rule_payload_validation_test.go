package handlers

// host_header 字符校验(CRLF/控制字符注入
// reverse_proxy 头部)、dns_server 形状校验(空 host/非数字端口)、
// services.ExtractMetricLabel 精确键匹配(x_host 不得误归集 host)。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func TestRulePayload_hostHeaderAndDnsServerValidation(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	base := func(extra string) string {
		return `{"name":"payload-v","protocol":"http","domain":"payload.test","listen_port":18582,` +
			`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,` +
			`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],` + extra + `}`
	}
	create := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	// 形状一:host_header 含 CRLF → 400
	rec := create(base(`"host_header":"evil.com\r\nX-Injected: 1"`))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "后端域名含非法字符") {
		t.Fatalf("CRLF host_header must 400, got %d %s", rec.Code, rec.Body.String())
	}

	// 形状二:垃圾 dns_server(非数字端口) → 400
	rec = create(base(`"dynamic_dns":true,"dns_server":"8.8.8.8:notaport"`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage dns_server must 400, got %d %s", rec.Code, rec.Body.String())
	}
	// 拒绝必须零落库：动态 DNS 行带着不可用解析器进库会让渲染期静默降级。
	var rejectedRows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name='payload-v'`).Scan(&rejectedRows); err != nil {
		t.Fatalf("count rejected rows: %v", err)
	}
	if rejectedRows != 0 {
		t.Fatalf("rejected dns_server payload rows=%d, want 0", rejectedRows)
	}

	// 形状三(回归):合法形状放行
	rec = create(base(`"host_header":"api.backend.local"`))
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("legit host_header must pass, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestExtractLabel_exactKeyMatch(t *testing.T) {
	// x_host 不得被 host 子串匹配误归集
	if got := services.ExtractMetricLabel(`caddy_http_requests_total{x_host="evil"}`, "host"); got != "" {
		t.Fatalf("host label must not match x_host, got %q", got)
	}
	if got := services.ExtractMetricLabel(`caddy_http_requests_total{x_host="evil",host="real"}`, "host"); got != "real" {
		t.Fatalf("host label must match exact key, got %q", got)
	}
	if got := services.ExtractMetricLabel(`caddy_http_requests_total{host="first",x_host="evil"}`, "host"); got != "first" {
		t.Fatalf("leading host label must match, got %q", got)
	}
	if got := services.ExtractMetricLabel(`caddy_http_requests_total{x_host="evil"}`, "x_host"); got != "evil" {
		t.Fatalf("x_host label must match its own key, got %q", got)
	}
}

// 共享保存门收录 tls_source 白名单与 request_body_max_size_mb 值域
// ——新增写路径只调共享门也不得落库跨模式 TLS 形态/越界值。
func TestRulePayloadSaveGateRejectsTLSSourceAndBodyLimit(t *testing.T) {
	h := newBackupTestHandlers(t)
	valid := func() models.CreateRuleRequest {
		return models.CreateRuleRequest{
			Name: "gate", Protocol: "http", Domain: "gate.example.test", ListenPort: 8443,
			Strategy: "weighted_round_robin", HealthCheckPath: "/", HealthCheckInterval: 10,
			HealthCheckTimeout: 2, HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2,
			Upstreams: []models.Upstream{{Host: "127.0.0.1", Port: 9000, Weight: 1, Enabled: true, Protocol: "http"}},
		}
	}

	baseline := valid()
	if err := h.validateRulePayloadBeforeSave(baseline); err != nil {
		t.Fatalf("基线载荷应通过共享门: %v", err)
	}

	badSource := valid()
	badSource.EnableTLS = true
	badSource.TLSSource = "https"
	if err := h.validateRulePayloadBeforeSave(badSource); err == nil || !strings.Contains(err.Error(), "证书来源") {
		t.Fatalf("tls_source=https 应被共享门拒绝, err=%v", err)
	}

	badBody := valid()
	badBody.RequestBodyMaxSizeMB = 1025
	if err := h.validateRulePayloadBeforeSave(badBody); err == nil || !strings.Contains(err.Error(), "0-1024") {
		t.Fatalf("request_body_max_size_mb=1025 应被共享门拒绝, err=%v", err)
	}
	boundary := valid()
	boundary.RequestBodyMaxSizeMB = 1024
	if err := h.validateRulePayloadBeforeSave(boundary); err != nil {
		t.Fatalf("request_body_max_size_mb=1024 应被接受: %v", err)
	}
}

func TestUpdateConfigRequest_bodyLimitMatchesEngineMaximum(t *testing.T) {
	for _, value := range []int{1024, 512} {
		req := models.UpdateConfigRequest{RequestBodyMaxSizeMB: &value}
		if err := validateUpdateConfigRequest(&req); err != nil {
			t.Fatalf("global request_body_max_size_mb=%d rejected: %v", value, err)
		}
	}
	for _, value := range []int{0, 1025, 4096} {
		req := models.UpdateConfigRequest{RequestBodyMaxSizeMB: &value}
		if err := validateUpdateConfigRequest(&req); err == nil || !strings.Contains(err.Error(), "1-1024") {
			t.Fatalf("global request_body_max_size_mb=%d error=%v, want 1-1024 rejection", value, err)
		}
	}
}

// DNS 服务器 host 不得「含点即 FQDN」——非法字符保存即拒。
func TestValidateSingleDnsAddress_rejectsIllegalHostCharacters(t *testing.T) {
	for _, bad := range []string{"a!b.example.com", "x/y.example.com", "dns example.com", `dns"bad.example.com`, "a:b:c"} {
		if err := validateSingleDnsAddress(bad); err == nil {
			t.Errorf("validateSingleDnsAddress(%q)=nil, want error", bad)
		}
	}
	for _, good := range []string{"8.8.8.8", "8.8.8.8:53", "dns.example.com", "dns.example.com:5353", "[2001:db8::1]:53", "localhost"} {
		if err := validateSingleDnsAddress(good); err != nil {
			t.Errorf("validateSingleDnsAddress(%q)=%v, want nil", good, err)
		}
	}
}

// 值域枚举门不得按「消费开关」条件生效：关闭态落库的非法 dns_family /
// compress_types / tls_source 渲染零消费，却会随导出/备份/集群快照放大，并在
// 用户后续只切换开关时命中指向本次未提交字段的 400。空值放行（写侧归默认）。
func TestRuleEnumGates_applyRegardlessOfConsumerSwitch(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	create := func(port int, extra string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"name":"enum-%d","protocol":"http","domain":"enum%d.test","listen_port":%d,`+
			`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,`+
			`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],%s}`, port, port, port, extra)
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	rejected := []struct{ name, extra, wantText string }{
		{"dns_family 关闭动态 DNS 仍校验值域", `"dynamic_dns":false,"dns_family":"bogus"`, "无效的 DNS 协议栈"},
		{"compress_types 关闭压缩仍校验值域", `"enable_compress":false,"compress_types":"brotli"`, "压缩类型"},
		{"tls_source 关闭 TLS 仍校验值域", `"enable_tls":false,"tls_source":"bogus"`, "无效的证书来源"},
	}
	for i, tc := range rejected {
		rec := create(18610+i, tc.extra)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.wantText) {
			t.Fatalf("%s：status=%d body=%s, want 400 含 %q", tc.name, rec.Code, rec.Body.String(), tc.wantText)
		}
	}

	// 回归形状：合法值在开关关闭时照常放行（值域门不误伤死配置的合法值）。
	rec := create(18620, `"dynamic_dns":false,"dns_family":"both","enable_compress":false,"compress_types":"zstd"`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("合法枚举值（开关关闭）应 201, got %d %s", rec.Code, rec.Body.String())
	}
}

// Update 形态同门：存量规则开关关闭时显式提交非法枚举必须 400 且零落库（
// 与 Create 同口径，不得因「部分更新合并」而放行）。
func TestUpdateRule_enumGatesApplyRegardlessOfConsumerSwitch(t *testing.T) {
	cases := []struct{ name, payload, wantText string }{
		{"dns_family", `{"dns_family":"bogus"}`, "无效的 DNS 协议栈"},
		{"compress_types", `{"compress_types":"brotli"}`, "压缩类型"},
		{"tls_source", `{"tls_source":"bogus"}`, "无效的证书来源"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := newRuleFeatureTestHandlers(t)
			seedAuditRule(t, "lb_enum_upd", "enum-upd", "enum-upd.example.test", 18630, true, "manual", false)
			seedAuditUpstream(t, "lb_enum_upd")
			// 开关关闭形态：compress_types 的门不得因 enable_compress=0 而失效。
			if _, err := db.DB.Exec(`UPDATE lb_rules SET enable_compress=0 WHERE caddy_id='lb_enum_upd'`); err != nil {
				t.Fatalf("turn off compress: %v", err)
			}
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.PUT("/rules/:caddy_id", handler.UpdateRule)
			request := httptest.NewRequest(http.MethodPut, "/rules/lb_enum_upd", strings.NewReader(tc.payload))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), tc.wantText) {
				t.Fatalf("status=%d body=%s, want 400 含 %q", response.Code, response.Body.String(), tc.wantText)
			}
		})
	}
}

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// ---- LB-01：CreateRule 支持显式 enabled（缺省=启用，显式 false=禁用）----

func TestCreateRule_persists_explicit_enabled_false(t *testing.T) {
	// Given：UI 复制向导以 enabled:false 创建副本（预览展示「禁用」）
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := `{"name":"copy","protocol":"tcp","listen_port":17001,"enabled":false,` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：落库终态必须为禁用
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var enabled int
	if err := db.DB.QueryRow(`SELECT IIF(enabled IN ('1',1),1,0) FROM lb_rules WHERE listen_port=17001`).Scan(&enabled); err != nil {
		t.Fatalf("read created rule: %v", err)
	}
	if enabled != 0 {
		t.Fatalf("created rule enabled=%d, want 0 (explicit enabled:false must persist disabled)", enabled)
	}
}

func TestCreateRule_defaults_to_enabled_when_field_absent(t *testing.T) {
	// Given：不带 enabled 字段的历史调用方（向后兼容）
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := `{"name":"classic","protocol":"tcp","listen_port":17002,` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：缺省保持创建即启用
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var enabled int
	if err := db.DB.QueryRow(`SELECT IIF(enabled IN ('1',1),1,0) FROM lb_rules WHERE listen_port=17002`).Scan(&enabled); err != nil {
		t.Fatalf("read created rule: %v", err)
	}
	if enabled != 1 {
		t.Fatalf("created rule enabled=%d, want 1 (absent enabled must default to enabled)", enabled)
	}
}

// ---- LB-02：UpdateRule 的 TCP 三字段指针化（nil=沿用存量，显式 0=真实零值）----

func seedTCPRuleForZeroMerge(t *testing.T, caddyID string, listenPort int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,
		health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,
		enable_active_health_check,tcp_health_check_port,tcp_proxy_protocol,tcp_try_duration,tcp_try_interval,
		request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,
		enable_tls,tls_source,acme_config_id,ca_provider_id,tls_cert,tls_key,tls_http_redirect,
		enable_compress,compress_types,enabled,created_by,host_header,log_enabled,
		custom_routes_enabled,
		proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,proxy_stream_timeout,proxy_flush_interval,proxy_stream_close_delay)
		VALUES (?,'tcp-zero','','tcp','',?,'weighted_round_robin',
		'',10,5,3,2,
		0,9001,0,5000,300,
		0,0,0,
		0,'manual',0,0,'','',0,
		1,'gzip',1,0,'',0,
		0,
		0,0,0,0,0,0,0)`, caddyID, listenPort); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'tcp')`, caddyID); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
}

func readTCPZeroFields(t *testing.T, caddyID string) (hcPort, tryDuration, tryInterval int) {
	t.Helper()
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,0)
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&hcPort, &tryDuration, &tryInterval); err != nil {
		t.Fatalf("read tcp rule fields: %v", err)
	}
	return
}

func TestUpdateRule_persists_explicit_zero_tcp_fields(t *testing.T) {
	// Given：存量 TCP 规则带非零重试窗口/间隔与自定义检查端口
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleForZeroMerge(t, "lb_tcpzero", 17003)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	body := `{"name":"zeroed","tcp_try_duration":0,"tcp_try_interval":0,"tcp_health_check_port":0}`
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tcpzero", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When：部分更新显式清零（UI 文案承诺 0=不重试/默认间隔/跟随上游端口）
	router.ServeHTTP(response, request)

	// Then：DB 终态必须为真实 0
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	hcPort, tryDuration, tryInterval := readTCPZeroFields(t, "lb_tcpzero")
	if hcPort != 0 || tryDuration != 0 || tryInterval != 0 {
		t.Fatalf("explicit zeros must persist: tcp_health_check_port=%d tcp_try_duration=%d tcp_try_interval=%d, want all 0", hcPort, tryDuration, tryInterval)
	}
}

func TestUpdateRule_keeps_tcp_fields_when_absent(t *testing.T) {
	// Given：同上存量；请求不携带 TCP 三字段（部分更新语义 nil=沿用）
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleForZeroMerge(t, "lb_tcpkeep", 17004)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tcpkeep", strings.NewReader(`{"name":"kept"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：存量值保留
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	hcPort, tryDuration, tryInterval := readTCPZeroFields(t, "lb_tcpkeep")
	if hcPort != 9001 || tryDuration != 5000 || tryInterval != 300 {
		t.Fatalf("absent fields must keep existing: tcp_health_check_port=%d tcp_try_duration=%d tcp_try_interval=%d, want 9001/5000/300", hcPort, tryDuration, tryInterval)
	}
}

// ---- LB-03：监听端口不得与本进程管理端口（面板口/Caddy admin 口）冲突 ----

func TestCreateRule_rejects_configured_admin_panel_port(t *testing.T) {
	// Given：部署把管理面板端口配置为 8800（非硬编码默认 8000）
	handler := newRuleFeatureTestHandlers(t)
	handler.cfg.Port = 8800
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := `{"name":"panel-port","protocol":"tcp","listen_port":8800,` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：拒绝占用管理端口
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "管理端口") {
		t.Fatalf("create on panel port status=%d body=%s, want 400 管理端口", response.Code, response.Body.String())
	}
}

func TestUpdateRule_rejects_configured_admin_panel_port(t *testing.T) {
	// Given：存量 TCP 规则（18080），部署面板端口 8800，更新尝试迁到 8800
	handler := newRuleFeatureTestHandlers(t)
	handler.cfg.Port = 8800
	gin.SetMode(gin.TestMode)
	seedTCPRuleForZeroMerge(t, "lb_panelport", 18080)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_panelport", strings.NewReader(fmt.Sprintf(`{"name":"migrate","listen_port":%d}`, 8800)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：拒绝占用管理端口
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "管理端口") {
		t.Fatalf("update to panel port status=%d body=%s, want 400 管理端口", response.Code, response.Body.String())
	}
}

// ---- LB-04：读取口径 health_check_timeout NULL 默认 2（原 5，与写侧/渲染统一）----

func TestListRules_defaults_NULL_health_check_timeout_to_2(t *testing.T) {
	// Given：存量 NULL timeout 行（导入/直改 DB 形态）
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,health_check_timeout)
		VALUES ('lb_hcnull','hc-null','http','hcnull.example.test',18083,'weighted_round_robin',1,NULL)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_hcnull','127.0.0.1',9000,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	router := gin.New()
	router.GET("/rules", handler.ListRules)
	request := httptest.NewRequest(http.MethodGet, "/rules", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：列表响应中该规则的 health_check_timeout 按统一默认 2 回显
	if response.Code != http.StatusOK {
		t.Fatalf("list rules status=%d body=%s", response.Code, response.Body.String())
	}
	var listed struct {
		Code int `json:"code"`
		Data []struct {
			CaddyID            string `json:"caddy_id"`
			HealthCheckTimeout int    `json:"health_check_timeout"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list rules: %v", err)
	}
	for _, rule := range listed.Data {
		if rule.CaddyID != "lb_hcnull" {
			continue
		}
		if rule.HealthCheckTimeout != 2 {
			t.Fatalf("NULL health_check_timeout read back as %d, want 2 (unified default)", rule.HealthCheckTimeout)
		}
		return
	}
	t.Fatalf("seeded rule lb_hcnull missing from list response: %s", response.Body.String())
}

// ---- LB-13：caddy-config 响应并列返回规则全部路由（主路由+路径路由等兄弟路由）----

func TestGetRuleCaddyConfig_returns_sibling_path_routes(t *testing.T) {
	// Given：启用自定义路由的规则；运行配置含其主路由与两条路径路由（及其他规则路由）
	initializeRuleFeatureTestDB(t)
	runningConfig := `{"apps":{"http":{"servers":{"http_8080":{"listen":[":8080"],"routes":[` +
		`{"@id":"lb_other","handle":[]},` +
		`{"@id":"lb_ctx","match":[{"host":["ctx.example.test"]}],"handle":[{"handler":"static_response"}]},` +
		`{"@id":"lb_ctx_path_0","match":[{"host":["ctx.example.test"],"path":["/a","/a/*"]}],"handle":[]},` +
		`{"@id":"lb_ctx_path_1","match":[{"host":["ctx.example.test"],"path":["/b"]}],"handle":[]}` +
		`]}}}}}`
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/config/":
			_, _ = response.Write([]byte(runningConfig))
		case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/id/"):
			_, _ = response.Write([]byte(`{"@id":"lb_ctx","match":[{"host":["ctx.example.test"]}],"handle":[{"handler":"static_response"}]}`))
		default:
			_, _ = response.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(fakeCaddy.Close)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,custom_routes_enabled)
		VALUES ('lb_ctx','ctx','http','ctx.example.test',8080,'weighted_round_robin',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_ctx','127.0.0.1',9000,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	handler := &Handlers{
		cfg:          &config.Config{CaddyAdminURL: fakeCaddy.URL},
		caddyService: services.NewCaddyService(fakeCaddy.URL),
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id/caddy-config", handler.GetRuleCaddyConfig)
	request := httptest.NewRequest(http.MethodGet, "/rules/lb_ctx/caddy-config", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：config.routes 含主路由+两条路径路由（按运行顺序），不含他规则路由
	if response.Code != http.StatusOK {
		t.Fatalf("caddy-config status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Code int `json:"code"`
		Data struct {
			Config struct {
				Route  map[string]interface{}   `json:"route"`
				Routes []map[string]interface{} `json:"routes"`
			} `json:"config"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode caddy-config: %v", err)
	}
	if payload.Data.Config.Route["@id"] != "lb_ctx" {
		t.Fatalf("config.route @id=%v, want lb_ctx (向后兼容保留)", payload.Data.Config.Route["@id"])
	}
	var ids []string
	for _, route := range payload.Data.Config.Routes {
		ids = append(ids, fmt.Sprintf("%v", route["@id"]))
	}
	if strings.Join(ids, ",") != "lb_ctx,lb_ctx_path_0,lb_ctx_path_1" {
		t.Fatalf("config.routes @ids=%v, want [lb_ctx lb_ctx_path_0 lb_ctx_path_1]（含主路由、按运行顺序、排除他规则）", ids)
	}
}

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 禁用 TCP 规则绑定 stage1（IP ACL，仅阶段 1 特征）策略后启用，绑定必须保留
// （L4 渲染链 buildTCPSecurityRoutes 消费 stage0/1）；仅 G2（CC）/G3（WAF）
// 特征绑定被清除。全删形态会让 L4 IP ACL/信任/GeoIP 防护在「禁用→启用」后
// 静默失效。
func TestEnableRule_tcpKeepsStage1BindingsDropsG23(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	const caddyID = "lb_enable_tcp_bind"
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled,strategy)
		VALUES (?,'enable-tcp-bind','tcp',19850,0,'weighted_round_robin')`, caddyID); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES (?,'127.0.0.1',9000,1,1,'tcp')`, caddyID); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	// stage1：mode=off + ip_acl_enabled=1（仅阶段 1 特征，TCP 合法）；
	// G3：mode=blocking（WAF）；G2：human_verify_mode=force（CC）。
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,policy_type) VALUES
		(1,'enable-tcp-acl','off','stage1'),
		(2,'enable-tcp-waf','blocking','stage1'),
		(3,'enable-tcp-cc','off','stage1')`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_policies SET ip_acl_enabled=1 WHERE id=1;
		UPDATE security_policies SET human_verify_mode='force', human_verify_type='slider' WHERE id=3`); err != nil {
		t.Fatalf("seed policy features: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		(?,1),(?,2),(?,3)`, caddyID, caddyID, caddyID); err != nil {
		t.Fatalf("seed bindings: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/"+caddyID+"/enable", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", response.Code, response.Body.String())
	}
	// DB 终态：仅阶段 1 特征绑定保留，G2/G3 绑定清除。
	rows, err := db.DB.Query(`SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id`, caddyID)
	if err != nil {
		t.Fatalf("read bindings: %v", err)
	}
	defer rows.Close()
	var remaining []int
	for rows.Next() {
		var pid int
		if err := rows.Scan(&pid); err != nil {
			t.Fatal(err)
		}
		remaining = append(remaining, pid)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0] != 1 {
		t.Fatalf("remaining bindings=%v, want [1]（stage1 IP ACL 保留，G2/G3 清除）", remaining)
	}
	// 审计如实：只披露被清除的 G2/G3 绑定，不得声称「TCP 不参与策略渲染」。
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='启用' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read binding audit: %v", err)
	}
	if !strings.Contains(detail, "已解除 2 条") {
		t.Fatalf("audit detail=%q, want 已解除 2 条（仅 G2/G3）", detail)
	}
	if strings.Contains(detail, "TCP 不参与策略渲染") {
		t.Fatalf("audit detail=%q 仍声称 TCP 不参与策略渲染（stage0/1 由 L4 渲染链消费）", detail)
	}
}

// legacy 路径规则（match_type=”、路径/上游地址带空白）的源行复制不得
// 400 死端；副本落库形态必须归一（prefix + TrimSpace）。
func TestDuplicateRule_normalizesLegacyPathRules(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,custom_routes_enabled)
		VALUES ('lb_dup_legacy','dup-legacy','http','dup-legacy.example.test',8080,'weighted_round_robin',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb_dup_legacy','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstreams_json)
		VALUES ('lb_dup_legacy',0,'',' /api/ ','[{"address":" 10.8.8.8 ","port":9090,"weight":1,"enabled":true}]')`); err != nil {
		t.Fatalf("seed legacy path rule: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dup_legacy/duplicate", nil))
	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s（legacy 路径规则不得复制即 400 死端）", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			CaddyID string `json:"caddy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	newID := payload.Data.CaddyID
	if newID == "" {
		t.Fatalf("response lacks caddy_id: %s", response.Body.String())
	}
	var matchType, path, upstreamsJSON string
	if err := db.DB.QueryRow(`SELECT match_type,path,upstreams_json FROM path_rules WHERE rule_id=?`, newID).Scan(&matchType, &path, &upstreamsJSON); err != nil {
		t.Fatalf("read copy path rule: %v", err)
	}
	if matchType != "prefix" || path != "/api/" {
		t.Fatalf("copy path rule=(%q,%q), want (prefix,/api/)（归一后落库）", matchType, path)
	}
	if strings.Contains(upstreamsJSON, " 10.8.8.8 ") {
		t.Fatalf("copy upstreams_json=%q 仍带空白地址（渲染 dial 恒 502）", upstreamsJSON)
	}
	if !strings.Contains(upstreamsJSON, `"10.8.8.8"`) {
		t.Fatalf("copy upstreams_json=%q, want 归一地址 10.8.8.8", upstreamsJSON)
	}
}

// tcp_health_check_port 越上界（>65535）必须保存前 400 点名；
// 0（未启用）与 65535（上界）放行。
func TestCreateRule_tcpHealthCheckPortUpperBound(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	create := func(hcPort, listenPort int) *httptest.ResponseRecorder {
		body := `{"name":"tcp-hc-port","protocol":"tcp","listen_port":` + strconv.Itoa(listenPort) + `,"tcp_health_check_port":` + strconv.Itoa(hcPort) + `,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"weight":1,"enabled":true}]}`
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	response := create(70000, 13100)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("port=70000 status=%d body=%s, want 400（越界端口不得落库）", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name='tcp-hc-port'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rejected rule persisted (count=%d)", count)
	}
	for i, port := range []int{0, 65535} {
		if response := create(port, 13101+i); response.Code != http.StatusCreated {
			t.Fatalf("port=%d status=%d body=%s, want 201", port, response.Code, response.Body.String())
		}
	}
}

// 批量签发候选查询按全仓 IIF 归一口径读 enable_tls（单源 SQL 片段）。
// lb_rules.enable_tls 为 NUMERIC 亲和，带外 TEXT '1' 写入即收敛为 INTEGER；
// 本用例钉住该形态的启用 ACME 规则必须入选批量候选。
func TestIssueCertificate_batchIncludesTextFormEnableTLS(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_text_tls','text-tls','http','text-tls.example.test',8443,1,'1','acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"queued":1`) {
		t.Fatalf("body=%s, want queued=1（TEXT '1' 形态必须入选批量候选）", response.Body.String())
	}
}

// TCP 终态 log_enabled 归零（指针合并已保证非 nil，直接赋值）：
// 显式 true 不得残留，省略时存量 1 也必须自愈为 0（log_enabled 仅 HTTP
// 渲染消费）。
func TestUpdateRule_tcpLogEnabledAlwaysZeroed(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,strategy,enabled,log_enabled)
		VALUES ('lb_tcp_log','tcp-log','tcp',19860,'weighted_round_robin',1,1)`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb_tcp_log','127.0.0.1',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	update := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_tcp_log", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	readLog := func() int {
		t.Helper()
		var v int
		if err := db.DB.QueryRow(`SELECT COALESCE(log_enabled,0) FROM lb_rules WHERE caddy_id='lb_tcp_log'`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if response := update(`{"log_enabled":true}`); response.Code != http.StatusOK {
		t.Fatalf("explicit log_enabled update status=%d body=%s", response.Code, response.Body.String())
	}
	if got := readLog(); got != 0 {
		t.Fatalf("explicit log_enabled=true on tcp persisted %d, want 0", got)
	}
	if _, err := db.DB.Exec(`UPDATE lb_rules SET log_enabled=1 WHERE caddy_id='lb_tcp_log'`); err != nil {
		t.Fatal(err)
	}
	if response := update(`{"name":"tcp-log-renamed"}`); response.Code != http.StatusOK {
		t.Fatalf("omitted log_enabled update status=%d body=%s", response.Code, response.Body.String())
	}
	if got := readLog(); got != 0 {
		t.Fatalf("omitted log_enabled on tcp kept stale %d, want 0", got)
	}
}

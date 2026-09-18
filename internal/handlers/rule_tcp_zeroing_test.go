package handlers

// LB40-2(第 40 轮):http→tcp 协议切换的零值化集合补 dynamic_dns/
// enable_dns_server/dns_server/dns_family 四字段——DNS 动态上游是 HTTP 语义,
// 残留会让 TCP 规则行携带永不消费的脏配置(快照/导出/审计随之放大)。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateRule_protocolSwitchToTCPZeroesDNSFields(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,dynamic_dns,enable_dns_server,dns_server,dns_family)
		VALUES ('lb_dnszero','dnszero','','http','dnszero.test',18580,'weighted_round_robin',1,1,1,'8.8.8.8:53','ipv6')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_dnszero','up.test',80,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	request := httptest.NewRequest(http.MethodPut, "/rules/lb_dnszero", strings.NewReader(`{"protocol":"tcp"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("switch to tcp: status=%d body=%s", response.Code, response.Body.String())
	}

	var dynamicDNS, enableDNSServer int
	var dnsServer, dnsFamily string
	if err := db.DB.QueryRow(`SELECT COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'') FROM lb_rules WHERE caddy_id='lb_dnszero'`).
		Scan(&dynamicDNS, &enableDNSServer, &dnsServer, &dnsFamily); err != nil {
		t.Fatal(err)
	}
	if dynamicDNS != 0 || enableDNSServer != 0 || dnsServer != "" || dnsFamily != "" {
		t.Fatalf("tcp switch must zero dns fields, got dynamic_dns=%d enable_dns_server=%d dns_server=%q dns_family=%q", dynamicDNS, enableDNSServer, dnsServer, dnsFamily)
	}
}

// LB40-3(第 40 轮):路径规则上游 host:port 去重——主上游已有同口径判定
// (handlers.go hostPortSeen),路径规则缺位:同 host:port 双条目权重翻倍,
// 均衡语义静默漂移。
func TestPathRuleUpstreams_duplicateRejected(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	body := `{"name":"path-dup","protocol":"http","domain":"pathdup.test","listen_port":18581,"custom_routes_enabled":true,` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],` +
		`"path_rules":[{"path":"/a","match_type":"prefix","upstreams":[{"address":"Up.Test","port":9001},{"address":"up.test ","port":9001}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "重复") {
		t.Fatalf("duplicate path-rule upstream must 400, got %d %s", response.Code, response.Body.String())
	}
}

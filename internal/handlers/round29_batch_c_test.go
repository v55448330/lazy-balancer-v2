package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestValidateRuleConflictMatrix_reports_cross_rule_conflicts(t *testing.T) {
	tests := []struct {
		name       string
		candidates []ruleConflictCandidate
		wantCount  int
	}{
		{
			name: "TCP rules share a port",
			candidates: []ruleConflictCandidate{
				{name: "tcp-one", protocol: "tcp", listenPort: 9000, enabled: true},
				{name: "tcp-two", protocol: "tcp", listenPort: 9000, enabled: true},
			},
			wantCount: 2,
		},
		{
			name: "TCP and HTTP rules share a port",
			candidates: []ruleConflictCandidate{
				{name: "tcp", protocol: "tcp", listenPort: 8443, enabled: true},
				{name: "http", protocol: "http", domain: "http.example.test", listenPort: 8443, enabled: true},
			},
			wantCount: 2,
		},
		{
			name: "R32 F-2: 禁用 TCP 与启用 TCP 同端口不构成冲突（禁用规则无运行时占用）",
			candidates: []ruleConflictCandidate{
				{name: "tcp-disabled", protocol: "tcp", listenPort: 9001, enabled: false},
				{name: "tcp-enabled", protocol: "tcp", listenPort: 9001, enabled: true},
			},
			wantCount: 0,
		},
		{
			name: "R32 F-2: 禁用 TCP 与启用 HTTP 同端口不构成冲突",
			candidates: []ruleConflictCandidate{
				{name: "tcp-disabled", protocol: "tcp", listenPort: 8445, enabled: false},
				{name: "http-enabled", protocol: "http", domain: "http.example.test", listenPort: 8445, enabled: true},
			},
			wantCount: 0,
		},
		{
			name: "R32 F-2: 双方禁用 TCP 同端口不判定",
			candidates: []ruleConflictCandidate{
				{name: "tcp-off-one", protocol: "tcp", listenPort: 9002, enabled: false},
				{name: "tcp-off-two", protocol: "tcp", listenPort: 9002, enabled: false},
			},
			wantCount: 0,
		},
		{
			name: "HTTP rules overlap after domain normalization",
			candidates: []ruleConflictCandidate{
				{name: "http-one", protocol: "http", domain: "WWW.Example.Test, api.example.test", listenPort: 443, enabled: true},
				{name: "http-two", protocol: "http", domain: "www.example.test", listenPort: 443, enabled: true},
			},
			wantCount: 2,
		},
		{
			name: "HTTP rules use different domains on one port",
			candidates: []ruleConflictCandidate{
				{name: "http-one", protocol: "http", domain: "one.example.test", listenPort: 80, enabled: true},
				{name: "http-two", protocol: "http", domain: "two.example.test", listenPort: 80, enabled: true},
			},
			wantCount: 0,
		},
		{
			name: "R31 C-1: 同端口同域名但一方禁用不构成冲突（禁用规则无运行时占用）",
			candidates: []ruleConflictCandidate{
				{name: "http-enabled", protocol: "http", domain: "shop.example.test", listenPort: 80, enabled: true},
				{name: "http-disabled-legacy", protocol: "http", domain: "shop.example.test", listenPort: 80, enabled: false, enableTLS: true, tlsHTTPRedirect: true},
			},
			wantCount: 0,
		},
		{
			name: "R31 C-1: 双方禁用同样不判定",
			candidates: []ruleConflictCandidate{
				{name: "http-off-one", protocol: "http", domain: "off.example.test", listenPort: 8080, enabled: false},
				{name: "http-off-two", protocol: "http", domain: "off.example.test", listenPort: 8080, enabled: false},
			},
			wantCount: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given test.candidates.

			// When
			conflicts := validateRuleConflictMatrix(test.candidates)

			// Then
			if len(conflicts) != test.wantCount {
				t.Fatalf("conflicts=%#v, want %d entries", conflicts, test.wantCount)
			}
		})
	}
}

// Round 32 F-1: v2 导入冲突矩阵对缺 enabled 列的手造备份必须按启用处理
// （与校验侧 backupRuleEnabled 同口径、与表 COALESCE(enabled,1) 一致）；
// 此前缺键按禁用跳过判定，两条同端口同域名规则双双启用导入、运行时相互遮蔽。
func TestDisableV2RuleConflicts_missingEnabledColumn_treatsAsEnabled(t *testing.T) {
	// Given 手造备份行省略 enabled 列（JSON 反序列化后键不存在）
	rows := []map[string]any{
		{"name": "rule-a", "caddy_id": "lb_a", "protocol": "tcp", "domain": "", "listen_port": float64(9000)},
		{"name": "rule-b", "caddy_id": "lb_b", "protocol": "tcp", "domain": "", "listen_port": float64(9000)},
	}

	// When
	conflicts := disableV2RuleConflicts(rows)

	// Then: 两行均视为启用 → 同端口判冲突且双双置禁用（rows 就地改写 enabled=0）
	if len(conflicts) != 2 {
		t.Fatalf("缺 enabled 列的两行应视为启用并判冲突，实际 %d 条: %#v", len(conflicts), conflicts)
	}
	for index, row := range rows {
		if backupBooleanEnabled(row["enabled"]) {
			t.Fatalf("rows[%d] 应在冲突后置禁用，实际 enabled=%#v", index, row["enabled"])
		}
	}
}

func TestValidateRuleConflictMatrix_cross_port_redirect_shadow(t *testing.T) {
	tests := []struct {
		name           string
		candidates     []ruleConflictCandidate
		wantCount      int
		wantDisabled80 bool
	}{
		{
			name: "80 规则与 TLS 跳转规则同域名且均启用 → 双方禁用（80 规则为被遮蔽方）",
			candidates: []ruleConflictCandidate{
				{name: "port80", protocol: "http", domain: "shadow.test", listenPort: 80, enabled: true},
				{name: "tls-redirect", protocol: "http", domain: "shadow.test", listenPort: 443, enabled: true, enableTLS: true, tlsHTTPRedirect: true},
			},
			wantCount: 2, wantDisabled80: true,
		},
		{
			name: "跳转规则未启用 → 不判定",
			candidates: []ruleConflictCandidate{
				{name: "port80", protocol: "http", domain: "shadow.test", listenPort: 80, enabled: true},
				{name: "tls-redirect-disabled", protocol: "http", domain: "shadow.test", listenPort: 443, enabled: false, enableTLS: true, tlsHTTPRedirect: true},
			},
			wantCount: 0,
		},
		{
			name: "80 规则未启用 → 不判定",
			candidates: []ruleConflictCandidate{
				{name: "port80-disabled", protocol: "http", domain: "shadow.test", listenPort: 80, enabled: false},
				{name: "tls-redirect", protocol: "http", domain: "shadow.test", listenPort: 443, enabled: true, enableTLS: true, tlsHTTPRedirect: true},
			},
			wantCount: 0,
		},
		{
			name: "不同域名 → 不判定",
			candidates: []ruleConflictCandidate{
				{name: "port80", protocol: "http", domain: "a.test", listenPort: 80, enabled: true},
				{name: "tls-redirect", protocol: "http", domain: "b.test", listenPort: 443, enabled: true, enableTLS: true, tlsHTTPRedirect: true},
			},
			wantCount: 0,
		},
		{
			name: "跳转规则在前、80 规则在后（顺序无关）",
			candidates: []ruleConflictCandidate{
				{name: "tls-redirect", protocol: "http", domain: "shadow.test", listenPort: 8443, enabled: true, enableTLS: true, tlsHTTPRedirect: true},
				{name: "port80", protocol: "http", domain: "shadow.test", listenPort: 80, enabled: true},
			},
			wantCount: 2, wantDisabled80: true,
		},
		{
			name: "多域名部分重叠 → 判定",
			candidates: []ruleConflictCandidate{
				{name: "port80", protocol: "http", domain: "a.test,shadow.test", listenPort: 80, enabled: true},
				{name: "tls-redirect", protocol: "http", domain: "shadow.test,b.test", listenPort: 443, enabled: true, enableTLS: true, tlsHTTPRedirect: true},
			},
			wantCount: 2, wantDisabled80: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conflicts := validateRuleConflictMatrix(tt.candidates)
			if len(conflicts) != tt.wantCount {
				t.Fatalf("conflicts=%#v, want %d entries", conflicts, tt.wantCount)
			}
			if tt.wantDisabled80 {
				disabledNames := make(map[string]bool, len(conflicts))
				for _, conflict := range conflicts {
					disabledNames[conflict.Name] = true
				}
				for _, candidate := range tt.candidates {
					if candidate.listenPort == 80 && !disabledNames[candidate.name] {
						t.Fatalf("被遮蔽的 80 端口规则 %q 未被置为禁用: %#v", candidate.name, conflicts)
					}
				}
			}
		})
	}
}

func TestValidateConfigImport_lists_v1_rules_that_will_be_disabled(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	body := `{"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"tcp-one","protocol":false,"listen":9000,"status":true,"upstream_list":[1]}},{"pk":2,"fields":{"proxy_name":"tcp-two","protocol":false,"listen":9000,"status":true,"upstream_list":[2]}}]},"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9101}},{"pk":2,"fields":{"status":true,"address":"127.0.0.1","port":9102}}]}}`
	router := gin.New()
	router.POST("/config/import/validate", h.ValidateConfigImport)
	request := httptest.NewRequest(http.MethodPost, "/config/import/validate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	var envelope struct {
		Data importValidateResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !envelope.Data.Valid || len(envelope.Data.DisabledConflicts) != 2 {
		t.Fatalf("response=%s, want two disabled conflicts", response.Body.String())
	}
}

func TestTCPRuleMetrics_deduplicates_and_joins_upstream_addresses(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		metricKey string
	}{
		{name: "IPv4", host: "192.0.2.1", metricKey: "192.0.2.1:443"},
		{name: "domain", host: "backend.example.test", metricKey: "backend.example.test:443"},
		{name: "IPv6", host: "2001:db8::1", metricKey: "[2001:db8::1]:443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			samples := []prometheusSample{{name: `caddy_layer4_proxy_connections_total{upstream="` + test.metricKey + `"}`, value: 7}}
			upstreams := []models.Upstream{
				{Host: test.host, Port: 443, Enabled: true},
				{Host: test.host, Port: 443, Enabled: true},
			}

			// When
			metrics := parseTCPRuleMetricsFromSamples(samples, upstreams)

			// Then
			if got := metrics["requests_total"]; got != int64(7) {
				t.Fatalf("requests_total=%v, want 7", got)
			}
		})
	}
}

func TestGetRulesCertInfo_rejects_more_than_200_caddy_ids(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	caddyIDs := make([]string, 201)
	for index := range caddyIDs {
		caddyIDs[index] = "lb_" + strconv.Itoa(index)
	}
	payload, err := json.Marshal(map[string][]string{"caddy_ids": caddyIDs})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/rules/cert-info", handler.GetRulesCertInfo)
	request := httptest.NewRequest(http.MethodPost, "/rules/cert-info", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "invalid_request") || !strings.Contains(response.Body.String(), "200") {
		t.Fatalf("body=%q, want invalid_request limit message", response.Body.String())
	}
}

func TestGetRulesCertInfo_ignores_retired_certificate_for_previous_domain(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	certPEM, keyPEM, err := generateTestCert("old.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_changed','changed','http','new.example.test',443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at,updated_at)
		VALUES ('lb_changed','old.example.test','disabled',?,?,?,datetime('now'))`, certPEM, keyPEM, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seed rule and old certificate: %v", err)
	}
	router := gin.New()
	router.POST("/rules/cert-info", h.GetRulesCertInfo)
	request := httptest.NewRequest(http.MethodPost, "/rules/cert-info", strings.NewReader(`{"caddy_ids":["lb_changed"]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	var envelope struct {
		Data map[string]*models.RuleCertInfo `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	info := envelope.Data["lb_changed"]
	if info == nil || info.Status != "unknown" {
		t.Fatalf("certificate info=%#v, want unknown", info)
	}
}

func TestGetRuleCertInfo_ignores_certificate_for_previous_domain(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	certPEM, keyPEM, err := generateTestCert("old.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_single_changed','changed','http','new.example.test',443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at,updated_at)
		VALUES ('lb_single_changed','old.example.test','issued',?,?,?,datetime('now'))`, certPEM, keyPEM, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seed rule and old certificate: %v", err)
	}
	router := gin.New()
	router.GET("/rules/:caddy_id/cert-info", h.GetRuleCertInfo)
	request := httptest.NewRequest(http.MethodGet, "/rules/lb_single_changed/cert-info", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	var envelope struct {
		Data *models.RuleCertInfo `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if envelope.Data == nil || envelope.Data.Status != "unknown" {
		t.Fatalf("certificate info=%#v, want unknown", envelope.Data)
	}
}

func TestGetCurrentCertJobs_returns_latest_non_disabled_job_per_rule(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message,created_at,updated_at) VALUES
		('lb_one','old.example.test','issued','old',datetime('now','-3 minutes'),datetime('now','-3 minutes')),
		('lb_one','new.example.test','failed','current',datetime('now','-2 minutes'),datetime('now','-2 minutes')),
		('lb_one','retired.example.test','disabled','retired',datetime('now','-1 minute'),datetime('now','-1 minute')),
		('lb_two','two.example.test','queued','two',datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed certificate jobs: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/jobs/current", h.GetCurrentCertJobs)
	request := httptest.NewRequest(http.MethodPost, "/certificates/jobs/current", strings.NewReader(`{"rule_ids":["lb_one","lb_two","lb_missing"]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	var envelope struct {
		Data map[string]*models.CertJob `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if envelope.Data["lb_one"] == nil || envelope.Data["lb_one"].Message != "current" {
		t.Fatalf("lb_one=%#v, want current non-disabled job", envelope.Data["lb_one"])
	}
	if envelope.Data["lb_two"] == nil || envelope.Data["lb_two"].Status != "queued" {
		t.Fatalf("lb_two=%#v, want queued job", envelope.Data["lb_two"])
	}
	if envelope.Data["lb_missing"] != nil {
		t.Fatalf("lb_missing=%#v, want nil", envelope.Data["lb_missing"])
	}
}

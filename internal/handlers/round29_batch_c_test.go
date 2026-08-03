package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
				{name: "tcp-one", protocol: "tcp", listenPort: 9000},
				{name: "tcp-two", protocol: "tcp", listenPort: 9000},
			},
			wantCount: 2,
		},
		{
			name: "TCP and HTTP rules share a port",
			candidates: []ruleConflictCandidate{
				{name: "tcp", protocol: "tcp", listenPort: 8443},
				{name: "http", protocol: "http", domain: "http.example.test", listenPort: 8443},
			},
			wantCount: 2,
		},
		{
			name: "HTTP rules overlap after domain normalization",
			candidates: []ruleConflictCandidate{
				{name: "http-one", protocol: "http", domain: "WWW.Example.Test, api.example.test", listenPort: 443},
				{name: "http-two", protocol: "http", domain: "www.example.test", listenPort: 443},
			},
			wantCount: 2,
		},
		{
			name: "HTTP rules use different domains on one port",
			candidates: []ruleConflictCandidate{
				{name: "http-one", protocol: "http", domain: "one.example.test", listenPort: 80},
				{name: "http-two", protocol: "http", domain: "two.example.test", listenPort: 80},
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

func TestGetRulesCertInfo_ignores_retired_certificate_for_previous_domain(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	certPEM, _, err := generateTestCert("old.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_changed','changed','http','new.example.test',443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,expires_at,updated_at)
		VALUES ('lb_changed','old.example.test','disabled',?,?,datetime('now'))`, certPEM, time.Now().Add(24*time.Hour)); err != nil {
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

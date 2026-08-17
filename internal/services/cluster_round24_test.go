package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestClusterService_Nodes_degrades_bad_health_json_per_node(t *testing.T) {
	// Given：一个节点 health_json 损坏，另一个节点正常
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO nodes (name,ip_address,is_approved,status,health_json) VALUES ('bad-health','10.0.0.2',1,'online','not-json{')`); err != nil {
		t.Fatalf("seed broken node: %v", err)
	}
	validHealth, err := json.Marshal(models.ClusterHealth{CaddyOK: true, RulesCount: 3})
	if err != nil {
		t.Fatalf("encode valid health: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO nodes (name,ip_address,is_approved,status,health_json) VALUES ('good-health','10.0.0.3',1,'online',?)`, string(validHealth)); err != nil {
		t.Fatalf("seed healthy node: %v", err)
	}

	// When
	nodes, err := service.Nodes(context.Background(), time.Now())

	// Then：列表不因单节点损坏而整体失败，损坏节点 Health=nil
	if err != nil {
		t.Fatalf("nodes list failed on single bad health_json: %v", err)
	}
	byName := map[string]*models.ClusterNodeView{}
	for i := range nodes {
		byName[nodes[i].Name] = &nodes[i]
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes count=%d, want 2", len(nodes))
	}
	if bad := byName["bad-health"]; bad == nil || bad.Health != nil {
		t.Fatalf("bad-health node present=%v, want present with nil Health", byName["bad-health"] != nil)
	}
	if good := byName["good-health"]; good == nil || good.Health == nil || good.Health.RulesCount != 3 {
		t.Fatalf("good-health node health=%v, want decoded health", nodeHealth(byName["good-health"]))
	}
}

func nodeHealth(node *models.ClusterNodeView) *models.ClusterHealth {
	if node == nil {
		return nil
	}
	return node.Health
}

func TestAutoProvisionZeroSSLEAB_email_is_url_encoded(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET acme_email='user+tag@example.com' WHERE id=1"); err != nil {
		t.Fatalf("seed acme email: %v", err)
	}
	var gotForm string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		gotForm = string(body)
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"success": true, "eab_kid": "fetched-kid", "eab_hmac_key": "fetched-secret"})
	}))
	defer server.Close()
	defer overrideZeroSSLEABURL(server.URL)()
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('eab','zerossl',?,'',1,1000,1)`, ZeroSSLDirectoryURL)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	provider := models.CAProvider{ID: int(providerID), Provider: ProviderZeroSSL, Credentials: ""}

	// When
	if err := AutoProvisionZeroSSLEAB(context.Background(), &provider); err != nil {
		t.Fatalf("auto provision EAB: %v", err)
	}

	// Then：'+' 与 '@' 必须转义，不能以裸 '+' 上送（会被解析成空格）
	if want := "email=" + url.QueryEscape("user+tag@example.com"); gotForm != want {
		t.Fatalf("request body=%q, want %q", gotForm, want)
	}
	if !strings.Contains(provider.Credentials, "fetched-kid") {
		t.Fatalf("provider credentials=%q, want fetched EAB", provider.Credentials)
	}
}

func TestAutoProvisionZeroSSLEAB_cas_loses_memory_follows_db(t *testing.T) {
	// Given：并发 worker 已把另一份 EAB 写入 DB，本调用内存中的 credentials 仍是旧的空值
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET acme_email='user@example.com' WHERE id=1"); err != nil {
		t.Fatalf("seed acme email: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"success": true, "eab_kid": "fetched-kid", "eab_hmac_key": "fetched-secret"})
	}))
	defer server.Close()
	defer overrideZeroSSLEABURL(server.URL)()
	const concurrentCredentials = `{"eab_kid":"db-kid","eab_hmac_key":"db-secret"}`
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('eab','zerossl',?,?,1,1000,1)`, ZeroSSLDirectoryURL, concurrentCredentials)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	provider := models.CAProvider{ID: int(providerID), Provider: ProviderZeroSSL, Credentials: ""}

	// When
	if err := AutoProvisionZeroSSLEAB(context.Background(), &provider); err != nil {
		t.Fatalf("auto provision EAB: %v", err)
	}

	// Then：CAS 未命中时内存必须回读 DB 实际值，而不是持有未持久化的新值
	if provider.Credentials != concurrentCredentials {
		t.Fatalf("memory credentials=%q, want DB value %q", provider.Credentials, concurrentCredentials)
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(credentials,'') FROM ca_providers WHERE id=?", providerID).Scan(&stored); err != nil {
		t.Fatalf("read stored credentials: %v", err)
	}
	if stored != concurrentCredentials {
		t.Fatalf("DB credentials=%q, want unchanged %q", stored, concurrentCredentials)
	}
}

func TestSyncService_Report_failure_audit_throttles_and_resets_on_recovery(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	deadMaster := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := deadMaster.URL
	deadMaster.Close()
	liveMaster := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"code":0,"message":"ok"}`))
	}))
	defer liveMaster.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='tok-1' WHERE id=1", deadURL); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	countAudit := func() int {
		var count int
		if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='上报失败'").Scan(&count); err != nil {
			t.Fatalf("count audit rows: %v", err)
		}
		return count
	}

	// When/Then：首次失败记录审计，重复同样失败被节流
	if err := service.Report(context.Background()); err == nil {
		t.Fatal("report to dead master unexpectedly succeeded")
	}
	if got := countAudit(); got != 1 {
		t.Fatalf("audit rows after first failure=%d, want 1", got)
	}
	if err := service.Report(context.Background()); err == nil {
		t.Fatal("report to dead master unexpectedly succeeded")
	}
	if got := countAudit(); got != 1 {
		t.Fatalf("audit rows after repeated failure=%d, want 1 (throttled)", got)
	}

	// When/Then：上报恢复后节流状态重置，再次失败重新记录一次
	if _, err := database.Exec("UPDATE global_config SET master_url=? WHERE id=1", liveMaster.URL); err != nil {
		t.Fatalf("point to live master: %v", err)
	}
	if err := service.Report(context.Background()); err != nil {
		t.Fatalf("report to live master: %v", err)
	}
	if got := countAudit(); got != 1 {
		t.Fatalf("audit rows after recovery=%d, want 1", got)
	}
	if _, err := database.Exec("UPDATE global_config SET master_url=? WHERE id=1", deadURL); err != nil {
		t.Fatalf("point back to dead master: %v", err)
	}
	if err := service.Report(context.Background()); err == nil {
		t.Fatal("report to dead master unexpectedly succeeded")
	}
	if got := countAudit(); got != 2 {
		t.Fatalf("audit rows after post-recovery failure=%d, want 2", got)
	}
}

func overrideZeroSSLEABURL(serverURL string) func() {
	original := zerosslEABURL
	zerosslEABURL = serverURL
	return func() { zerosslEABURL = original }
}

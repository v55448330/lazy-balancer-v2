package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func snapshotScalarString(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		if v {
			return "1"
		}
		return "0"
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func TestClusterSnapshot_securityPoliciesIncludeFullColumnSet(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_block_pages (id,name,content,status_code) VALUES (9,'snapshot page','<html>blocked</html>',451)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,ip_whitelist,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,crs_rule_groups,crs_excluded_rules,custom_rules,block_page_id,block_status_code,enabled)
		VALUES (5,'full policy','desc','blocking',7,'deny','["10.0.0.0/8"]',1,'["1.1.1.1"]','["2.2.2.2"]',1,100,200,'["900","901"]','["942100"]','[]',9,403,1)`); err != nil {
		t.Fatal(err)
	}

	// When
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then
	var policies []map[string]interface{}
	if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
		t.Fatalf("parse security policies: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("policies=%d, want 1", len(policies))
	}
	policy := policies[0]
	want := map[string]string{
		"ip_acl_mode":        "deny",
		"ip_acl_list":        `["10.0.0.0/8"]`,
		"ip_acl_enabled":     "1",
		"ip_whitelist":       `["1.1.1.1"]`,
		"ip_blacklist":       `["2.2.2.2"]`,
		"crs_excluded_rules": `["942100"]`,
		"block_page_id":      "9",
	}
	for column, expected := range want {
		if got := snapshotScalarString(policy[column]); got != expected {
			t.Errorf("policy column %s=%q, want %q", column, got, expected)
		}
	}
}

func TestClusterSnapshot_securityAuxTablesRoundTrip(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	conditions := `[{"target":"uri","operator":"contains","pattern":"/admin"}]`
	if _, err := database.Exec(`INSERT INTO security_custom_rules (id,name,description,conditions,action,score,status_code,enabled,updated_by)
		VALUES (3,'aux rule','aux desc',?,'block',9,418,1,2)`, conditions); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_block_pages (id,name,description,content,status_code,is_default,created_by,updated_by)
		VALUES (4,'aux page','page desc','<html>aux</html>',499,0,1,2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_crs_version (id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at)
		VALUES (1,'v4.15.0','2026-08-01 00:00:00',0,'failed','boom','2026-08-01 01:00:00','2026-08-02 01:00:00','auto','2026-08-01 01:00:01','2026-08-01 01:02:03')`); err != nil {
		t.Fatal(err)
	}

	// When
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then: snapshot carries the three tables with typed fidelity
	if len(snapshot.SecurityCustomRules) != 1 {
		t.Fatalf("custom rules=%d, want 1", len(snapshot.SecurityCustomRules))
	}
	rule := snapshot.SecurityCustomRules[0]
	if rule.ID != 3 || rule.Name != "aux rule" || rule.Description != "aux desc" || rule.Action != "block" || rule.Score != 9 || rule.StatusCode != 418 || !rule.Enabled || rule.UpdatedBy != 2 {
		t.Fatalf("custom rule mismatch: %+v", rule)
	}
	if len(rule.Conditions) != 1 || rule.Conditions[0] != (models.CustomRuleCondition{Target: "uri", Operator: "contains", Pattern: "/admin"}) {
		t.Fatalf("custom rule conditions mismatch: %+v", rule.Conditions)
	}
	var auxPage *models.SecurityBlockPage
	for i := range snapshot.SecurityBlockPages {
		if snapshot.SecurityBlockPages[i].ID == 4 {
			auxPage = &snapshot.SecurityBlockPages[i]
		}
	}
	if auxPage == nil {
		t.Fatalf("block page 4 missing from snapshot: %+v", snapshot.SecurityBlockPages)
	}
	if auxPage.Name != "aux page" || auxPage.Description != "page desc" || auxPage.Content != "<html>aux</html>" || auxPage.StatusCode != 499 || auxPage.IsDefault || auxPage.CreatedBy != 1 || auxPage.UpdatedBy != 2 {
		t.Fatalf("block page mismatch: %+v", auxPage)
	}
	if len(snapshot.SecurityCRSVersion) != 1 {
		t.Fatalf("crs version rows=%d, want 1", len(snapshot.SecurityCRSVersion))
	}
	crs := snapshot.SecurityCRSVersion[0]
	if crs.Version != "v4.15.0" || crs.AutoUpdate || crs.UpdateStatus != "failed" || crs.Message != "boom" ||
		crs.LastChecked != "2026-08-01 01:00:00" || crs.NextUpdate != "2026-08-02 01:00:00" || crs.Trigger != "auto" ||
		crs.StartedAt != "2026-08-01 01:00:01" || crs.FinishedAt != "2026-08-01 01:02:03" || crs.UpdatedAt != "2026-08-01 00:00:00" {
		t.Fatalf("crs version mismatch: %+v", crs)
	}

	// When: the slave wipes its local tables and applies the snapshot
	if _, err := database.Exec("DELETE FROM security_custom_rules; DELETE FROM security_block_pages; DELETE FROM security_crs_version"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	clusterSnapshotCaches.Delete(database)
	restored, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then: a post-apply snapshot is field-for-field identical
	if !reflect.DeepEqual(restored.SecurityCustomRules, snapshot.SecurityCustomRules) {
		t.Fatalf("custom rules round trip mismatch:\ngot  %+v\nwant %+v", restored.SecurityCustomRules, snapshot.SecurityCustomRules)
	}
	if !reflect.DeepEqual(restored.SecurityBlockPages, snapshot.SecurityBlockPages) {
		t.Fatalf("block pages round trip mismatch:\ngot  %+v\nwant %+v", restored.SecurityBlockPages, snapshot.SecurityBlockPages)
	}
	if !reflect.DeepEqual(restored.SecurityCRSVersion, snapshot.SecurityCRSVersion) {
		t.Fatalf("crs version round trip mismatch:\ngot  %+v\nwant %+v", restored.SecurityCRSVersion, snapshot.SecurityCRSVersion)
	}
}

func TestApplySnapshot_emptySecurityPayloadDeletesRows(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode) VALUES (5,'doomed','blocking');
		INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_doomed',5);
		INSERT INTO security_custom_rules (id,name) VALUES (3,'doomed');
		INSERT INTO security_crs_version (id,version) VALUES (1,'v4.14.0')`); err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{
		Version:             9,
		SecurityPolicies:    json.RawMessage("[]"),
		SecurityBindings:    json.RawMessage("[]"),
		SecurityCustomRules: []models.SecurityCustomRule{},
		SecurityBlockPages:  []models.SecurityBlockPage{},
		SecurityCRSVersion:  []models.ClusterSecurityCRSVersion{},
	}

	// When
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then
	for _, table := range []string{"security_policies", "security_policy_bindings", "security_custom_rules", "security_block_pages", "security_crs_version"} {
		var count int
		if err := database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s rows=%d after empty snapshot, want 0", table, count)
		}
	}
}

func TestSyncService_applySnapshot_securityVisibleToCommittedCaddyConfig(t *testing.T) {
	// Given: a master snapshot with a WAF policy bound to an HTTP rule
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_sec','sec','http','sec.example.com',80,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_sec','127.0.0.1',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (5,'synced policy','blocking',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_sec',5)`); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// The slave starts without the security rows and without the master role.
	if _, err := database.Exec("DELETE FROM security_policy_bindings; DELETE FROM security_policies"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	clusterSnapshotCaches.Delete(database)
	var mu sync.Mutex
	var applied []byte
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		applied = body
		mu.Unlock()
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then: the policy and binding are visible to a post-commit db.DB read
	policy := GetSecurityPolicyForRule("lb_sec")
	if policy == nil || policy.Mode != "blocking" {
		t.Fatalf("policy after apply=%+v, want blocking policy", policy)
	}
	// And the Caddy config pushed to the admin API was generated after the
	// transaction committed, so it contains the WAF handler for the bound rule.
	mu.Lock()
	config := string(applied)
	mu.Unlock()
	if !strings.Contains(config, `"handler":"waf"`) {
		t.Fatalf("applied Caddy config missing waf handler (config generated before commit?): %s", config)
	}
}

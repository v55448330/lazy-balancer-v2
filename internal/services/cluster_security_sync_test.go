package services

import (
	"bytes"
	"context"
	"database/sql"
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

func securityPolicySchemaColumns(t *testing.T, database *sql.DB) []string {
	t.Helper()
	rows, err := database.Query(`SELECT name FROM pragma_table_info('security_policies') ORDER BY cid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(columns) == 0 {
		t.Fatal("security_policies schema is empty")
	}
	return columns
}

func TestClusterSnapshot_securityPoliciesIncludeFullColumnSet(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_block_pages (id,name,content) VALUES (9,'snapshot page','<html>blocked</html>')`); err != nil {
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

func TestClusterSnapshot_securityPoliciesSchemaColumnParity(t *testing.T) {
	// Given：初始化后的真实表形状（fresh DDL ∪ newColumns 的终态）与一行策略。
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (id,name) VALUES (5,'schema parity')`); err != nil {
		t.Fatal(err)
	}

	// When：走生产快照导出。
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：dump 键集合必须与表列集合完全相等，新增列不得只落 schema。
	schemaColumns := make(map[string]bool)
	for _, column := range securityPolicySchemaColumns(t, database) {
		schemaColumns[column] = true
	}
	var policies []map[string]interface{}
	if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
		t.Fatalf("parse security policies: %v", err)
	}
	if len(policies) != 1 || len(schemaColumns) == 0 {
		t.Fatalf("policies=%d schema columns=%d, want 1 and non-empty", len(policies), len(schemaColumns))
	}
	for column := range schemaColumns {
		if _, ok := policies[0][column]; !ok {
			t.Errorf("snapshot lacks security_policies column %q", column)
		}
	}
	for column := range policies[0] {
		if !schemaColumns[column] {
			t.Errorf("snapshot contains non-schema security_policies key %q", column)
		}
	}
}

func TestApplySnapshot_securityPoliciesEverySchemaColumnRoundTrip(t *testing.T) {
	// Given：不依赖 snapshot dump 的全列哨兵载荷——专门隔离 apply INSERT 漏列。
	_, database := newClusterTestService(t)
	columns := securityPolicySchemaColumns(t, database)
	jsonColumns := map[string]bool{
		"ip_acl_list": true, "ip_whitelist": true, "ip_blacklist": true,
		"crs_rule_groups": true, "crs_excluded_rules": true, "custom_rules": true,
		"geoip_countries": true, "geoip_crawler_engines": true,
		"ip_acl_list_refs": true, "ip_whitelist_refs": true,
	}
	booleanColumns := map[string]bool{
		"ip_acl_enabled": true, "ip_whitelist_enabled": true, "rate_limit_enabled": true,
		"enabled": true, "geoip_crawler_exempt": true, "waf_check_response": true,
		"log_request_body": true, "trust_detection": true,
	}
	expected := make(map[string]interface{}, len(columns))
	for _, column := range columns {
		switch {
		case column == "name":
			expected[column] = "apply parity"
		case column == "description":
			expected[column] = "every column"
		case column == "mode":
			expected[column] = "blocking"
		case column == "ip_acl_mode":
			expected[column] = "deny"
		case column == "geoip_mode":
			expected[column] = "off"
		case column == "policy_type":
			expected[column] = "stage0"
		case column == "created_at" || column == "updated_at":
			expected[column] = "2026-01-02 03:04:05"
		case column == "block_status_code":
			expected[column] = 403
		case column == "enabled" || column == "ip_whitelist_enabled":
			expected[column] = 0
		case jsonColumns[column]:
			expected[column] = `["7"]`
		case booleanColumns[column]:
			expected[column] = 1
		default:
			// 当前其余列均为整数（id/阈值/限流/审计外键等）；未来新增文本列
			// 若引入约束，本测试会以真实 SQLite 错误要求显式登记其有效哨兵。
			expected[column] = 7
		}
	}
	rawPolicies, err := json.Marshal([]map[string]interface{}{expected})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{
		Version:             9,
		SecurityPolicies:    rawPolicies,
		SecurityBindings:    json.RawMessage("[]"),
		SecurityCustomRules: []models.SecurityCustomRule{},
		SecurityBlockPages:  []models.SecurityBlockPage{},
		SecurityIPLists:     json.RawMessage("[]"),
		SecurityCRSVersion:  []models.ClusterSecurityCRSVersion{},
	}

	// When：走生产 replaceSnapshotTx/applySecurityTables。
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply full-column snapshot: %v", err)
	}

	// Then：逐列读取真实 SQLite 文本值；任何 INSERT 漏列都会落 schema 默认值而判红。
	for _, column := range columns {
		var got string
		query := fmt.Sprintf(`SELECT CAST("%s" AS TEXT) FROM security_policies WHERE id=7`, column)
		if err := database.QueryRow(query).Scan(&got); err != nil {
			t.Fatalf("read applied column %s: %v", column, err)
		}
		if want := snapshotScalarString(expected[column]); got != want {
			t.Errorf("applied column %s=%q, want %q", column, got, want)
		}
	}
}

func TestSyncService_applySnapshot_geoIPCrawlerExemptionRoundTrip(t *testing.T) {
	stubSecurityLibsAvailable(t)
	// Given：主端非默认爬虫豁免值，经真实绑定参与渲染。
	cluster, database := newClusterTestService(t)
	const engines = `["googlebot","baiduspider"]`
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_crawler_sync','crawler','http','crawler.example.test',80,1);
		INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_crawler_sync','127.0.0.1',8080,1);
		INSERT INTO security_policies (id,name,mode,enabled,geoip_countries,geoip_mode,geoip_crawler_exempt,geoip_crawler_engines)
		VALUES (7,'crawler exemption','blocking',1,'["海外"]','deny',1,'["googlebot","baiduspider"]');
		INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_crawler_sync',7)`); err != nil {
		t.Fatal(err)
	}
	masterPolicy := scanSecurityPolicyByID(7)
	if masterPolicy == nil {
		t.Fatal("master policy missing")
	}
	masterDirectives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{masterPolicy}, 403, "lb_crawler_sync"))

	// When：主端真实快照导出。
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：快照先携带哨兵值；用 Errorf 继续跑 apply，分别暴露 dump/apply 缺列。
	var exported []map[string]interface{}
	if err := json.Unmarshal(snapshot.SecurityPolicies, &exported); err != nil {
		t.Fatalf("parse exported policies: %v", err)
	}
	if len(exported) != 1 {
		t.Fatalf("exported policies=%d, want 1", len(exported))
	}
	if got := snapshotScalarString(exported[0]["geoip_crawler_exempt"]); got != "1" {
		t.Errorf("snapshot geoip_crawler_exempt=%q, want 1", got)
	}
	if got := snapshotScalarString(exported[0]["geoip_crawler_engines"]); got != engines {
		t.Errorf("snapshot geoip_crawler_engines=%q, want %s", got, engines)
	}

	// When：从端清空本地策略，经生产 applySnapshot 落库并生成/提交 Caddy 配置。
	if _, err := database.Exec(`DELETE FROM security_policy_bindings; DELETE FROM security_policies; UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
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
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：从库值、真实渲染预载与安全指令均与主端一致。
	var exempt int
	var storedEngines string
	if err := database.QueryRow(`SELECT geoip_crawler_exempt,geoip_crawler_engines FROM security_policies WHERE id=7`).Scan(&exempt, &storedEngines); err != nil {
		t.Fatal(err)
	}
	if exempt != 1 || storedEngines != engines {
		t.Errorf("applied crawler values=(%d,%s), want (1,%s)", exempt, storedEngines, engines)
	}
	policyContext, err := loadSecurityPolicyContext(database)
	if err != nil {
		t.Fatalf("load slave policy context: %v", err)
	}
	policies := policyContext.policyByRule["lb_crawler_sync"]
	if len(policies) != 1 {
		t.Fatalf("slave policies=%d, want 1", len(policies))
	}
	slavePolicy := policies[0]
	if !slavePolicy.GeoIPCrawlerExempt || string(slavePolicy.GeoIPCrawlerEngines) != engines {
		t.Errorf("slave render input crawler=(%v,%s), want (true,%s)", slavePolicy.GeoIPCrawlerExempt, slavePolicy.GeoIPCrawlerEngines, engines)
	}
	slaveDirectives := mustDirectives(buildIPPrecheckDirectives(policies, 403, "lb_crawler_sync"))
	if slaveDirectives != masterDirectives {
		t.Errorf("slave directives diverge from master:\n%s\nwant:\n%s", slaveDirectives, masterDirectives)
	}
	mu.Lock()
	appliedConfig := string(applied)
	mu.Unlock()
	for _, engine := range []string{"googlebot", "baiduspider"} {
		if !strings.Contains(appliedConfig, engine) {
			t.Errorf("applied Caddy config lacks crawler engine %q", engine)
		}
	}
}

func TestClusterSnapshot_securityAuxTablesRoundTrip(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	conditions := `[{"target":"uri","operator":"contains","pattern":"/admin"}]`
	if _, err := database.Exec(`INSERT INTO security_custom_rules (id,name,description,conditions,condition_logic,action,score,enabled,updated_by)
		VALUES (3,'aux rule','aux desc',?,'or','block',9,1,2)`, conditions); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_block_pages (id,name,description,content,is_default,created_by,updated_by)
		VALUES (4,'aux page','page desc','<html>aux</html>',0,1,2)`); err != nil {
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
	if rule.ID != 3 || rule.Name != "aux rule" || rule.Description != "aux desc" || rule.ConditionLogic != "or" || rule.Action != "block" || rule.Score != 9 || !rule.Enabled || rule.UpdatedBy != 2 {
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
	if auxPage.Name != "aux page" || auxPage.Description != "page desc" || auxPage.Content != "<html>aux</html>" || auxPage.IsDefault || auxPage.CreatedBy != 1 || auxPage.UpdatedBy != 2 {
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

// 口径：只经 replaceSnapshotTx（不含角色复核/Caddy 重载/提交后副作用）。
// 这是「显式空载荷清空全部安全表」的唯一归属用例（六表联合清点）——单表的
// 重复清点已并入此处，新增表只需在本矩阵加一项。
func TestReplaceSnapshotTx_emptySecurityPayloadDeletesRows(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode) VALUES (5,'doomed','blocking');
		INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_doomed',5);
		INSERT INTO security_custom_rules (id,name) VALUES (3,'doomed');
		INSERT INTO security_ip_lists (id,name,entries) VALUES (11,'doomed','[]');
		INSERT INTO security_crs_version (id,version) VALUES (1,'v4.14.0')`); err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{
		Version:             9,
		SecurityPolicies:    json.RawMessage("[]"),
		SecurityBindings:    json.RawMessage("[]"),
		SecurityCustomRules: []models.SecurityCustomRule{},
		SecurityBlockPages:  []models.SecurityBlockPage{},
		SecurityIPLists:     json.RawMessage("[]"),
		SecurityCRSVersion:  []models.ClusterSecurityCRSVersion{},
	}

	// When
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then
	for _, table := range []string{"security_policies", "security_policy_bindings", "security_custom_rules", "security_block_pages", "security_ip_lists", "security_crs_version"} {
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
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
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

// queryBindingRows reads security_policy_bindings for a rule ordered by
// policy_id ASC — the same SELECT the runtime uses (GetSecurityPoliciesForRule).
func queryBindingRows(t *testing.T, database *sql.DB, ruleCaddyID string) []int {
	t.Helper()
	rows, err := database.Query("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id ASC", ruleCaddyID)
	if err != nil {
		t.Fatalf("query bindings for %s: %v", ruleCaddyID, err)
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan binding: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate bindings: %v", err)
	}
	return ids
}

// A primary node with MULTIPLE binding rows for one rule
// (e.g. rule R bound to policies 1, 3, 5) snapshots to a slave; after apply,
// the slave's security_policy_bindings contains exactly those rows (no dedup
// to one row, no loss, order-preserving by policy_id).
func TestClusterSnapshot_multiRowBindingsPreserved(t *testing.T) {
	// Given: a primary with policies 1-5, three rules, and multi-row bindings:
	//   lb_multi → policies {1, 3, 5} (multi-row)
	//   lb_single → policy {1} (single row)
	//   lb_none → no bindings (zero rows)
	// Policies 2 and 4 exist but are unbound.
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES
		('lb_multi','multi','http','multi.example.com',80,1),
		('lb_single','single','http','single.example.com',81,1),
		('lb_none','none','http','none.example.com',82,1)`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int{1, 2, 3, 4, 5} {
		if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (?,?,'blocking',1)`, id, fmt.Sprintf("policy-%d", id)); err != nil {
			t.Fatal(err)
		}
	}
	for _, pid := range []int{1, 3, 5} {
		if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_multi',?)`, pid); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_single',1)`); err != nil {
		t.Fatal(err)
	}

	// When: snapshot → wipe slave → apply
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("DELETE FROM security_policy_bindings; DELETE FROM security_policies"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then: exact row set per rule, ordered by policy_id ASC
	multiBindings := queryBindingRows(t, database, "lb_multi")
	if !reflect.DeepEqual(multiBindings, []int{1, 3, 5}) {
		t.Fatalf("lb_multi bindings=%v, want [1 3 5]", multiBindings)
	}
	singleBindings := queryBindingRows(t, database, "lb_single")
	if !reflect.DeepEqual(singleBindings, []int{1}) {
		t.Fatalf("lb_single bindings=%v, want [1]", singleBindings)
	}
	noneBindings := queryBindingRows(t, database, "lb_none")
	if len(noneBindings) != 0 {
		t.Fatalf("lb_none bindings=%v, want empty", noneBindings)
	}
	// Unbound policies 2 and 4 must not leak into any rule's bindings.
	var totalBindings int
	if err := database.QueryRow("SELECT COUNT(*) FROM security_policy_bindings").Scan(&totalBindings); err != nil {
		t.Fatal(err)
	}
	if totalBindings != 4 {
		t.Fatalf("total bindings=%d, want 4 (3 multi + 1 single)", totalBindings)
	}
}

// (dangling): A binding whose policy was deleted on primary is
// carried verbatim through snapshot→apply. The runtime (GetSecurityPoliciesForRule)
// silently skips it via scanSecurityPolicyByID. Pin this pre-v2.2.0 behavior.
func TestClusterSnapshot_danglingBindingPreserved(t *testing.T) {
	// Given: rule lb_dangle has a valid binding to policy 1 and a dangling
	// binding to policy 99 (no such row in security_policies).
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_dangle','dangle','http','dangle.example.com',80,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (1,'real','blocking',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_dangle',1),('lb_dangle',99)`); err != nil {
		t.Fatal(err)
	}

	// When: snapshot → wipe → apply
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("DELETE FROM security_policy_bindings; DELETE FROM security_policies"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then: both rows survive verbatim (snapshot/apply does not validate references)
	bindings := queryBindingRows(t, database, "lb_dangle")
	if !reflect.DeepEqual(bindings, []int{1, 99}) {
		t.Fatalf("lb_dangle bindings=%v, want [1 99] (dangling row preserved)", bindings)
	}
	// Runtime skips the dangling binding: only policy 1 is returned.
	policies := GetSecurityPoliciesForRule("lb_dangle")
	if len(policies) != 1 || policies[0].ID != 1 {
		t.Fatalf("runtime policies=%v, want only policy 1 (dangling skipped)", policies)
	}
}

// queryRecordingSnapshotStore 记录最近一次 QueryContext 的 SQL 后委托真实 DB
// 执行（同时验证 SQL 可执行）——仅用于  的宽松 ORDER BY 成员断言。
type queryRecordingSnapshotStore struct {
	database *sql.DB
	query    string
}

func (s *queryRecordingSnapshotStore) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	s.query = query
	return s.database.QueryContext(ctx, query, args...)
}

func (s *queryRecordingSnapshotStore) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return s.database.QueryRowContext(ctx, query, args...)
}

func captureSnapshotQuery(t *testing.T, database *sql.DB, cluster *ClusterService) string {
	t.Helper()
	store := &queryRecordingSnapshotStore{database: database}
	if _, err := cluster.snapshotSecurityBindings(context.Background(), store); err != nil {
		t.Fatalf("snapshot security bindings: %v", err)
	}
	return store.query
}

// orderByNameSet 判定 ORDER BY 子句是否以列名形式覆盖给定全部列（大小写/
// 空白/列序不敏感，容忍 ASC/DESC 后缀）。不做文本后缀钉——等价 SQL 改写
// （列序、空白、别名）都可通过。
func orderByNameSet(query string, names ...string) bool {
	lower := strings.ToLower(query)
	idx := strings.LastIndex(lower, "order by")
	if idx < 0 {
		return false
	}
	terms := make(map[string]struct{})
	for _, term := range strings.Split(lower[idx+len("order by"):], ",") {
		fields := strings.Fields(term)
		if len(fields) == 0 {
			continue
		}
		terms[strings.Trim(fields[0], " ;")] = struct{}{}
	}
	for _, name := range names {
		if _, ok := terms[strings.ToLower(name)]; !ok {
			return false
		}
	}
	return true
}

func TestClusterSnapshot_securityBindingsFullyOrdered(t *testing.T) {
	// 回归：v2.2.0 多策略后同一 rule_caddy_id 最多 8 行绑定
	// 上限 2026-09-21 已 5→8，注释滞同步）。ORDER BY 只给 rule_caddy_id 时行间
	// 顺序在 SQL 层无定义（靠复合主键覆盖索引碰巧稳定，属查询计划偶然），而
	// 快照指纹/缓存键要求字节级确定性。
	// 旧断言钉 SQL 文本后缀（ORDER BY rule_caddy_id, policy_id），
	// 对等价改写（ORDER BY 1,2 / 子查询 / CTE）过敏且不证明行为——改为行为钉：
	// 同一绑定集合按两种相反的物理插入顺序落库，快照字节必须一致。
	cluster, database := newClusterTestService(t)
	rows := [][2]any{{"rule-a", 10}, {"rule-a", 5}, {"rule-a", 7}, {"rule-b", 3}, {"rule-b", 1}}
	insertAndSnapshot := func(order []int) []byte {
		t.Helper()
		if _, err := database.Exec("DELETE FROM security_policy_bindings"); err != nil {
			t.Fatal(err)
		}
		for _, i := range order {
			if _, err := database.Exec("INSERT INTO security_policy_bindings(rule_caddy_id, policy_id) VALUES(?,?)", rows[i][0], rows[i][1]); err != nil {
				t.Fatal(err)
			}
		}
		data, err := cluster.snapshotSecurityBindings(context.Background(), database)
		if err != nil {
			t.Fatalf("snapshot security bindings: %v", err)
		}
		return data
	}

	// When：正序与逆序落库各取一次快照
	forward := insertAndSnapshot([]int{0, 1, 2, 3, 4})
	reverse := insertAndSnapshot([]int{4, 3, 2, 1, 0})

	// Then：字节级一致（全序由 (rule_caddy_id, policy_id) 决定，与物理行序无关）
	if !bytes.Equal(forward, reverse) {
		t.Fatalf("同一绑定集合的两种物理插入顺序产出不同快照字节:\n %s\n %s\n（ORDER BY 未覆盖 (rule_caddy_id, policy_id) 全序）", forward, reverse)
	}
	// 内容自证：按 (rule_caddy_id, policy_id) 升序
	want := `[{"policy_id":5,"rule_caddy_id":"rule-a"},{"policy_id":7,"rule_caddy_id":"rule-a"},{"policy_id":10,"rule_caddy_id":"rule-a"},{"policy_id":1,"rule_caddy_id":"rule-b"},{"policy_id":3,"rule_caddy_id":"rule-b"}]`
	if string(forward) != want {
		t.Fatalf("bindings snapshot=%s\nwant %s", forward, want)
	}

	// 契约钉（ 取舍说明）：字节确定性用例在 SQLite 上无法区分
	// 「ORDER BY 只给 rule_caddy_id」——复合主键覆盖索引恰可满足该排序，行间
	// 次序仍稳定（正是找出项所说的「查询计划偶然」）。因此补一条宽松的
	// ORDER BY 成员断言：只要求子句里出现两列（去空白后按词元比较），容忍
	// 空白/列序/别名写法，不对 SQL 文本做后缀级钉。
	query := captureSnapshotQuery(t, database, cluster)
	if !orderByNameSet(query, "rule_caddy_id", "policy_id") {
		t.Fatalf("bindings query=%q, want ORDER BY 同时覆盖 rule_caddy_id 与 policy_id（仅一列时次序依赖查询计划）", query)
	}
}

// 库值唯一真相（批 3）：集群 apply 门值列归一——旧主快照/带外脏值不得在从
// 节点复制静默漂移：anomaly_threshold<=0/nil→5、rate_limit_burst<0→0、
// block_status_code 枚举外→403。rate_limit_rps 有意不归一（无默认可归，
// 镜像语义下主从渲染同报错 fail-visible）。
func TestApplySnapshot_normalizesPolicyValueColumns(t *testing.T) {
	_, database := newClusterTestService(t)
	snapshot := models.ClusterSnapshot{SecurityPolicies: json.RawMessage(`[
		{"id":7,"name":"dirty","mode":"blocking","anomaly_threshold":0,"rate_limit_burst":-5,"block_status_code":418,"enabled":true},
		{"id":8,"name":"nil-anomaly","mode":"off","anomaly_threshold":null,"enabled":true}
	]`)}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	var anomaly, burst, block int
	if err := database.QueryRow(`SELECT anomaly_threshold, rate_limit_burst, block_status_code FROM security_policies WHERE id=7`).Scan(&anomaly, &burst, &block); err != nil {
		t.Fatalf("read dirty policy: %v", err)
	}
	if anomaly != 5 || burst != 0 || block != 403 {
		t.Fatalf("dirty policy value columns=(%d,%d,%d), want (5,0,403)", anomaly, burst, block)
	}
	if err := database.QueryRow(`SELECT anomaly_threshold FROM security_policies WHERE id=8`).Scan(&anomaly); err != nil {
		t.Fatalf("read nil-anomaly policy: %v", err)
	}
	if anomaly != 5 {
		t.Fatalf("nil anomaly_threshold applied as %d, want 5", anomaly)
	}
}

// 旧主端（v2.3.0-）快照不携带 security_ip_lists 键时，
// 从端不得清空本地名单——与威胁源/爬虫源「缺席=保留本地」nil 门同口径。
// 携带空数组 [] = 显式清空；携带正常载荷 = 全量替换。
func TestClusterApplySnapshot_securityIPListsAbsentPreservesLocal(t *testing.T) {
	seedLists := func(t *testing.T, database *sql.DB) {
		t.Helper()
		if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,created_by,created_at,updated_by,updated_at,system) VALUES
			('p205-list-a','','','["1.1.1.1"]',0,'2026-01-01 00:00:00',0,'2026-01-01 00:00:00',1),
			('p205-list-b','','','["2.2.2.2"]',0,'2026-01-01 00:00:00',0,'2026-01-01 00:00:00',1),
			('p205-list-c','','','["3.3.3.3"]',0,'2026-01-01 00:00:00',0,'2026-01-01 00:00:00',1)`); err != nil {
			t.Fatal(err)
		}
	}
	countLists := func(t *testing.T, database *sql.DB) int {
		t.Helper()
		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	baseSnapshot := func() models.ClusterSnapshot {
		return models.ClusterSnapshot{
			Version:             9,
			SecurityPolicies:    json.RawMessage("[]"),
			SecurityBindings:    json.RawMessage("[]"),
			SecurityCustomRules: []models.SecurityCustomRule{},
			SecurityBlockPages:  []models.SecurityBlockPage{},
			SecurityCRSVersion:  []models.ClusterSecurityCRSVersion{},
		}
	}

	t.Run("absent key preserves local lists", func(t *testing.T) {
		// Given：本地三条名单 + 无 security_ip_lists 键的快照（nil RawMessage，
		// 模拟 v2.3.0- 主端）。
		_, database := newClusterTestService(t)
		seedLists(t, database)
		before := countLists(t, database)
		snapshot := baseSnapshot()

		// When
		if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
			t.Fatalf("apply snapshot: %v", err)
		}

		// Then：本地名单全部保留。
		if got := countLists(t, database); got != before {
			t.Fatalf("security_ip_lists rows=%d after absent-key apply, want %d (preserved)", got, before)
		}
	})

	t.Run("empty array explicitly clears", func(t *testing.T) {
		// Given：本地三条名单 + 显式空数组载荷（主端已清空名单）。
		_, database := newClusterTestService(t)
		seedLists(t, database)
		snapshot := baseSnapshot()
		snapshot.SecurityIPLists = json.RawMessage("[]")

		// When
		if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
			t.Fatalf("apply snapshot: %v", err)
		}

		// Then：显式清空语义不破坏。
		if got := countLists(t, database); got != 0 {
			t.Fatalf("security_ip_lists rows=%d after empty-array apply, want 0", got)
		}
	})

	t.Run("payload replaces all", func(t *testing.T) {
		// Given：本地三条名单 + 携带一行的正常载荷。
		_, database := newClusterTestService(t)
		seedLists(t, database)
		row := map[string]interface{}{
			"id": 41, "name": "p205-master-list", "description": "from master",
			"category": "deny", "entries": `["9.9.9.9"]`,
			"created_by": 1, "created_at": "2026-02-02 00:00:00",
			"updated_by": 1, "updated_at": "2026-02-02 00:00:00", "system": 0,
		}
		raw, err := json.Marshal([]map[string]interface{}{row})
		if err != nil {
			t.Fatal(err)
		}
		snapshot := baseSnapshot()
		snapshot.SecurityIPLists = raw

		// When
		if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
			t.Fatalf("apply snapshot: %v", err)
		}

		// Then：全量替换——仅剩载荷行。
		if got := countLists(t, database); got != 1 {
			t.Fatalf("security_ip_lists rows=%d after payload apply, want 1", got)
		}
		var name string
		if err := database.QueryRow(`SELECT name FROM security_ip_lists`).Scan(&name); err != nil {
			t.Fatal(err)
		}
		if name != "p205-master-list" {
			t.Fatalf("remaining list name=%q, want p205-master-list", name)
		}
	})
}

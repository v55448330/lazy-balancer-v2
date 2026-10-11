package services

import (
	"context"
	"testing"
)

// CL-U1（第 69 轮审计）：逐上游回源域名（origin_domain）集群同步面钉测试——
// snapshotAllUpstreams SELECT 与 insertSnapshotRules 的 upstreams INSERT 必须
// 同构携带该列，缺一即从节点静默丢回源域名（同步面分叉）。钉住「快照导出 →
// 清空 → 重放」全链路 origin_domain 逐值守恒（含空值零值守恒）。
// 形状镜像 cluster_upstream_path_test.go 的 upstream_path round-trip 先例。
func TestClusterSnapshot_originDomainRoundTrip(t *testing.T) {
	// Given：主端规则挂两个上游，仅 A 配回源域名
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb_origin','origin','http','origin.example.test',8080,'weighted_round_robin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,origin_domain)
		VALUES ('lb_origin','10.0.0.1',9000,1,1,'origin-a.example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled)
		VALUES ('lb_origin','10.0.0.2',9001,1,1)`); err != nil {
		t.Fatal(err)
	}

	// When：快照导出
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：导出侧 origin_domain 逐值存活
	exported := map[string]string{}
	for _, rule := range snapshot.Rules {
		if rule.CaddyID != "lb_origin" {
			continue
		}
		for _, upstream := range rule.Upstreams {
			exported[upstream.Host] = upstream.OriginDomain
		}
	}
	if exported["10.0.0.1"] != "origin-a.example.test" {
		t.Fatalf("snapshot upstream A origin_domain=%q, want origin-a.example.test", exported["10.0.0.1"])
	}
	if value, ok := exported["10.0.0.2"]; !ok || value != "" {
		t.Fatalf("snapshot upstream B origin_domain=%q (present=%v), want empty string", value, ok)
	}

	// When：从节点清空后重放
	if _, err := database.Exec("DELETE FROM upstreams"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：重放侧 origin_domain 逐值存活
	rows, err := database.Query(`SELECT host, origin_domain FROM upstreams WHERE rule_id='lb_origin' ORDER BY id`)
	if err != nil {
		t.Fatalf("read applied upstreams: %v", err)
	}
	defer rows.Close()
	applied := map[string]string{}
	for rows.Next() {
		var host, originDomain string
		if err := rows.Scan(&host, &originDomain); err != nil {
			t.Fatalf("scan applied upstream: %v", err)
		}
		applied[host] = originDomain
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if applied["10.0.0.1"] != "origin-a.example.test" {
		t.Fatalf("applied upstream A origin_domain=%q, want origin-a.example.test", applied["10.0.0.1"])
	}
	if value, ok := applied["10.0.0.2"]; !ok || value != "" {
		t.Fatalf("applied upstream B origin_domain=%q (present=%v), want empty string", value, ok)
	}
}

// CL-U1（第 69 轮审计）：健康检查域名（health_check_host）集群同步面钉测试——
// snapshotRules SELECT 与 insertSnapshotRules 的 lb_rules INSERT 必须同构携带
// 该列，缺一即从节点静默丢健康检查域名。钉住「导出 → 清空 → 重放」逐值守恒。
func TestClusterSnapshot_healthCheckHostRoundTrip(t *testing.T) {
	// Given：主端规则携带 health_check_host
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,health_check_host)
		VALUES ('lb_hchost','hchost','http','hchost.example.test',8080,'weighted_round_robin',1,'probe.example.test')`); err != nil {
		t.Fatal(err)
	}

	// When：快照导出
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：导出侧 health_check_host 存活
	exported := false
	for _, rule := range snapshot.Rules {
		if rule.CaddyID != "lb_hchost" {
			continue
		}
		exported = true
		if rule.HealthCheckHost != "probe.example.test" {
			t.Fatalf("snapshot rule health_check_host=%q, want probe.example.test", rule.HealthCheckHost)
		}
	}
	if !exported {
		t.Fatal("snapshot missing lb_hchost rule")
	}

	// When：从节点清空后重放（子表先删，与 clearSyncTables 同序）
	if _, err := database.Exec("DELETE FROM path_rules"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("DELETE FROM upstreams"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("DELETE FROM lb_rules"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：重放侧 health_check_host 存活
	var healthCheckHost string
	if err := database.QueryRow(`SELECT health_check_host FROM lb_rules WHERE caddy_id='lb_hchost'`).Scan(&healthCheckHost); err != nil {
		t.Fatalf("read applied rule: %v", err)
	}
	if healthCheckHost != "probe.example.test" {
		t.Fatalf("applied health_check_host=%q, want probe.example.test", healthCheckHost)
	}
}

// CL-U1（第 69 轮审计）：path_rules 静态响应/301 跳转五列（response_mode/
// response_status/response_body/response_content_type/redirect_to）集群同步面
// 钉测试——snapshotAllPathRules SELECT 与 insertSnapshotPathRules INSERT 必须
// 同构携带，缺一即从节点静默丢静态响应配置。钉住「导出 → 清空 → 重放」
// 两种模式各一行逐值守恒。
func TestClusterSnapshot_pathRulesResponseColumnsRoundTrip(t *testing.T) {
	// Given：主端路径规则一行 static、一行 redirect
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb_resp','resp','http','resp.example.test',8080,'weighted_round_robin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,response_mode,response_status,response_body,response_content_type)
		VALUES ('lb_resp',0,'prefix','/healthz','static',201,'pong','text/plain')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,response_mode,redirect_to)
		VALUES ('lb_resp',1,'exact','/old','redirect','https://example.test/landing')`); err != nil {
		t.Fatal(err)
	}

	// When：快照导出
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：导出侧 response 五列逐值存活
	exported := map[string]struct {
		mode, body, contentType, redirectTo string
		status                              int
	}{}
	for _, rule := range snapshot.Rules {
		if rule.CaddyID != "lb_resp" {
			continue
		}
		for _, pathRule := range rule.PathRules {
			exported[pathRule.Path] = struct {
				mode, body, contentType, redirectTo string
				status                              int
			}{pathRule.ResponseMode, pathRule.ResponseBody, pathRule.ResponseContentType, pathRule.RedirectTo, pathRule.ResponseStatus}
		}
	}
	staticRow, ok := exported["/healthz"]
	if !ok || staticRow.mode != "static" || staticRow.status != 201 || staticRow.body != "pong" || staticRow.contentType != "text/plain" {
		t.Fatalf("snapshot static path rule=%+v (present=%v), want mode=static status=201 body=pong content_type=text/plain", staticRow, ok)
	}
	redirectRow, ok := exported["/old"]
	if !ok || redirectRow.mode != "redirect" || redirectRow.redirectTo != "https://example.test/landing" {
		t.Fatalf("snapshot redirect path rule=%+v (present=%v), want mode=redirect redirect_to=https://example.test/landing", redirectRow, ok)
	}

	// When：从节点清空后重放
	if _, err := database.Exec("DELETE FROM path_rules"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：重放侧 response 五列逐值存活
	rows, err := database.Query(`SELECT path, response_mode, response_status, response_body, response_content_type, redirect_to FROM path_rules WHERE rule_id='lb_resp' ORDER BY sort_order`)
	if err != nil {
		t.Fatalf("read applied path rules: %v", err)
	}
	defer rows.Close()
	applied := map[string]struct {
		mode, body, contentType, redirectTo string
		status                              int
	}{}
	for rows.Next() {
		var path, mode, body, contentType, redirectTo string
		var status int
		if err := rows.Scan(&path, &mode, &status, &body, &contentType, &redirectTo); err != nil {
			t.Fatalf("scan applied path rule: %v", err)
		}
		applied[path] = struct {
			mode, body, contentType, redirectTo string
			status                              int
		}{mode, body, contentType, redirectTo, status}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	staticApplied, ok := applied["/healthz"]
	if !ok || staticApplied.mode != "static" || staticApplied.status != 201 || staticApplied.body != "pong" || staticApplied.contentType != "text/plain" {
		t.Fatalf("applied static path rule=%+v (present=%v), want mode=static status=201 body=pong content_type=text/plain", staticApplied, ok)
	}
	redirectApplied, ok := applied["/old"]
	if !ok || redirectApplied.mode != "redirect" || redirectApplied.redirectTo != "https://example.test/landing" {
		t.Fatalf("applied redirect path rule=%+v (present=%v), want mode=redirect redirect_to=https://example.test/landing", redirectApplied, ok)
	}
}

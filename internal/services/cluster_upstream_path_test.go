package services

import (
	"context"
	"testing"
)

// 上游 path 改写（upstream_path）的集群同步面：snapshotAllPathRules
// SELECT/scan 与 insertSnapshotPathRules INSERT 必须同构携带——缺一即从节点
// 静默丢改写配置（同步面分叉）。本测试钉住「快照导出 → 清空 → 重放」全链路
// upstream_path 不丢。
func TestClusterSnapshot_pathRulesUpstreamPathRoundTrip(t *testing.T) {
	// Given：主端路径规则携带 upstream_path
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb_uppath','uppath','http','uppath.example.test',8080,'weighted_round_robin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_uppath','127.0.0.1',9000,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path,upstreams_json)
		VALUES ('lb_uppath',0,'prefix','/api','/v1',NULL)`); err != nil {
		t.Fatal(err)
	}

	// When：快照导出
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：导出侧 upstream_path 存活
	var exported bool
	for _, rule := range snapshot.Rules {
		if rule.CaddyID != "lb_uppath" {
			continue
		}
		exported = true
		if len(rule.PathRules) != 1 || rule.PathRules[0].UpstreamPath != "/v1" {
			t.Fatalf("snapshot path rules upstream_path=%+v, want /v1", rule.PathRules)
		}
	}
	if !exported {
		t.Fatal("snapshot missing lb_uppath rule")
	}

	// When：从节点清空后重放
	if _, err := database.Exec("DELETE FROM path_rules"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：重放侧 upstream_path 逐值存活
	var upstreamPath string
	if err := database.QueryRow(`SELECT upstream_path FROM path_rules WHERE rule_id='lb_uppath'`).Scan(&upstreamPath); err != nil {
		t.Fatalf("read applied path rule: %v", err)
	}
	if upstreamPath != "/v1" {
		t.Fatalf("applied upstream_path=%q, want /v1", upstreamPath)
	}
}

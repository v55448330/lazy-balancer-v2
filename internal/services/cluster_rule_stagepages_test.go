package services

import (
	"context"
	"testing"
)

// 阶段拦截页 4 列（block_page_stage1_id/status、block_page_stage3_id/status）
// 的集群同步面：snapshotRules SELECT/scan 与 insertSnapshotRules INSERT 必须
// 同构携带——缺一即从节点静默丢阶段页配置（同步面分叉）。本测试钉住
// 「快照导出 → 清空 → 重放」全链路 4 列不丢。
func TestClusterSnapshot_rulesStageBlockPagesRoundTrip(t *testing.T) {
	// Given：主端规则携带阶段 1/3 覆盖页配置
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,
		block_page_stage1_id,block_page_stage1_status,block_page_stage3_id,block_page_stage3_status)
		VALUES ('lb_sp','sp','http','sp.example.test',8080,'weighted_round_robin',1,7,401,8,503)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_sp','127.0.0.1',9000,1,1)`); err != nil {
		t.Fatal(err)
	}

	// When：快照导出
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：导出侧 4 列存活
	var exported bool
	for _, rule := range snapshot.Rules {
		if rule.CaddyID != "lb_sp" {
			continue
		}
		exported = true
		if rule.BlockPageStage1ID != 7 || rule.BlockPageStage1Status != 401 || rule.BlockPageStage3ID != 8 || rule.BlockPageStage3Status != 503 {
			t.Fatalf("snapshot stage columns=(%d,%d,%d,%d), want (7,401,8,503)",
				rule.BlockPageStage1ID, rule.BlockPageStage1Status, rule.BlockPageStage3ID, rule.BlockPageStage3Status)
		}
	}
	if !exported {
		t.Fatal("snapshot missing lb_sp rule")
	}

	// When：从节点清空后重放
	if _, err := database.Exec("DELETE FROM lb_rules"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：重放侧 4 列逐值存活
	var s1id, s1status, s3id, s3status int
	if err := database.QueryRow(`SELECT COALESCE(block_page_stage1_id,0),COALESCE(block_page_stage1_status,0),COALESCE(block_page_stage3_id,0),COALESCE(block_page_stage3_status,0) FROM lb_rules WHERE caddy_id='lb_sp'`).
		Scan(&s1id, &s1status, &s3id, &s3status); err != nil {
		t.Fatalf("read applied rule: %v", err)
	}
	if s1id != 7 || s1status != 401 || s3id != 8 || s3status != 503 {
		t.Fatalf("applied stage columns=(%d,%d,%d,%d), want (7,401,8,503)", s1id, s1status, s3id, s3status)
	}
}

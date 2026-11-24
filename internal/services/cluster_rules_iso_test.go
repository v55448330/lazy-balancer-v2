package services

// 规则三面同构不变量（2026-10-11 用户裁定「如果没有就都应该没有，同步后就
// 应该一致」）：主端导出 → 从端应用落库 → 从端重建导出，rules 节哈希必须相等。
// 历史事故根因即两处平行手写归一块不同构（导出侧漏七字段），从端重建哈希
// ≠主端快照哈希 → drifted 落本地口径 → 面板「分区滞后」304 稳态永不自愈。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func seedTCPDeadRow(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,host_header,health_check_path,enable_compress,compress_types,request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,created_at,updated_at)
		VALUES ('lb_iso','同构','tcp',9997,'dead.example.com','/hc',1,'gzip',128,30,1,'2026-01-01T00:00:00Z','2026-01-02 03:04:05')`); err != nil {
		t.Fatal(err)
	}
}

// Given 主端 TCP 行携带七字段死值与 RFC3339 时间戳。
// When 主端构建快照（snapshotRules 导出）。
// Then 导出值已归一——与从端 insertSnapshotRules 落库值同构。
func TestSnapshotRules_exportNormalizesTCPDeadFields(t *testing.T) {
	svc, _ := newClusterTestService(t)
	seedTCPDeadRow(t)

	snap, err := svc.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range snap.Rules {
		if r.CaddyID != "lb_iso" {
			continue
		}
		found = true
		if r.HostHeader != "" || r.HealthCheckPath != "" || r.EnableCompress || r.CompressTypes != "" ||
			r.RequestBodyMaxSizeMB != 0 || r.UpstreamKeepaliveTimeout != 0 || r.ServerTokensHidden != 0 {
			t.Fatalf("导出侧 TCP 死值未归零：host=%q hc=%q compress=%v types=%q body=%d ka=%d tokens=%d",
				r.HostHeader, r.HealthCheckPath, r.EnableCompress, r.CompressTypes, r.RequestBodyMaxSizeMB, r.UpstreamKeepaliveTimeout, r.ServerTokensHidden)
		}
	}
	if !found {
		t.Fatal("快照未携带测试规则")
	}
}

// 主从往返同构（不变量级）：主端导出 → 从端 apply → 从端重建，rules 节哈希相等。
func TestSnapshotRules_masterSlaveRoundTripHashEqual(t *testing.T) {
	masterSvc, _ := newClusterTestService(t)
	seedTCPDeadRow(t)
	masterSnap, err := masterSvc.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	masterHash := masterSnap.SectionHashes["rules"]
	// 先断言两侧哈希非空再比较：SectionHashes 漏 rules 键时两侧都是 ""，
	// 空==空会让「同步后不同构」的根因以「相等」形态静默通过。
	if masterHash == "" {
		t.Fatal("主端快照 SectionHashes 缺 rules 节哈希（不变量守卫失效）")
	}

	// 从端视角：另一空库应用同一快照（replaceSnapshotDB 内部无 skips=全量重放）后重建
	slaveSvc, slaveDB := newClusterTestService(t)
	if err := replaceSnapshotDB(context.Background(), slaveDB, masterSnap); err != nil {
		t.Fatalf("从端应用快照: %v", err)
	}
	// 从端重建用主端同款装载（driftGuard 通道共用 snapshotRules 语义）
	slaveLocal, err := slaveSvc.driftGuardSectionHashes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if slaveLocal["rules"] == "" {
		t.Fatal("从端重建 SectionHashes 缺 rules 节哈希（不变量守卫失效）")
	}
	if masterHash != slaveLocal["rules"] {
		t.Fatalf("主端 rules 节哈希 %s ≠ 从端重建 %s——同步后不同构（分区滞后永续根因）", masterHash[:16], slaveLocal["rules"][:16])
	}
}

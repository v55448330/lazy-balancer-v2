package services

// autoban_escalation（第十列）集群同步钉：快照装载携带 / 从端 apply 落库 /
// 缺席保留本地（nil 门混跑兼容）。补齐十列传播测试面——此前实钉仅九列
// （六基础+证据分层三列），escalation 携带/落库无断言。
// 触发器独立 bump 钉在 middleware/cluster_version_autoban_recidivism_test.go。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestLoadSnapshotGlobalSettings_carriesAutobanEscalation(t *testing.T) {
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET autoban_escalation='progressive' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	s := snapshot.BasicSettings
	if s.AutobanEscalation == nil || *s.AutobanEscalation != "progressive" {
		t.Fatalf("autoban_escalation=%+v, want non-nil pointer carrying DB value", s.AutobanEscalation)
	}
	wire, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"autoban_escalation":"progressive"`) {
		t.Fatalf("wire basic_settings=%s, must contain autoban_escalation", wire)
	}
}

func TestUpdateSnapshotSettings_autobanEscalationAppliedWhenPresent(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	esc := "progressive"
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateSnapshotSettings(ctx, tx, models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{
		JWTExpireMinutes:  new(20),
		AutobanEscalation: &esc,
	}}); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := database.QueryRow(`SELECT COALESCE(autoban_escalation,'') FROM global_config WHERE id=1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "progressive" {
		t.Fatalf("applied autoban_escalation=%q, want progressive", got)
	}
}

func TestUpdateSnapshotSettings_autobanEscalationAbsentPreservesLocal(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE global_config SET autoban_escalation='progressive' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateSnapshotSettings(ctx, tx, models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{JWTExpireMinutes: new(20)}}); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := database.QueryRow(`SELECT COALESCE(autoban_escalation,'') FROM global_config WHERE id=1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "progressive" {
		t.Fatalf("absent snapshot must preserve local autoban_escalation, got %q", got)
	}
}

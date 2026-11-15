package services

// 证据分层三列集群同步钉：快照装载携带 / 从端 apply 落库 / 缺席保留本地
// （nil 门混跑兼容：旧主端不发新字段，从端保持本地 classic 默认）。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestLoadSnapshotGlobalSettings_carriesEvidenceCountingFields(t *testing.T) {
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET autoban_counting_mode='evidence',
		autoban_suspicion_multiplier=8, autoban_confirm_floor_ratio='0.6' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	s := snapshot.BasicSettings
	if s.AutobanCountingMode == nil || *s.AutobanCountingMode != "evidence" ||
		s.AutobanSuspicionMultiplier == nil || *s.AutobanSuspicionMultiplier != 8 ||
		s.AutobanConfirmFloorRatio == nil || *s.AutobanConfirmFloorRatio != "0.6" {
		t.Fatalf("evidence counting fields=%+v, want non-nil pointers carrying DB values", s)
	}
	wire, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"autoban_counting_mode":"evidence"`, `"autoban_suspicion_multiplier":8`, `"autoban_confirm_floor_ratio":"0.6"`,
	} {
		if !strings.Contains(string(wire), want) {
			t.Fatalf("wire basic_settings=%s, must contain %s", wire, want)
		}
	}
}

func TestUpdateSnapshotSettings_evidenceCountingAppliedWhenPresent(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	mode, floor := "evidence", "0.6"
	mult := 8
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateSnapshotSettings(ctx, tx, models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{
		JWTExpireMinutes:           new(20),
		AutobanCountingMode:        &mode,
		AutobanSuspicionMultiplier: &mult,
		AutobanConfirmFloorRatio:   &floor,
	}}); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var gotMode, gotFloor string
	var gotMult int
	if err := database.QueryRow(`SELECT COALESCE(autoban_counting_mode,''), COALESCE(autoban_suspicion_multiplier,0), COALESCE(autoban_confirm_floor_ratio,'') FROM global_config WHERE id=1`).
		Scan(&gotMode, &gotMult, &gotFloor); err != nil {
		t.Fatal(err)
	}
	if gotMode != "evidence" || gotMult != 8 || gotFloor != "0.6" {
		t.Fatalf("applied evidence fields mode=%q mult=%d floor=%q, want snapshot values", gotMode, gotMult, gotFloor)
	}
}

func TestUpdateSnapshotSettings_evidenceCountingAbsentPreservesLocal(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE global_config SET autoban_counting_mode='evidence',
		autoban_suspicion_multiplier=12, autoban_confirm_floor_ratio='0.2' WHERE id=1`); err != nil {
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
	var gotMode, gotFloor string
	var gotMult int
	if err := database.QueryRow(`SELECT COALESCE(autoban_counting_mode,''), COALESCE(autoban_suspicion_multiplier,0), COALESCE(autoban_confirm_floor_ratio,'') FROM global_config WHERE id=1`).
		Scan(&gotMode, &gotMult, &gotFloor); err != nil {
		t.Fatal(err)
	}
	if gotMode != "evidence" || gotMult != 12 || gotFloor != "0.2" {
		t.Fatalf("absent snapshot must preserve local evidence fields, got mode=%q mult=%d floor=%q", gotMode, gotMult, gotFloor)
	}
}

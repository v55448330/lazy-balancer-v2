package services

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// SYS41-2(第 41 轮审计):demote 必须停自动备份调度器——与 R54-N5
// (CRS/IP2Region SetMasterRole(false),TestClusterService_BecomeSlave_
// stopsUpdateSchedulers)同点位对称;否则降级后调度器继续运行,从节点本地
// 产出备份文件,打破「调度器仅主节点运行」不变量。
func TestClusterService_BecomeSlave_stopsAutoBackupScheduler(t *testing.T) {
	service, _ := newClusterTestService(t)
	t.Cleanup(StopAutoBackupScheduler)
	StartAutoBackupScheduler(context.Background())
	if autoBackupWorkerDone() == nil {
		t.Fatal("given: 主节点上自动备份调度器必须在运行")
	}

	// When 节点降级注册进另一集群
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}

	// Then 自动备份调度器停止
	if autoBackupWorkerDone() != nil {
		t.Fatal("降级为从节点后自动备份调度器必须停止")
	}
}

// CL41-1b(第 41 轮审计):promote 成功后拉起自动备份调度器(与 lifecycle.
// StartACME 对称)——此前调度器仅在进程启动的 isMaster 分支装配,从节点
// 提升后需重启进程才开始自动备份。
func TestClusterService_Promote_startsAutoBackupScheduler(t *testing.T) {
	service, database := newClusterTestService(t)
	t.Cleanup(StopAutoBackupScheduler)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url='' WHERE id=1"); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	if autoBackupWorkerDone() != nil {
		t.Fatal("given: 提升前调度器不得运行")
	}

	// When 从节点提升为主节点
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Then 自动备份调度器启动
	if autoBackupWorkerDone() == nil {
		t.Fatal("提升为主节点后自动备份调度器必须启动")
	}
}

// CL41-1a(第 41 轮审计)快照面:自动备份六设置列(不含 last_run 节点本地
// 运行态)随 users 节同步——主端装载恒携带(非 nil 指针),线格式六键齐全。
func TestLoadSnapshotGlobalSettings_carriesAutoBackupSettings(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='weekly', auto_backup_time='04:30', auto_backup_day=3, auto_backup_keep=5, auto_backup_sections='["users","security"]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	var snapshot models.ClusterSnapshot
	if err := service.loadSnapshotGlobalSettings(context.Background(), database, &snapshot); err != nil {
		t.Fatalf("load snapshot settings: %v", err)
	}
	s := snapshot.BasicSettings
	if s.AutoBackupEnabled == nil || !*s.AutoBackupEnabled ||
		s.AutoBackupFrequency == nil || *s.AutoBackupFrequency != "weekly" ||
		s.AutoBackupTime == nil || *s.AutoBackupTime != "04:30" ||
		s.AutoBackupDay == nil || *s.AutoBackupDay != 3 ||
		s.AutoBackupKeep == nil || *s.AutoBackupKeep != 5 ||
		s.AutoBackupSections == nil || *s.AutoBackupSections != `["users","security"]` {
		t.Fatalf("auto backup settings=%+v, want six non-nil pointers carrying DB values", s)
	}
	// 线格式:六键必须出现在 basic_settings JSON(omitempty 仅省 nil,
	// 即旧主端缺席形态;新主端恒携带)。
	wire, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"auto_backup_enabled":true`, `"auto_backup_frequency":"weekly"`, `"auto_backup_time":"04:30"`, `"auto_backup_day":3`, `"auto_backup_keep":5`, `"auto_backup_sections":"[\"users\",\"security\"]"`} {
		if !strings.Contains(string(wire), want) {
			t.Fatalf("wire basic_settings=%s, must contain %s", wire, want)
		}
	}
}

// CL41-1a apply 面:快照携带六列时从端落库(新主端→新从端收敛);
// last_run 为节点本地运行态,任何快照形态都不得覆盖。
func TestUpdateSnapshotSettings_autoBackupSettingsAppliedWhenPresent(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE global_config SET auto_backup_last_run='2026-09-19T03:00:00+08:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	enabled, freq, tm, day, keep, sections := true, "monthly", "05:40", 12, 9, `["rules"]`
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateSnapshotSettings(ctx, tx, models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{
		JWTExpireMinutes:    20,
		AutoBackupEnabled:   &enabled,
		AutoBackupFrequency: &freq,
		AutoBackupTime:      &tm,
		AutoBackupDay:       &day,
		AutoBackupKeep:      &keep,
		AutoBackupSections:  &sections,
	}}); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var gotEnabled bool
	var gotFreq, gotTime, gotSections, gotLastRun string
	var gotDay, gotKeep int
	if err := database.QueryRow(`SELECT COALESCE(auto_backup_enabled,0), COALESCE(auto_backup_frequency,''), COALESCE(auto_backup_time,''), COALESCE(auto_backup_day,0), COALESCE(auto_backup_keep,0), COALESCE(auto_backup_sections,''), COALESCE(auto_backup_last_run,'') FROM global_config WHERE id=1`).
		Scan(&gotEnabled, &gotFreq, &gotTime, &gotDay, &gotKeep, &gotSections, &gotLastRun); err != nil {
		t.Fatal(err)
	}
	if !gotEnabled || gotFreq != "monthly" || gotTime != "05:40" || gotDay != 12 || gotKeep != 9 || gotSections != `["rules"]` {
		t.Fatalf("applied auto backup settings enabled=%v freq=%q time=%q day=%d keep=%d sections=%q, want snapshot values",
			gotEnabled, gotFreq, gotTime, gotDay, gotKeep, gotSections)
	}
	if gotLastRun != "2026-09-19T03:00:00+08:00" {
		t.Fatalf("auto_backup_last_run=%q, want untouched node-local value", gotLastRun)
	}
}

// CL41-1a 偏斜面(镜像 branding_json d55a675 缺席语义):旧主端快照缺该组
// 字段(全 nil 指针)时,从端 apply 必须跳过写入、保留本地设置——不得把
// 从端本地值清成零值。
func TestUpdateSnapshotSettings_autoBackupSettingsAbsentPreservesLocal(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='weekly', auto_backup_time='04:30', auto_backup_day=3, auto_backup_keep=5, auto_backup_sections='["users"]', auto_backup_last_run='2026-09-19T03:00:00+08:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// 旧主端形态:BasicSettings 不含自动备份组(全 nil)
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateSnapshotSettings(ctx, tx, models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{JWTExpireMinutes: 20}}); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var gotEnabled bool
	var gotFreq, gotTime, gotSections, gotLastRun string
	var gotDay, gotKeep int
	if err := database.QueryRow(`SELECT COALESCE(auto_backup_enabled,0), COALESCE(auto_backup_frequency,''), COALESCE(auto_backup_time,''), COALESCE(auto_backup_day,0), COALESCE(auto_backup_keep,0), COALESCE(auto_backup_sections,''), COALESCE(auto_backup_last_run,'') FROM global_config WHERE id=1`).
		Scan(&gotEnabled, &gotFreq, &gotTime, &gotDay, &gotKeep, &gotSections, &gotLastRun); err != nil {
		t.Fatal(err)
	}
	if !gotEnabled || gotFreq != "weekly" || gotTime != "04:30" || gotDay != 3 || gotKeep != 5 || gotSections != `["users"]` || gotLastRun != "2026-09-19T03:00:00+08:00" {
		t.Fatalf("absent snapshot must preserve local settings, got enabled=%v freq=%q time=%q day=%d keep=%d sections=%q last_run=%q",
			gotEnabled, gotFreq, gotTime, gotDay, gotKeep, gotSections, gotLastRun)
	}
}

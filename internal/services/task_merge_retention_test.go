package services

// 任务合并回归钉（v2.4.5-beta）：五个日清理任务合一为 maintenance-retention、
// 证书续期扫描与状态对账合一为 cert-scan。断言旧 ID 不再注册（不留双注册/
// 兼容别名）、新任务角色/周期固定、合并任务逐个执行子步骤且单步失败不阻断
// 其余步骤并汇总进 error。

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func TestTaskEngineWire_mergedTaskIDsRegisteredAndOldIDsGone(t *testing.T) {
	te := newWireTestEngine(t)

	// 旧 ID 必须彻底离开注册表：双注册会让同一清理轮跑两遍，兼容别名会让
	// 页面/偏好行在新旧两套 ID 间分裂。
	for _, oldID := range []string{
		"log-cleanup", "audit-retention", "security-events-retention",
		"metrics-history-cleanup", "metrics-orphan-cleanup",
		"cert-renewal-scan", "cert-reconcile",
	} {
		if _, ok := te.Lookup(oldID); ok {
			t.Errorf("旧任务 ID %s 仍在注册表（合并后不得留双注册/兼容别名）", oldID)
		}
	}

	retention, ok := te.Lookup(maintenanceRetentionTaskID)
	if !ok {
		t.Fatalf("合并任务 %s 未注册", maintenanceRetentionTaskID)
	}
	if retention.Kind != taskengine.KindPeriodic {
		t.Errorf("%s Kind=%s, want periodic", maintenanceRetentionTaskID, retention.Kind)
	}
	if retention.IntervalSec != int(24*time.Hour/time.Second) {
		t.Errorf("%s IntervalSec=%d, want 24h", maintenanceRetentionTaskID, retention.IntervalSec)
	}
	if !retention.LoopOn {
		t.Errorf("%s 必须在默认启动清单（每日清理默认开启）", maintenanceRetentionTaskID)
	}
	cert, ok := te.Lookup(certScanTaskID)
	if !ok {
		t.Fatalf("合并任务 %s 未注册", certScanTaskID)
	}
	if cert.Kind != taskengine.KindPeriodic {
		t.Errorf("%s Kind=%s, want periodic", certScanTaskID, cert.Kind)
	}
	if cert.IntervalSec != int(6*time.Hour/time.Second) {
		t.Errorf("%s IntervalSec=%d, want 6h", certScanTaskID, cert.IntervalSec)
	}
	if !cert.LoopOn {
		t.Errorf("%s 必须在默认启动清单（主节点自动续签/对账默认开启）", certScanTaskID)
	}

	// 角色：保留期清理 RoleAny（两角色都该清理本节点库）；证书扫描保持
	// MasterOnly（从节点不签发，写前门零写）。角色门经 RoleApplicable 派生。
	te.SetRole(false)
	if m, _ := te.Lookup(maintenanceRetentionTaskID); !m.RoleApplicable {
		t.Errorf("%s 必须 RoleAny（从节点仍需本地保留期清理）", maintenanceRetentionTaskID)
	}
	if m, _ := te.Lookup(certScanTaskID); m.RoleApplicable {
		t.Errorf("%s 必须 RoleMasterOnly（从节点不得执行签发/对账写面）", certScanTaskID)
	}
}

// 健康轮：五个清理步骤都必须真实执行并各留一条摘要行（合并不得变成
// 只跑第一步的退化形态）。
func TestMaintenanceRetentionRound_runsEveryStep(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	newTaskLogDir(t)
	SetMetricsCollector(&MetricsService{})
	t.Cleanup(func() { SetMetricsCollector(nil) })

	if err := runMaintenanceRetentionRound(context.Background(), filepath.Join(t.TempDir(), "app.log")); err != nil {
		t.Fatalf("健康轮不得报错, got %v", err)
	}

	log := readTaskLog(t, maintenanceRetentionTaskID)
	for _, want := range []string{
		"日志清理完成",
		"清理完成：审计日志",
		"安全事件保留清理完成",
		"指标历史清理完成",
		"孤儿规则指标清理完成",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("缺步骤摘要 %q；任务日志=%q", want, log)
		}
	}
}

// 单步失败不得阻断其余步骤：安全事件保留步失败后，日志清理/审计/指标历史/
// 孤儿指标仍各留摘要，且轮末 error 点名失败步骤（task_runs 落 failed 可定位）。
func TestMaintenanceRetentionRound_singleStepFailureKeepsGoing(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	newTaskLogDir(t)
	SetMetricsCollector(&MetricsService{})
	t.Cleanup(func() { SetMetricsCollector(nil) })
	// 安全事件就绪判据所需两表同时破坏（仅破坏事件表会被「回填未就绪」
	// 合法降级吞掉，测不出失败隔离）。
	for _, stmt := range []string{
		`ALTER TABLE security_events RENAME TO security_events_broken`,
		`ALTER TABLE metrics_state RENAME TO metrics_state_broken`,
	} {
		if _, err := db.MetricsDB.Exec(stmt); err != nil {
			t.Fatalf("break metrics schema: %v", err)
		}
	}

	err := runMaintenanceRetentionRound(context.Background(), filepath.Join(t.TempDir(), "app.log"))
	if err == nil {
		t.Fatal("安全事件保留步失败必须汇总为 error（不得记成功）")
	}
	msg := err.Error()
	if !strings.Contains(msg, "安全事件保留") {
		t.Fatalf("汇总错误未点名失败步骤: %v", err)
	}
	if !strings.Contains(msg, "保留期清理部分失败") {
		t.Fatalf("汇总错误缺合并任务归因: %v", err)
	}

	log := readTaskLog(t, maintenanceRetentionTaskID)
	if !strings.Contains(log, "安全事件保留清理失败") {
		t.Fatalf("失败步缺失败摘要行: %q", log)
	}
	// 失败步之前的步骤照常完成。
	if !strings.Contains(log, "日志清理完成") || !strings.Contains(log, "清理完成：审计日志") {
		t.Fatalf("失败步之前的步骤未完成: %q", log)
	}
	// 失败步之后的步骤也必须执行（合并任务的核心契约：单步失败不阻断）。
	if !strings.Contains(log, "指标历史清理完成") || !strings.Contains(log, "孤儿规则指标清理完成") {
		t.Fatalf("失败步之后的步骤被阻断: %q", log)
	}
}

// 续期扫描步跳过（证书服务未运行）时，状态对账步照常执行；整轮保留跳过
// 哨兵（task_runs=skipped），不得因对账成功而谎报 success。
func TestCertScanRound_skippedScanStillRunsReconcile(t *testing.T) {
	te := newWireTestEngine(t)
	te.StopLoop(certScanTaskID) // 关闭周期调度，仅本用例同步驱动
	newTaskLogDir(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(nil) // 服务未运行 → 续期扫描步跳过
	t.Cleanup(func() { SetActiveCertificateService(nil) })

	err := runCertScanRound(context.Background())
	if !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want ErrTaskSkipped（至少一步跳过，整轮不得记 success）", err)
	}
	log := readTaskLog(t, certScanTaskID)
	if !strings.Contains(log, "续期扫描已跳过") {
		t.Fatalf("续期扫描跳过缺留痕: %q", log)
	}
	if !strings.Contains(log, "状态对账完成") {
		t.Fatalf("续期扫描跳过不得阻断状态对账步: %q", log)
	}
}

// 两步都真失败时汇总 error 同时点名两步（失败优先于跳过）。
func TestCertScanRound_aggregatesBothStepFailures(t *testing.T) {
	te := newWireTestEngine(t)
	te.StopLoop(certScanTaskID)
	newTaskLogDir(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	t.Cleanup(func() { SetActiveCertificateService(nil) })
	// cert_jobs 读故障 → 续期扫描与状态对账两步都失败。
	if _, err := db.DB.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	err := runCertScanRound(context.Background())
	if err == nil {
		t.Fatal("两步失败必须汇总为 error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "续期扫描") || !strings.Contains(msg, "状态对账") {
		t.Fatalf("汇总错误未点名全部失败步骤: %v", err)
	}
	if !strings.Contains(msg, "证书扫描任务部分失败") {
		t.Fatalf("汇总错误缺合并任务归因: %v", err)
	}
}

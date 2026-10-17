package services

// Round 62 用户反馈批次钉（SPEC §6.5 业务摘要行）：每个真实执行轮在
// tasks/{id}.log 留业务结论——「无临期证书/清理 N 条/摄取 N 条/配置一致」。
// R66 收敛（2026-10-03 裁定）：一致轮不再逐轮记录，收敛为小时级心跳；
// 漂移/异常轮照旧逐轮留痕。

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func newTaskLogDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// U12-F12：保存并恢复旧目录（原实现只在旧目录为空时置空——上一用例的
	// 临时目录被删后残留指针，跨用例读日志失败/假绿）。
	old := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(dir, "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(old) })
	return filepath.Join(dir, "tasks")
}

func readTaskLog(t *testing.T, taskID string) string {
	t.Helper()
	data, err := os.ReadFile(taskengine.TaskLogPath(taskID))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	return string(data)
}

// Given 空库（无临期证书、无过期审计、配置一致无从判定——cert 域最简可测形）。
// When cert-renewal-scan 摘要行写入。
// Then tasks/cert-renewal-scan.log 含「无临期证书」业务结论行。
func TestTaskLogf_CertRenewalScanNoExpiringSummary(t *testing.T) {
	newTaskLogDir(t)
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA })
	// 空库：is_master 默认 1，CheckExpiration 无临期 → 摘要行必达（qm 仅在
	// 有 jobs 的循环内消费——空路径不依赖队列）
	s := &CertificateService{}
	s.renewExpiringCertificates()
	log := readTaskLog(t, "cert-renewal-scan")
	if !strings.Contains(log, "无临期证书") {
		t.Fatalf("cert-renewal-scan 摘要行缺失: %q", log)
	}
}

// Given audit-retention 已在引擎注册（真实 Run 体：CleanupAuditLogs→
// PurgeTaskRuns→TaskLogf），库中含过期审计行。
// When 经引擎 Trigger 执行真实 Run 体（U1-66-10 接线钉——曾由测试自调
// CleanupAuditLogs+自写 TaskLogf，删 Run 体内 TaskLogf 调用不会红）。
// Then tasks/audit-retention.log 含 Run 体写出的带删除条数的结论行。
func TestTaskLogf_AuditRetentionCleanupSummary(t *testing.T) {
	newTaskLogDir(t)
	te := newWireTestEngine(t)
	// seed 全局配置行（retention 读取）与过期审计行（audit 库）
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO global_config (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES ('u','登录','认证','','','2020-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if err := te.Trigger("audit-retention", "manual", ""); err != nil {
		t.Fatalf("trigger audit-retention: %v", err)
	}
	log := readTaskLog(t, "audit-retention")
	if !strings.Contains(log, "清理完成：审计日志 1 条") {
		t.Fatalf("audit-retention Run 体摘要行缺失（接线断）: %q", log)
	}
}

// Given config-watchdog 已在引擎注册（真实 Run 体：WatchdogCheckOnce——R66 起
// 一致轮零逐轮行，每 60 轮一条心跳；漂移轮逐轮行不变）。
// When 经引擎 Trigger 连打 60 轮真实 Run 体（U1-66-10 接线钉——假 Caddy 提供
// 空运行配置、空规则库 → 每轮真实完成且一致；U12-F02 起跳过轮不计入干净轮，
// 心跳必须由真实检查轮驱动）。
// Then tasks/config-watchdog.log 恰含一条「配置一致（心跳…）」结论行。
func TestTaskLogf_WatchdogSummaryShape(t *testing.T) {
	newTaskLogDir(t)
	resetConfigWatchdogForTest(t)
	te := newWireTestEngine(t)
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	oldURL := watchdogAdminURLValue
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	for i := 1; i <= 60; i++ {
		if err := te.Trigger("config-watchdog", "manual", ""); err != nil {
			t.Fatalf("trigger config-watchdog: %v", err)
		}
	}
	log := readTaskLog(t, "config-watchdog")
	if got := strings.Count(log, "配置一致（心跳，近 60 轮无漂移）"); got != 1 {
		t.Fatalf("watchdog 心跳行=%d, want 1（接线断或心跳窗口失准）: %q", got, log)
	}
	if !strings.Contains(log, "[INFO]") {
		t.Fatalf("watchdog 摘要行形态不符: %q", log)
	}
}

// R66 收敛（2026-10-03 裁定）：cert-manual-poll 全正常轮（无过期无临期）零任务
// 日志行；仅异常轮（过期或临期>0）记一行带计数的业务结论行。
func TestTaskLogf_CertManualPoll_exceptionRoundsOnly(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	lastCertServiceMissing.Store(false)
	SetActiveCertificateService(NewCertificateService())
	t.Cleanup(func() { SetActiveCertificateService(nil) })
	oldWriter := log.Writer()
	var buf strings.Builder
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// Given：一张 3650 天后才过期的手动证书（全正常形态）。
	farPEM, _ := expiredShapeCertAndKey(t, "manual-far66.test", time.Now().Add(3650*24*time.Hour))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert) VALUES ('lb_manual_far66','manual-far66','manual-far66.test','http',8080,1,1,'manual',?)`, farPEM); err != nil {
		t.Fatal(err)
	}

	// When：全正常轮。Then：零任务日志行（原「共 N 张，无过期无临期」行删除）。
	CertManualCheckOnce()
	if data, err := os.ReadFile(taskengine.TaskLogPath("cert-manual-poll")); err == nil && strings.Contains(string(data), "手动证书到期检查") {
		t.Fatalf("全正常轮不得写任务日志行: %q", string(data))
	}

	// Given：叠加一张 10 天后过期的手动证书（默认阈值 30 天内 → 临期）。
	soonPEM, _ := expiredShapeCertAndKey(t, "manual-soon66.test", time.Now().Add(10*24*time.Hour))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert) VALUES ('lb_manual_soon66','manual-soon66','manual-soon66.test','http',8080,1,1,'manual',?)`, soonPEM); err != nil {
		t.Fatal(err)
	}

	// When：异常轮。Then：恰一行带计数结论。
	CertManualCheckOnce()
	logStr := readTaskLog(t, "cert-manual-poll")
	if got := strings.Count(logStr, "手动证书到期检查"); got != 1 {
		t.Fatalf("异常轮结论行=%d, want 1: %q", got, logStr)
	}
	if !strings.Contains(logStr, "0 张已过期、1 张临期") {
		t.Fatalf("结论行计数不符: %q", logStr)
	}
}

// Given v2.0 四类型标准全量注册。
// When DescribeAll。
// Then Kind 映射：定时 5（threat/crs/ip2region/crawlerbot-update/auto-backup）、循环 9、
// 常驻 3（ingestion/cert-issuance/cluster-sync）、触发 1（startup:config-load）；
// cert-waiting-ca 默认 LoopOn=false（调度关闭——续期扫描唤醒）。
func TestTaskEngineWire_KindMapping(t *testing.T) {
	te := newWireTestEngine(t)
	got := map[string]taskengine.TaskMeta{}
	for _, m := range te.DescribeAll() {
		got[m.ID] = m
	}
	want := map[string]taskengine.Kind{
		"threat": taskengine.KindScheduled, "crs": taskengine.KindScheduled,
		"ip2region": taskengine.KindScheduled, "auto-backup": taskengine.KindScheduled,
		"crawlerbot-update": taskengine.KindScheduled,
		"config-watchdog":   taskengine.KindPeriodic, "log-cleanup": taskengine.KindPeriodic,
		"audit-retention": taskengine.KindPeriodic, "security-events-retention": taskengine.KindPeriodic,
		"cert-renewal-scan": taskengine.KindPeriodic, "cert-reconcile": taskengine.KindPeriodic,
		"cert-manual-poll": taskengine.KindPeriodic, "cert-waiting-ca": taskengine.KindPeriodic,
		"autoban":                   taskengine.KindPeriodic,
		"security-events-ingestion": taskengine.KindDaemon, "cert-issuance": taskengine.KindDaemon,
		"cluster-sync":        taskengine.KindDaemon,
		"startup:config-load": taskengine.KindOneshot,
	}
	for id, kind := range want {
		m, ok := got[id]
		if !ok {
			t.Errorf("%s 未注册", id)
			continue
		}
		if m.Kind != kind {
			t.Errorf("%s Kind=%s, want %s", id, m.Kind, kind)
		}
	}
	if m, ok := got["cert-waiting-ca"]; ok && m.LoopOn {
		t.Error("cert-waiting-ca 默认调度应关闭（LoopOn=false，续期扫描唤醒）")
	}
}

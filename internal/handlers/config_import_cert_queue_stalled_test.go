package handlers

// 导入/还原时「证书签发任务已被用户停止」的边界披露。
//
// 设计边界（有意保留）：importQueueRecovery.finish 在导入前队列未激活时**不**
// 重排备份带来的非终态 cert_jobs——不越过用户「停止签发」的意图，无数据丢失。
// 缺陷只是「无任何提示」：任务列表显示进行中，实际没有 worker 推进，等待中的
// 管理员会误以为签发在跑。修复=导入成功响应的 warnings 与操作审计双通道披露
// 数量（文案单源 importQueueRecovery.stalledWarning）。
//
// 两个方向都必须钉住：队列未激活必须有披露（否则回到静默边界），队列激活时
// 不得出现该披露（否则每次正常导入都误报）。

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// stalledCertQueueBackup 构造一份含「启用 ACME 规则 + 非终态证书任务」的备份，
// 任务状态取签发链中段的 creating_order（无 worker 就永远不会推进）。
func stalledCertQueueBackup(t *testing.T) string {
	t.Helper()
	return buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_stalledacme", "name": "stalledacme", "protocol": "http", "domain": "stalled.example.test",
				"listen_port": 8499, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 96},
		},
		"certificate_configs": {
			{"id": 96, "name": "stalled-dns", "dns_provider": "dnspod", "enabled": 1},
		},
		"cert_jobs": {
			{"rule_id": "lb_stalledacme", "domain": "stalled.example.test", "status": "creating_order"},
		},
	}, EmptyConfigIfNil: true})
}

// Given 证书队列未激活（等价于管理员在任务监控里停止了「证书签发」）。
// When 导入含一条非终态证书任务的备份。
// Then 导入成功、任务行保持原状态（未被越过停止意图重排），且响应 warnings
// 点名「1 个非终态证书任务因证书签发任务已停止而未重排」。
func TestImportConfigBackup_warnsWhenCertQueueStopped(t *testing.T) {
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir()) // 未 Start = inactive
	t.Cleanup(services.ResetCAQueueManagerForTest)

	h := newBackupTestHandlers(t)
	response := postBackupImport(t, h, stalledCertQueueBackup(t))

	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	// 前置：任务行确实以非终态落库（否则「未重排」披露没有对象，断言会空转）。
	var status string
	if err := db.DB.QueryRow(`SELECT status FROM cert_jobs WHERE rule_id='lb_stalledacme'`).Scan(&status); err != nil {
		t.Fatalf("read imported cert job: %v", err)
	}
	if status != "creating_order" {
		t.Fatalf("导入的任务状态=%q, want creating_order（队列停止时不得推进状态）", status)
	}

	warnings := decodeImportWarnings(t, response)
	needle := "1 个非终态证书任务因证书签发任务已停止而未重排"
	if !warningsContain(warnings, needle) {
		t.Fatalf("warnings=%v, want 含 %q（队列停止时不重排必须有披露）", warnings, needle)
	}

	// 双通道披露（生产 config_backup.go 的 stalledWarning 分支）：响应 warnings
	// 之外必须落操作审计，否则事后只能看到「任务列表显示进行中」而无法追溯
	// 来源。只断言 warnings 时删掉 recordAudit 用例仍全绿。
	auditRows, auditDetail := stalledCertAuditRows(t)
	if auditRows != 1 {
		t.Fatalf("停滞披露审计行=%d, want 1（warnings 之外必须有操作审计）detail=%q", auditRows, auditDetail)
	}
	if !strings.Contains(auditDetail, needle) {
		t.Fatalf("审计 detail=%q, want 与 warnings 同文（含 %q）", auditDetail, needle)
	}
}

// stalledCertAuditRows 返回「证书任务停滞」披露在操作审计里的行数与首条
// detail（文案单源：stalledWarning 同时供给响应与审计）。
func stalledCertAuditRows(t *testing.T) (int, string) {
	t.Helper()
	var count int
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(detail), '') FROM audit_log
		WHERE resource='配置备份' AND detail LIKE '%非终态证书任务%'`).Scan(&count, &detail); err != nil {
		t.Fatalf("read stalled cert audit: %v", err)
	}
	return count, detail
}

// Given 证书队列激活（导入前队列正常运行）。
// When 导入同一份备份。
// Then 不得出现「因证书签发任务已停止而未重排」的披露——否则每次正常导入都
// 误报（披露本身失去意义）。
func TestImportConfigBackup_noStalledWarningWhenCertQueueActive(t *testing.T) {
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)

	h := newBackupTestHandlers(t)
	response := postBackupImport(t, h, stalledCertQueueBackup(t))

	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	warnings := decodeImportWarnings(t, response)
	if warningsContain(warnings, "未重排") {
		t.Fatalf("warnings=%v, want 无「未重排」披露（队列激活时导入会重排非终态任务）", warnings)
	}
	// 审计通道同样不得误报（否则每次正常导入都在操作日志里留下停滞告警）。
	if rows, detail := stalledCertAuditRows(t); rows != 0 {
		t.Fatalf("队列激活时停滞披露审计行=%d, want 0（detail=%q）", rows, detail)
	}
}

// 文案单源自检：披露句里的数量必须取自实测统计（不是写死的 1），
// 多行任务时数量随之变化——否则「N 个」会与实际停滞任务数脱节。
func TestImportConfigBackup_stalledWarningCountsAllNonTerminalJobs(t *testing.T) {
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(services.ResetCAQueueManagerForTest)

	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_stalleda", "name": "stalleda", "protocol": "http", "domain": "stal2.example.test",
				"listen_port": 8497, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 97},
			{"caddy_id": "lb_stalledb", "name": "stalledb", "protocol": "http", "domain": "stal3.example.test",
				"listen_port": 8498, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 97},
		},
		"certificate_configs": {
			{"id": 97, "name": "stalled-dns-2", "dns_provider": "dnspod", "enabled": 1},
		},
		"cert_jobs": {
			{"rule_id": "lb_stalleda", "domain": "stal2.example.test", "status": "creating_order"},
			{"rule_id": "lb_stalledb", "domain": "stal3.example.test", "status": "waiting_ca"},
		},
	}, EmptyConfigIfNil: true})

	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	needle := strconv.Itoa(2) + " 个非终态证书任务因证书签发任务已停止而未重排"
	if warnings := decodeImportWarnings(t, response); !warningsContain(warnings, needle) {
		t.Fatalf("warnings=%v, want 含 %q（数量必须为实测停滞任务数）", warnings, needle)
	}
	if !strings.Contains(strings.Join(decodeImportWarnings(t, response), "\n"), "恢复该任务后才会继续推进") {
		t.Fatalf("warnings 缺少可操作指引（恢复签发任务后才会推进）")
	}
}

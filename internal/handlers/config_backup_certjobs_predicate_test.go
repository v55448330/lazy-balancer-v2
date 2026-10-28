package handlers

// 导入侧证书任务清理缺口——备份可携带「规则存在但已非
// ACME 自动签发态」的 cert_jobs 行（如 manual 来源规则带任务行）。导入侧的
// 孤儿清理只删「rule_id 不在 lb_rules 中」的行，对这类「规则仍在但已非 ACME」
// 的行不覆盖；残留任务会被续签扫描/任务列表当作活任务（与续签扫描口径
// `enable_tls=1 AND tls_source='acme_dns'` 相悖；禁用但 acme 态的规则任务行保留
// （DisableRule 再启用续期语义，cert_jobs 无补建路径——主审裁定收窄）。
// 修复=导入后追加同谓词清理（v2 导入事务 + v1 协调器后处理两处同语句）。

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestImportConfigBackup_purgesCertJobsOfNonACMERules(t *testing.T) {
	// Given：备份含一条 manual 来源规则 + 其 cert_jobs 行（规则非 ACME 态），
	// 以及一条启用 ACME 规则的任务行（导入后必须保留）——后者是清理断言的
	// 前置：若生产不再导入 cert_jobs，「清理后 0 行」会因为表本来就空而恒真；
	// 保留行同时为 0 时立即暴露导入侧断链。
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_manualrule", "name": "manualrule", "protocol": "http", "domain": "manual.example.test",
				"listen_port": 8080, "enabled": 1, "enable_tls": 0, "tls_source": "manual"},
			{"caddy_id": "lb_nulltls", "name": "nulltls", "protocol": "http", "domain": "nulltls.example.test",
				"listen_port": 8083, "enabled": 1, "enable_tls": nil, "tls_source": "acme_dns"},
			{"caddy_id": "lb_acmerule", "name": "acmerule", "protocol": "http", "domain": "acmerule.example.test",
				"listen_port": 8463, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 92},
		},
		"certificate_configs": {
			{"id": 92, "name": "acmerule-dns", "dns_provider": "dnspod", "enabled": 1},
		},
		"cert_jobs": {
			{"rule_id": "lb_manualrule", "domain": "manual.example.test", "status": "issued"},
			{"rule_id": "lb_nulltls", "domain": "nulltls.example.test", "status": "issued"},
			{"rule_id": "lb_acmerule", "domain": "acmerule.example.test", "status": "queued"},
		},
	}, EmptyConfigIfNil: true})
	// 夹具自检：三条任务行都必须在备份里，清理断言才有判别力。
	var fixture configBackup
	if err := json.Unmarshal([]byte(backup), &fixture); err != nil {
		t.Fatalf("parse backup fixture: %v", err)
	}
	if got := len(fixture.Tables["cert_jobs"]); got != 3 {
		t.Fatalf("fixture cert_jobs rows=%d, want 3（含将被清理的 manual/NULL 行与必须保留的 ACME 行）", got)
	}

	// When
	response := postBackupImport(t, h, backup)

	// Then：导入成功、规则保留；ACME 规则的任务行保留（证明备份行确实落库），
	// manual 规则的任务行被清理。
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var ruleCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_manualrule'`).Scan(&ruleCount); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if ruleCount != 1 {
		t.Fatalf("manual rule rows=%d, want 1（规则本身须保留）", ruleCount)
	}
	var keptJobs int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_acmerule'`).Scan(&keptJobs); err != nil {
		t.Fatalf("read ACME cert_jobs: %v", err)
	}
	if keptJobs != 1 {
		t.Fatalf("启用 ACME 规则的 cert_jobs 行=%d, want 1（前置：备份任务行须真实落库）", keptJobs)
	}
	var jobCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id IN ('lb_manualrule','lb_nulltls')`).Scan(&jobCount); err != nil {
		t.Fatalf("read cert_jobs: %v", err)
	}
	if jobCount != 0 {
		t.Fatalf("非 ACME/NULL 来源规则的 cert_jobs 行=%d, want 0（导入须清理失效任务）", jobCount)
	}
}

// 收窄裁定（主审，2026-10-13）：禁用但仍 acme_dns 态的规则，其 disabled 任务行
// **保留**——DisableRule 刻意保留行供再启用续期（cert_jobs 无自动补建路径）。
func TestImportConfigBackup_keepsDisabledACMERuleCertJobs(t *testing.T) {
	// Given：备份含一条禁用但 acme_dns 态规则 + 其 cert_jobs 行
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_disabledacme", "name": "disabledacme", "protocol": "http", "domain": "disacme.example.test",
				"listen_port": 8081, "enabled": 0, "enable_tls": 1, "tls_source": "acme_dns"},
		},
		"cert_jobs": {
			{"rule_id": "lb_disabledacme", "domain": "disacme.example.test", "status": "disabled"},
		},
	}, EmptyConfigIfNil: true})

	// When
	response := postBackupImport(t, h, backup)

	// Then：导入成功且任务行保留（再启用续期链不断）
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var jobCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_disabledacme'`).Scan(&jobCount); err != nil {
		t.Fatalf("read cert_jobs: %v", err)
	}
	if jobCount != 1 {
		t.Fatalf("禁用 ACME 规则的 cert_jobs 行=%d, want 1（保留供再启用续期）", jobCount)
	}
}

func TestValidateV2BackupCertJobs_canonicalizesStoredDomain(t *testing.T) {
	const rawDomain = "WWW.JobDomain.example.test,JOBDOMAIN.example.test"
	if got := canonicalACMEDomainForJobLookup(rawDomain); got != "jobdomain.example.test,www.jobdomain.example.test" {
		t.Fatalf("canonical helper returned %q", got)
	}
	tables := map[string][]map[string]any{
		"lb_rules": {{
			"caddy_id": "lb_jobdomain", "name": "jobdomain", "protocol": "http",
			"domain": "WWW.JobDomain.example.test, jobdomain.example.test", "enabled": 0,
			"enable_tls": 1, "tls_source": "acme_dns",
		}},
		"cert_jobs": {{
			"rule_id": "lb_jobdomain", "domain": " WWW.JobDomain.example.test, JOBDOMAIN.example.test ", "status": "disabled",
		}},
	}
	if _, err := validateV2BackupCertJobs(tables); err != nil {
		t.Fatalf("validate cert jobs: %v", err)
	}
	if got := tables["cert_jobs"][0]["domain"]; got != "jobdomain.example.test,www.jobdomain.example.test" {
		t.Fatalf("normalized domain=%v, want canonical", got)
	}
}

func TestImportConfigBackup_canonicalizesACMEJobDomains(t *testing.T) {
	// Given a disabled ACME rule whose resumable job uses a case/order-variant domain.
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {{
			"caddy_id": "lb_jobdomain", "name": "jobdomain", "protocol": "http",
			"domain": "WWW.JobDomain.example.test, jobdomain.example.test", "listen_port": 8082,
			"enabled": 0, "enable_tls": 1, "tls_source": "acme_dns",
		}},
		"cert_jobs": {{
			"rule_id": "lb_jobdomain", "domain": " WWW.JobDomain.example.test, JOBDOMAIN.example.test ", "status": "disabled",
		}},
	}, EmptyConfigIfNil: true})

	// When importing the backup.
	response := postBackupImport(t, h, backup)

	// Then the sole resumable job is stored under the canonical lookup key.
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var domain string
	var count int
	if err := db.DB.QueryRow(`SELECT domain, COUNT(*) FROM cert_jobs WHERE rule_id='lb_jobdomain'`).Scan(&domain, &count); err != nil {
		t.Fatalf("read imported cert job: %v", err)
	}
	if count != 1 || domain != "jobdomain.example.test,www.jobdomain.example.test" {
		t.Fatalf("cert jobs count=%d domain=%q, want one canonical domain", count, domain)
	}
}

// cert_jobs.ca_provider_id 参与导入期可解析性校验：悬挂/已禁用引用会让
// 非终态任务首次入队即落 failed 终态（loadCAProvider 对「存在但禁用」显性
// 报错）——导入期归一为 0（跟随默认）并产出警告，而不是静默带入运行态。
func TestValidateV2BackupCertJobs_normalizesDanglingCAProvider(t *testing.T) {
	enabledACMERule := map[string]any{
		"caddy_id": "bak-acme", "name": "bak-acme", "protocol": "http",
		"domain": "jobdomain.example.test", "enabled": int64(1), "enable_tls": int64(1), "tls_source": "acme_dns",
		"acme_config_id": int64(3),
	}
	jobWithProvider := func(id any) map[string]any {
		return map[string]any{"rule_id": "bak-acme", "domain": "jobdomain.example.test", "status": "queued", "ca_provider_id": id}
	}

	t.Run("已禁用提供商归一为跟随默认", func(t *testing.T) {
		job := jobWithProvider(int64(9))
		tables := map[string][]map[string]any{
			"lb_rules":            {enabledACMERule},
			"cert_jobs":           {job},
			"ca_providers":        {{"id": int64(9), "enabled": int64(0)}},
			"certificate_configs": {{"id": int64(3), "enabled": int64(1)}},
		}
		warnings, err := validateV2BackupCertJobs(tables)
		if err != nil {
			t.Fatalf("unexpected rejection: %v", err)
		}
		if got := job["ca_provider_id"]; got != 0 {
			t.Fatalf("ca_provider_id=%v, want 0（归一跟随默认）", got)
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], "CA 提供商") {
			t.Fatalf("warnings=%v, want 1 条提供商归一警告", warnings)
		}
	})

	t.Run("悬挂引用同样归一", func(t *testing.T) {
		job := jobWithProvider(int64(99))
		tables := map[string][]map[string]any{
			"lb_rules":            {enabledACMERule},
			"cert_jobs":           {job},
			"ca_providers":        {{"id": int64(9), "enabled": int64(1)}},
			"certificate_configs": {{"id": int64(3), "enabled": int64(1)}},
		}
		warnings, err := validateV2BackupCertJobs(tables)
		if err != nil {
			t.Fatalf("unexpected rejection: %v", err)
		}
		if got := job["ca_provider_id"]; got != 0 {
			t.Fatalf("ca_provider_id=%v, want 0（悬挂归一）", got)
		}
		if len(warnings) != 1 {
			t.Fatalf("warnings=%v, want 1 条警告", warnings)
		}
	})

	t.Run("启用提供商不受影响", func(t *testing.T) {
		job := jobWithProvider(int64(9))
		tables := map[string][]map[string]any{
			"lb_rules":            {enabledACMERule},
			"cert_jobs":           {job},
			"ca_providers":        {{"id": int64(9), "enabled": int64(1)}},
			"certificate_configs": {{"id": int64(3), "enabled": int64(1)}},
		}
		warnings, err := validateV2BackupCertJobs(tables)
		if err != nil {
			t.Fatalf("unexpected rejection: %v", err)
		}
		if got := job["ca_provider_id"]; got != int64(9) {
			t.Fatalf("ca_provider_id=%v, want 9（启用引用保持）", got)
		}
		if len(warnings) != 0 {
			t.Fatalf("warnings=%v, want 空", warnings)
		}
	})

	t.Run("无提供商引用零告警零数据库依赖", func(t *testing.T) {
		job := map[string]any{"rule_id": "bak-acme", "domain": "jobdomain.example.test", "status": "queued"}
		tables := map[string][]map[string]any{
			"lb_rules":            {enabledACMERule},
			"cert_jobs":           {job},
			"certificate_configs": {{"id": int64(3), "enabled": int64(1)}},
		}
		warnings, err := validateV2BackupCertJobs(tables)
		if err != nil || len(warnings) != 0 {
			t.Fatalf("warnings=%v err=%v, want 空/nil（无引用不得触碰 ca_providers）", warnings, err)
		}
	})
}

// certJobsWindowBackup 构造「携带启用 ACME 规则、但整个 cert_jobs 表缺席」的
// 备份——缺席=保留本地任务行，启用规则的不变量因此依赖 live 行（正常导出
// 的 rules 分类恒含 cert_jobs，该形态只来自手改备份或史前文件）。只选
// rules 分类可避开全量形态的必需表门。
func certJobsWindowBackup(t *testing.T) string {
	t.Helper()
	return buildBackup(t, backupFixtureOptions{
		Sections: []string{"rules"},
		Tables: map[string][]map[string]any{
			"lb_rules": {{
				"caddy_id": "lb_winjob", "name": "winjob", "protocol": "http", "domain": "winjob.example.test",
				"listen_port": 8465, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 92,
			}},
		},
		EmptyConfigIfNil: true,
	})
}

func seedLiveCertJobWindow(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_winjob','winjob.example.test','queued')`); err != nil {
		t.Fatalf("seed live cert job: %v", err)
	}
}

// 备份未携带 cert_jobs 时任务行保持 live：初检按锁外本地行放行，导入成功后
// 规则与本地任务行共存（正例，证明不变量读的是 live 行）。
func TestImportConfigBackup_liveCertJobsSatisfyCertJobInvariant(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	seedLiveCertJobWindow(t)

	response := postImportBytes(t, h, []byte(certJobsWindowBackup(t)))

	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（live 任务行满足不变量）", response.Code, response.Body.String())
	}
	var ruleCount, jobCount int
	if err := db.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_winjob'),
		(SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_winjob')`).Scan(&ruleCount, &jobCount); err != nil {
		t.Fatalf("read post-import state: %v", err)
	}
	if ruleCount != 1 || jobCount != 1 {
		t.Fatalf("rules=%d jobs=%d, want 1/1（缺席表保留本地任务行）", ruleCount, jobCount)
	}
}

// 初检→加锁窗口内并发删除 live 任务行：锁内必须按事务视图重跑不变量，否则
// 「规则启用但无续签行」的断链状态会静默落库（周期扫描只遍历已存在任务行，
// 不补建），证书到期后 TLS 端口无证书可用且无失败信号。
func TestImportConfigBackup_lockRecheckRejectsCertJobDeletionDuringWindow(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	seedLiveCertJobWindow(t)
	oldHook := configImportBeforeLock
	configImportBeforeLock = func() {
		// 初检已按锁外 live 任务行放行；窗口内删除该任务行。
		if _, err := db.DB.Exec(`DELETE FROM cert_jobs WHERE rule_id='lb_winjob'`); err != nil {
			t.Errorf("simulate window deletion: %v", err)
		}
	}
	t.Cleanup(func() { configImportBeforeLock = oldHook })

	response := postImportBytes(t, h, []byte(certJobsWindowBackup(t)))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（锁内证书任务复核）", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "实时数据已变化") || !strings.Contains(body, "winjob") || !strings.Contains(body, "缺少证书签发任务") {
		t.Fatalf("body=%s, want 点名实时数据变化与缺少任务的规则", body)
	}
	var ruleCount, jobCount int
	if err := db.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_winjob'),
		(SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_winjob')`).Scan(&ruleCount, &jobCount); err != nil {
		t.Fatalf("read post-reject state: %v", err)
	}
	if ruleCount != 0 || jobCount != 0 {
		t.Fatalf("rules=%d jobs=%d, want 0/0（锁内复核拒绝须整包回滚）", ruleCount, jobCount)
	}
}

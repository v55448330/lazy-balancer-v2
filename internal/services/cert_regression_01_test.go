package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 提升/启动时为主从快照未携带任务行的启用 ACME 规则补建 queued 行，
// 否则续期/首发重试/补扫/对账全部 JOIN cert_jobs，自动签发链静默中断。
func TestBackfillMissingACMECertJobs_CreatesRowsForEnabledACMERules(t *testing.T) {
	_, database := newClusterTestService(t)
	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := database.Exec(query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}
	mustExec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source) VALUES
		('lb_bf_a','a','http','a.example',8443,1,1,'acme_dns'),
		('lb_bf_b','b','http','b.example',8443,1,1,'acme_dns'),
		('lb_bf_c','c','http','c.example',8443,0,1,'acme_dns'),
		('lb_bf_d','d','http','d.example',8443,1,1,'manual'),
		('lb_bf_e','e','http','e.example',8443,1,1,'acme_dns')`)
	mustExec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_bf_b','b.example','issued')`)
	mustExec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_bf_e','e.example','disabled')`)

	created, err := BackfillMissingACMECertJobs(context.Background(), nil)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if created != 2 {
		t.Fatalf("created=%d, want 2（lb_bf_a 新行 + lb_bf_e disabled 复活）", created)
	}
	for ruleID, want := range map[string]string{
		"lb_bf_a": "queued",
		"lb_bf_b": "issued",
		"lb_bf_e": "queued",
	} {
		var status string
		if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&status); err != nil {
			t.Fatalf("read %s: %v", ruleID, err)
		}
		if status != want {
			t.Fatalf("%s status=%q, want %q", ruleID, status, want)
		}
	}
	for _, ruleID := range []string{"lb_bf_c", "lb_bf_d"} {
		var n int
		if err := database.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", ruleID, err)
		}
		if n != 0 {
			t.Fatalf("%s 不应补建任务（禁用规则/非 ACME），got %d", ruleID, n)
		}
	}

	// 幂等：第二次收敛为 0。
	created, err = BackfillMissingACMECertJobs(context.Background(), nil)
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if created != 0 {
		t.Fatalf("second created=%d, want 0", created)
	}
}

// 执行超时发生在材料已落库后必须保持可部署态（否则 failJob 把新证书
// 打成终态，续期/首发重试/补扫/对账全部不可达）。
func TestHandleExecutionTimeout_KeepsDownloadedMaterialDeployable(t *testing.T) {
	_, database := newClusterTestService(t)
	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := database.Exec(query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}
	mustExec(`INSERT INTO cert_jobs (id,rule_id,domain,status,cert_pem,key_pem) VALUES (901,'lb_to_1','to1.example','downloaded','CERT','KEY')`)
	mustExec(`INSERT INTO cert_jobs (id,rule_id,domain,status) VALUES (902,'lb_to_2','to2.example','creating_order')`)

	handleExecutionTimeout(901)
	var status, message string
	var availableAfter *string
	if err := database.QueryRow("SELECT status,message,deployment_available_after FROM cert_jobs WHERE id=901").Scan(&status, &message, &availableAfter); err != nil {
		t.Fatalf("read job 901: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("job 901 status=%q, want downloaded（材料在身不得终态化）", status)
	}
	if availableAfter == nil || *availableAfter == "" {
		t.Fatal("job 901 deployment_available_after 必须置为 now 以触发部署重试")
	}
	if !strings.Contains(message, "执行超时") {
		t.Fatalf("job 901 message=%q, want 含执行超时说明", message)
	}

	handleExecutionTimeout(902)
	var noMaterialStatus string
	var attempts int
	if err := database.QueryRow("SELECT status,COALESCE(renewal_attempts,0) FROM cert_jobs WHERE id=902").Scan(&noMaterialStatus, &attempts); err != nil {
		t.Fatalf("read job 902: %v", err)
	}
	if noMaterialStatus != "failed" {
		t.Fatalf("job 902 status=%q, want failed（无材料维持 failJob 语义）", noMaterialStatus)
	}
	if attempts != 1 {
		t.Fatalf("job 902 renewal_attempts=%d, want 1", attempts)
	}
}

// waitDoneOrTimeout 超时后必须放弃本轮部署重试调度，不得以
// cancelWaitTimeout 周期无限循环。
func TestScheduleDeploymentRetry_AbandonsRoundWhenCallbackStuck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service := &CertificateService{
		ctx:                 ctx,
		cancel:              cancel,
		deploymentTimers:    make(map[int]*deploymentTimer),
		deploymentCallbacks: make(map[int]map[*deploymentTimer]struct{}),
		cancelWaitTimeout:   50 * time.Millisecond,
		retryDeployment:     func(context.Context, int) error { return nil },
	}
	entry := &deploymentTimer{done: make(chan struct{}), ruleID: "lb_stuck"}
	entry.ctx, entry.cancel = context.WithCancel(ctx)
	service.deploymentCallbacks[7] = map[*deploymentTimer]struct{}{entry: {}}
	t.Cleanup(func() { close(entry.done) })

	started := time.Now()
	service.scheduleDeploymentRetry(7, "lb_stuck", time.Hour)
	elapsed := time.Since(started)
	if elapsed > 2*time.Second {
		t.Fatalf("scheduleDeploymentRetry 耗时 %s，疑似超时后继续循环", elapsed)
	}
	if !entry.canceled {
		t.Fatal("在途回调必须被取消")
	}
	service.timerMu.Lock()
	timers := len(service.deploymentTimers)
	service.timerMu.Unlock()
	if timers != 0 {
		t.Fatalf("放弃本轮调度后不应创建 timer，got %d", timers)
	}
}

func TestCancelJobsForRule_UsesSingleSharedDeadline(t *testing.T) {
	saved := caCancelWaitTimeout
	caCancelWaitTimeout = 40 * time.Millisecond
	t.Cleanup(func() { caCancelWaitTimeout = saved })

	queue := &caQueue{
		executionDone: map[int]chan struct{}{
			1: make(chan struct{}),
			2: make(chan struct{}),
			3: make(chan struct{}),
		},
		runningRules: map[int]string{1: "lb_multi", 2: "lb_multi", 3: "lb_multi"},
		cancels: map[int]context.CancelFunc{
			1: func() {}, 2: func() {}, 3: func() {},
		},
	}
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}

	started := time.Now()
	err := manager.CancelJobsForRule(context.Background(), "lb_multi")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel rule jobs error=%v, want shared-deadline failure instead of pseudo-success", err)
	}
	elapsed := time.Since(started)
	// 逐 job 串行 = 3×40ms；共享截止 = ~40ms。留足调度余量。
	if elapsed > 100*time.Millisecond {
		t.Fatalf("取消等待耗时 %s，want 单次共享截止（3×40ms → ~40ms）", elapsed)
	}
}

// 水位线槽以触发时刻计算，跨槽边界完成不得写成未执行的新槽。
func TestAutoBackupWatermarkSlot_UsesTriggerTime(t *testing.T) {
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily',
		auto_backup_time='03:00', auto_backup_last_run='2025-12-31T03:00:00Z' WHERE id=1`); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	trigger := time.Date(2026, 1, 2, 2, 58, 0, 0, time.UTC)
	slot, ok := autoBackupWatermarkSlot(trigger)
	if !ok {
		t.Fatal("trigger slot ok=false, want true")
	}
	want := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	if !slot.Equal(want) {
		t.Fatalf("watermark slot=%v, want %v（触发时刻的最近过去槽）", slot, want)
	}
	// 执行体必须使用触发时刻（旧实现用完成时刻 time.Now() 重算：跨过 03:00
	// 边界会把今日未执行的槽写成已跑，静默漏跑）。
	advanceAutoBackupWatermark(trigger)
	var stored string
	if err := db.DB.QueryRow("SELECT auto_backup_last_run FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatalf("read watermark: %v", err)
	}
	parsed, err := time.Parse(time.RFC3339, stored)
	if err != nil || !parsed.Equal(want) {
		t.Fatalf("watermark=%q (%v), want %v（不得用完成时刻）", stored, err, want)
	}
	if _, ok := autoBackupWatermarkSlot(trigger); ok {
		t.Fatal("last_run 已覆盖触发槽时不得再次推进")
	}
}

func TestBumpClusterVersion_MissingGlobalConfigFails(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("DELETE FROM global_config WHERE id=1"); err != nil {
		t.Fatalf("delete global_config: %v", err)
	}
	if err := BumpClusterVersion(context.Background(), database); err == nil {
		t.Fatal("missing global_config row must fail visibly")
	}
}

func TestReconcileBrandingFileDB_RestoresMissingAndCorruptFile(t *testing.T) {
	_, database := newClusterTestService(t)
	content := `{"app_name":"A","footer_text":"F","landing_text":"L","version":"1"}`
	if _, err := database.Exec(`UPDATE global_config SET branding_json=? WHERE id=1`, content); err != nil {
		t.Fatalf("seed branding_json: %v", err)
	}
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "branding.json")

	healed, err := ReconcileBrandingFileDB(database, dataDir)
	if err != nil {
		t.Fatalf("reconcile missing file: %v", err)
	}
	if !healed {
		t.Fatal("missing branding.json must be healed")
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != content {
		t.Fatalf("healed content=%q err=%v, want %q", raw, err, content)
	}
	if healed, err := ReconcileBrandingFileDB(database, dataDir); err != nil || healed {
		t.Fatalf("consistent file must not rewrite (healed=%v err=%v)", healed, err)
	}
	if err := os.WriteFile(path, []byte("{corrupted"), 0o644); err != nil {
		t.Fatalf("corrupt branding.json: %v", err)
	}
	if healed, err := ReconcileBrandingFileDB(database, dataDir); err != nil || !healed {
		t.Fatalf("corrupt file must be healed (healed=%v err=%v)", healed, err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != content {
		t.Fatalf("restored content=%q err=%v, want %q", raw, err, content)
	}
}

// 禁用被启用中 ACME 规则引用的 CA 提供商必须拒绝（409 语义）。
func TestUpdateCAProvider_RejectsDisableWhenReferenced(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES (99,'LE-test','letsencrypt','https://acme-v02.api.letsencrypt.org/directory','',1,1000,1)`); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,ca_provider_id)
		VALUES ('lb_ref','ref','http','ref.example',8443,1,1,'acme_dns',99)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	service := NewCAProviderService()
	disabled := false
	_, err := service.UpdateCAProvider(99, models.UpdateCAProviderRequest{Enabled: &disabled})
	if !errors.Is(err, ErrCAProviderInUse) {
		t.Fatalf("disable referenced provider err=%v, want ErrCAProviderInUse", err)
	}
	var inUse *CAProviderInUseError
	if !errors.As(err, &inUse) || inUse.Total != 1 || len(inUse.Rules) != 1 {
		t.Fatalf("in-use detail=%+v, want 1 referenced rule", inUse)
	}
	var enabled int
	if err := database.QueryRow("SELECT enabled FROM ca_providers WHERE id=99").Scan(&enabled); err != nil {
		t.Fatalf("read provider: %v", err)
	}
	if enabled != 1 {
		t.Fatal("rejected disable must not modify provider")
	}
	// 解除引用后可正常禁用。
	if _, err := database.Exec("DELETE FROM lb_rules WHERE caddy_id='lb_ref'"); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	if _, err := service.UpdateCAProvider(99, models.UpdateCAProviderRequest{Enabled: &disabled}); err != nil {
		t.Fatalf("disable unreferenced provider: %v", err)
	}
}

// 证书文件路径字母表单源导出。
func TestValidCertRuleID(t *testing.T) {
	cases := map[string]bool{
		"lb_abc-123":            true,
		"lb.dot":                false, // 含点 ID 无法物化证书文件（导入须 fail-fast）
		"":                      false,
		strings.Repeat("a", 65): false,
		"LB":                    false, // 只允许小写字母
		"路径":                    false,
	}
	for ruleID, want := range cases {
		if got := ValidCertRuleID(ruleID); got != want {
			t.Errorf("ValidCertRuleID(%q)=%v, want %v", ruleID, got, want)
		}
	}
}

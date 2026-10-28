package services

// cert-renewal-scan 降级终态钉测：降级（入口复核/逐任务入队复核两处）统一落
// skipped 哨兵（ErrTaskSkipped，与 crs/threat 同构）——此前 return nil 落
// success，把「从节点未执行」误报为「本轮扫描成功」。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// Given 入口复核时节点已是（降级窗口翻转为）从节点。
// Then 返回 ErrTaskSkipped（引擎落 skipped 终态），不得静默 success。
func TestCertRenewalScanOnce_demoteAtEntryLandsSkipped(t *testing.T) {
	useCertSweepTickTestEnv(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	err := CertRenewalScanOnce(context.Background())

	if !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want ErrTaskSkipped（降级终态与 crs/threat 同构，不落 success）", err)
	}
}

// Given 两个临期任务，第二个任务入队前 demote（复用逐任务复核 hook 形态）。
// Then 中止轮返回 ErrTaskSkipped——旧形态 return nil 把中止轮记成 success。
func TestCertRenewalScan_demoteMidLoopLandsSkipped(t *testing.T) {
	_, database := newClusterTestService(t)
	for _, ruleID := range []string{"lb_demote_skip_a", "lb_demote_skip_b"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
			VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_provider_id) VALUES
		('lb_demote_skip_a','lb_demote_skip_a.example.com','issued',datetime('now','+1 day'),0,1),
		('lb_demote_skip_b','lb_demote_skip_b.example.com','issued',datetime('now','+2 day'),0,1)`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}
	logDir := filepath.Join(t.TempDir(), "tasks")
	oldDir := taskengine.LogDir()
	taskengine.SetLogDir(logDir)
	t.Cleanup(func() { taskengine.SetLogDir(oldDir) })

	calls := 0
	oldHook := certRenewalRoleRecheckHook
	certRenewalRoleRecheckHook = func() {
		calls++
		if calls == 2 {
			if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
				t.Errorf("demote: %v", err)
			}
		}
	}
	t.Cleanup(func() { certRenewalRoleRecheckHook = oldHook })

	resetCertificateServiceForTest(t)
	// 单例隔离：InitCAQueueManager 由 sync.Once 守卫，缺 Reset 时本用例注入的
	// no-op reloader 会泄漏到后续用例（后续 Init(真实 reloader) 静默变 no-op）。
	ResetCAQueueManagerForTest()
	t.Cleanup(ResetCAQueueManagerForTest)
	InitCAQueueManager(func() error { return nil })
	err := NewCertificateService().renewExpiringCertificates(context.Background())

	if !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want ErrTaskSkipped（降级中止轮不得落 success）", err)
	}
	// 留痕不回退：中止原因仍写任务日志。
	data, rerr := os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan"))
	if rerr != nil {
		t.Fatalf("read renewal task log: %v", rerr)
	}
	if !strings.Contains(string(data), "从节点") {
		t.Fatalf("demote 中止必须留痕: %q", string(data))
	}
	// 中止点必须落在「第二个任务入队之前」：摘要点名剩余未入队数量，且两行
	// 都保持 issued（若实现先入队再复核，第一行会被改写为 queued/failed）。
	if !strings.Contains(string(data), "剩余 1 个任务本轮未入队") {
		t.Fatalf("中止轮摘要未点明剩余未入队数量: %q", string(data))
	}
	var issued int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id IN ('lb_demote_skip_a','lb_demote_skip_b') AND status='issued'`).Scan(&issued); err != nil {
		t.Fatalf("count issued jobs: %v", err)
	}
	if issued != 2 {
		t.Fatalf("issued jobs=%d, want 2（降级中止后两行都不得被入队改写）", issued)
	}
}

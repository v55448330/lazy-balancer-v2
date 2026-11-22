package services

// 证书状态对账的写前门：对账轮次开始后节点降级/调度取消不得继续写库
// （重建证书文件 / 禁用孤儿 / 补建任务行三个写点各自复核），且中止轮摘要
// 不得谎报「状态对账完成」。

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// seedBackfillCandidateRule 播种一条「启用 ACME、无任务行」的规则——补建写点
// 是本组用例的观测面。
func seedBackfillCandidateRule(t *testing.T, ruleID string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
		t.Fatalf("seed rule %s: %v", ruleID, err)
	}
}

func countCertJobsByRule(t *testing.T, ruleID string) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id=?`, ruleID).Scan(&n); err != nil {
		t.Fatalf("count cert jobs: %v", err)
	}
	return n
}

func readCertReconcileLog(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-scan"))
	if err != nil {
		t.Fatalf("read cert-scan task log: %v", err)
	}
	return string(data)
}

// Given 补建写点前的角色复核发现节点已降级。
// Then 中止轮返回 ErrTaskSkipped、零补建、摘要写「状态对账中止」而非「完成」。
func TestCertReconcileOnce_demoteDuringRoundSkipsWrites(t *testing.T) {
	useCertSweepTickTestEnv(t)
	ResetCAQueueManagerForTest()
	t.Cleanup(ResetCAQueueManagerForTest)
	seedBackfillCandidateRule(t, "lb_gate_demote")

	oldHook := certReconcileRoleRecheckHook
	certReconcileRoleRecheckHook = func() {
		if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
			t.Errorf("demote during round: %v", err)
		}
	}
	t.Cleanup(func() { certReconcileRoleRecheckHook = oldHook })

	err := CertReconcileOnce(context.Background())

	if !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want ErrTaskSkipped（写前门发现降级→中止轮，不得 success）", err)
	}
	if got := countCertJobsByRule(t, "lb_gate_demote"); got != 0 {
		t.Fatalf("降级后补建 %d 行, want 0（从节点不得写证书任务）", got)
	}
	log := readCertReconcileLog(t)
	if !strings.Contains(log, "状态对账中止") {
		t.Fatalf("中止轮摘要缺失「状态对账中止」: %q", log)
	}
	if strings.Contains(log, "状态对账完成") {
		t.Fatalf("中止轮摘要谎报完成: %q", log)
	}
}

// 回归形状：主节点健康轮照常补建并报完成——写前门不得误伤正常轮次。
func TestCertReconcileOnce_masterRoundStillBackfills(t *testing.T) {
	useCertSweepTickTestEnv(t)
	ResetCAQueueManagerForTest()
	t.Cleanup(ResetCAQueueManagerForTest)
	seedBackfillCandidateRule(t, "lb_gate_master")

	if err := CertReconcileOnce(context.Background()); err != nil {
		t.Fatalf("CertReconcileOnce err=%v, want nil（主节点健康轮）", err)
	}
	if got := countCertJobsByRule(t, "lb_gate_master"); got != 1 {
		t.Fatalf("主节点补建 %d 行, want 1", got)
	}
	if log := readCertReconcileLog(t); !strings.Contains(log, "状态对账完成") {
		t.Fatalf("健康轮摘要缺失「状态对账完成」: %q", log)
	}
}

// Given 引擎已取消本轮（降级/导入排空/停机都会取消 RunContext）。
// Then 写点全部中止、零补建，且取消不得被映射为降级跳过哨兵。
func TestCertReconcileOnce_cancelledContextStopsWrites(t *testing.T) {
	useCertSweepTickTestEnv(t)
	ResetCAQueueManagerForTest()
	t.Cleanup(ResetCAQueueManagerForTest)
	seedBackfillCandidateRule(t, "lb_gate_cancel")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := CertReconcileOnce(ctx)

	if err == nil {
		t.Fatal("已取消的轮次必须上抛（不得记为成功）")
	}
	if errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v，取消不等于降级跳过（终态语义必须区分）", err)
	}
	if got := countCertJobsByRule(t, "lb_gate_cancel"); got != 0 {
		t.Fatalf("取消后补建 %d 行, want 0", got)
	}
	if log := readCertReconcileLog(t); !strings.Contains(log, "状态对账中止") || strings.Contains(log, "状态对账完成") {
		t.Fatalf("取消轮摘要必须归因「状态对账中止」且不得报完成: %q", log)
	}
}

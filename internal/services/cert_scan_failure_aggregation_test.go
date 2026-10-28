package services

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// noMatchingQuery 是假驱动的「永不命中」针：fakeIterErrConnector 的
// failNeedle 用 strings.Contains 匹配，空串会命中所有查询（全部返回迭代错误），
// 健康形状用例必须显式给一个不可能出现在 SQL 里的针。
const noMatchingQuery = "__no_such_query__"

// 单行读失败必须与「逐行动作失败」同权地让本轮进入失败终态：只写应用日志时
// 6h 状态对账仍报「完成」，而某行根本没被检查过——运维从任务监控看不出
// 「本轮有行未检查」。同族 rescanDroppedDeploymentRetries /
// requeueWaitingCAJobs 已按 errors.Join 上抛，本路径曾只 continue。
func TestReconcileMissingCertFiles_scanFailureJoinsError(t *testing.T) {
	newClusterTestService(t)
	// 注入「首行值不可 Scan」的结果集（驱动级异常形态；列在正常形态下不可能
	// 扫描失败，故只有驱动/连接异常可达）。
	fake := sql.OpenDB(&fakeIterErrConnector{scanFailNeedle: "FROM cert_jobs"})
	t.Cleanup(func() { _ = fake.Close() })

	rebuilt, err := reconcileMissingCertFiles(context.Background(), fake)

	if err == nil {
		t.Fatalf("rebuilt=%d err=nil, want 单行 Scan 失败上抛（本轮有行未检查）", rebuilt)
	}
	if !strings.Contains(err.Error(), "读取待对账证书任务行") {
		t.Fatalf("err=%v, want 归因到「读取待对账证书任务行」", err)
	}
}

// 回归形状：空结果集（无事可做）必须仍返回 nil——失败聚合不得把健康轮变红。
func TestReconcileMissingCertFiles_noRowsStaysClean(t *testing.T) {
	newClusterTestService(t)
	fake := sql.OpenDB(&fakeIterErrConnector{failNeedle: noMatchingQuery})
	t.Cleanup(func() { _ = fake.Close() })

	rebuilt, err := reconcileMissingCertFiles(context.Background(), fake)

	if err != nil || rebuilt != 0 {
		t.Fatalf("rebuilt=%d err=%v, want 0/nil（空结果集不是失败轮）", rebuilt, err)
	}
}

// 手动证书巡检的单行读失败必须进摘要并让本轮失败：摘要说「无过期无临期」是对
// 事实的断言，有行没检查过就不能这么说（同族解析失败行计数口径）。
func TestRunManualCertExpiryCheck_scanFailureInSummaryAndError(t *testing.T) {
	newClusterTestService(t)
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	realDB := db.DB
	fake := sql.OpenDB(&fakeIterErrConnector{scanFailNeedle: "FROM lb_rules"})
	db.DB = fake
	t.Cleanup(func() { db.DB = realDB; _ = fake.Close() })

	err := runManualCertExpiryCheck(newManualCertExpiryAlertGate())

	if err == nil {
		t.Fatal("单行 Scan 失败必须上抛（本轮结果不可信）")
	}
	if !strings.Contains(err.Error(), "读取失败") {
		t.Fatalf("err=%v, want 归因到行读取失败", err)
	}
	summary, readErr := os.ReadFile(taskengine.TaskLogPath("cert-manual-poll"))
	if readErr != nil {
		t.Fatalf("read manual poll task log: %v", readErr)
	}
	if !strings.Contains(string(summary), "行读取失败已跳过") {
		t.Fatalf("任务摘要=%q, want 标注读取失败行数（「无过期无临期」不得在存在未检查行时无条件断言）", string(summary))
	}
}

// 回归形状：无失败行时巡检仍返回 nil（失败聚合不得把健康轮变红）。
func TestRunManualCertExpiryCheck_healthyRowsStayClean(t *testing.T) {
	newClusterTestService(t)
	realDB := db.DB
	fake := sql.OpenDB(&fakeIterErrConnector{failNeedle: noMatchingQuery})
	db.DB = fake
	t.Cleanup(func() { db.DB = realDB; _ = fake.Close() })

	if err := runManualCertExpiryCheck(newManualCertExpiryAlertGate()); err != nil {
		t.Fatalf("err=%v, want nil（空结果集不是失败轮）", err)
	}
}

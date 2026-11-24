package services

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 任务监控视图的裸库读取（cert-job 行 / cert-waiting-ca 下次可用时间）在
// 关停窗口内必须 fail-visible 而非 panic：db.Close 的 SetDB(nil)+DB=nil
// 落在「判空」与「解引用」之间时，旧实现二次读包级 db.DB 会把 nil *sql.DB
// 当接收者解引用——/system/tasks 轮询与后台采集都会被整进程退出。
func TestCollectCertJobRows_shutdownBeforeQueryLogsAndReturnsEmpty(t *testing.T) {
	setupIsolatedDB(t)
	resetLogStateTransitionForTest(taskMonitorCertJobsLogKey)
	logs := captureLogf(t)
	handle := db.DB
	previous := beforeTaskMonitorCertJobsQuery
	called := false
	beforeTaskMonitorCertJobsQuery = func() {
		called = true
		db.SetDB(nil)
		db.DB = nil
		_ = handle.Close()
	}
	t.Cleanup(func() {
		beforeTaskMonitorCertJobsQuery = previous
		resetLogStateTransitionForTest(taskMonitorCertJobsLogKey)
	})

	var (
		rows      []TaskInfo
		truncated bool
	)
	autobanRequireNoPanic(t, func() { rows, truncated = collectCertJobRows() })
	if !called {
		t.Fatal("cert job rows query interleaving was not exercised")
	}
	if rows != nil || truncated {
		t.Fatalf("关闭句柄下的查询失败必须返回空结果, got %d rows truncated=%v", len(rows), truncated)
	}
	if !strings.Contains(logs.String(), "cert 任务行查询失败") {
		t.Fatalf("查询失败必须按失败态转换留痕（不得静默空列表）: %q", logs.String())
	}
}

func TestCollectEngineFamilies_shutdownBeforeWaitingCAQueryDoesNotPanic(t *testing.T) {
	te := newWireTestEngine(t)
	te.SetRole(true)
	resetLogStateTransitionForTest(taskMonitorWaitingCALogKey)
	logs := captureLogf(t)
	// 先停引擎：关库时不得让后台 daemon 与本用例交错（本用例只验证视图读路径）。
	StopTaskEngine()
	handle := db.DB
	previous := beforeTaskMonitorWaitingCAQuery
	called := false
	beforeTaskMonitorWaitingCAQuery = func() {
		called = true
		db.SetDB(nil)
		db.DB = nil
		_ = handle.Close()
	}
	t.Cleanup(func() {
		beforeTaskMonitorWaitingCAQuery = previous
		resetLogStateTransitionForTest(taskMonitorWaitingCALogKey)
	})

	var rows []TaskInfo
	autobanRequireNoPanic(t, func() { rows = collectEngineFamilies(te) })
	if !called {
		t.Fatal("cert-waiting-ca query interleaving was not exercised")
	}
	ti := findTaskInfo(t, rows, "cert-waiting-ca")
	if ti.NextRunAt != "" {
		t.Fatalf("关闭句柄的查询失败不得给出下次可用时间, got %q", ti.NextRunAt)
	}
	if !strings.Contains(logs.String(), "cert 等待 CA 下次可用时间查询失败") {
		t.Fatalf("查询失败必须按失败态转换留痕: %q", logs.String())
	}
}

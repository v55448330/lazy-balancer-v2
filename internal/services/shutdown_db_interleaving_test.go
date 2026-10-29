package services

import (
	"context"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func requireNoPanic(t *testing.T, run func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("shutdown interleaving panicked: %v", recovered)
		}
	}()
	run()
}

func TestRecordAuditLog_shutdownBetweenHandleCheckAndExecDoesNotPanic(t *testing.T) {
	initServicesDB(t)
	logs := captureLogf(t)
	auditDB := db.AuditDB
	previous := beforeAuditLogExec
	calls := 0
	beforeAuditLogExec = func() {
		calls++
		db.AuditDB = nil
		_ = auditDB.Close()
	}
	t.Cleanup(func() { beforeAuditLogExec = previous })

	requireNoPanic(t, func() {
		RecordAuditLog("system", "测试", "审计", "关停交错", "127.0.0.1")
	})
	if calls != 1 {
		t.Fatalf("audit exec interleaving calls=%d, want 1", calls)
	}
	if !strings.Contains(logs.String(), "audit log write failed") {
		t.Fatalf("快照句柄在 Exec 前关闭时必须走写入失败留痕: %q", logs.String())
	}
	if strings.Contains(logs.String(), "audit log write skipped") {
		t.Fatalf("hook 不得落在句柄快照之前并提前走 nil 分支: %q", logs.String())
	}
}

func TestLiveRuleIDs_shutdownBetweenHandleCheckAndQueryReturnsError(t *testing.T) {
	initServicesDB(t)
	database := db.DB
	previous := beforeLiveRuleIDsQuery
	called := false
	beforeLiveRuleIDsQuery = func() {
		called = true
		// 真实关停链（db.Close）=SetDB(nil) + 关闭句柄：liveRuleIDs 读
		// db.GetDB() 注册句柄，只置 db.DB 不再构成关停窗口。
		db.SetDB(nil)
		_ = database.Close()
	}
	t.Cleanup(func() { beforeLiveRuleIDsQuery = previous })

	var (
		live map[string]bool
		err  error
	)
	requireNoPanic(t, func() {
		live, err = liveRuleIDs(t.Context())
	})
	if !called {
		t.Fatal("rule query interleaving was not exercised")
	}
	if err == nil {
		t.Fatal("closed snapshot must return its query error")
	}
	if !strings.Contains(err.Error(), "数据库未初始化") {
		t.Fatalf("err=%v, want 数据库未初始化（nil 分支语义）", err)
	}
	if live != nil {
		t.Fatalf("closed snapshot returned live IDs: %#v", live)
	}
}

func TestGetTaskLogSizeBytes_shutdownBetweenHandleCheckAndQueryFallsBack(t *testing.T) {
	initServicesDB(t)
	resetLogStateTransitionForTest("task-log-size-refresh")
	taskLogSizeCache.invalidate()
	database := db.DB
	previous := beforeTaskLogSizeQuery
	called := false
	beforeTaskLogSizeQuery = func() {
		called = true
		db.DB = nil
		_ = database.Close()
	}
	t.Cleanup(func() {
		beforeTaskLogSizeQuery = previous
		taskLogSizeCache.invalidate()
		resetLogStateTransitionForTest("task-log-size-refresh")
	})

	var got int64
	requireNoPanic(t, func() { got = getTaskLogSizeBytes(context.Background()) })
	if !called {
		t.Fatal("task log threshold interleaving was not exercised")
	}
	if want := int64(db.DefaultTaskLogSizeMB) * 1024 * 1024; got != want {
		t.Fatalf("task log threshold=%d, want fallback %d", got, want)
	}
	if stateTransitionRecorded("task-log-size-refresh") {
		t.Fatal("nil 句柄分支不应走查询失败路径（应直接返回默认值）")
	}
}

func TestGetAuditLogSizeBytes_shutdownBetweenHandleCheckAndQueryFallsBack(t *testing.T) {
	initServicesDB(t)
	resetLogStateTransitionForTest("audit-log-size-refresh")
	auditLogSizeValueCache.invalidate()
	database := db.DB
	previous := beforeAuditLogSizeQuery
	called := false
	beforeAuditLogSizeQuery = func() {
		called = true
		db.DB = nil
		_ = database.Close()
	}
	t.Cleanup(func() {
		beforeAuditLogSizeQuery = previous
		auditLogSizeValueCache.invalidate()
		resetLogStateTransitionForTest("audit-log-size-refresh")
	})

	var got int64
	requireNoPanic(t, func() { got = getAuditLogSizeBytesContext(context.Background()) })
	if !called {
		t.Fatal("audit log threshold interleaving was not exercised")
	}
	if want := int64(db.DefaultAuditLogSizeMB) * 1024 * 1024; got != want {
		t.Fatalf("audit log threshold=%d, want fallback %d", got, want)
	}
	if stateTransitionRecorded("audit-log-size-refresh") {
		t.Fatal("nil 句柄分支不应走查询失败路径（应直接返回默认值）")
	}
}

func stateTransitionRecorded(key string) bool {
	metricsStateMu.Lock()
	defer metricsStateMu.Unlock()
	_, seen := metricsStateFailed[key]
	return seen
}

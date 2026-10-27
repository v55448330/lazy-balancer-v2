package services

import (
	"context"
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
	auditDB := db.AuditDB
	previous := beforeAuditLogExec
	called := false
	beforeAuditLogExec = func() {
		called = true
		db.AuditDB = nil
		_ = auditDB.Close()
	}
	t.Cleanup(func() { beforeAuditLogExec = previous })

	requireNoPanic(t, func() {
		RecordAuditLog("system", "测试", "审计", "关停交错", "127.0.0.1")
	})
	if !called {
		t.Fatal("audit exec interleaving was not exercised")
	}
}

func TestLiveRuleIDs_shutdownBetweenHandleCheckAndQueryReturnsError(t *testing.T) {
	initServicesDB(t)
	database := db.DB
	previous := beforeLiveRuleIDsQuery
	called := false
	beforeLiveRuleIDsQuery = func() {
		called = true
		db.DB = nil
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
	requireNoPanic(t, func() { got = getTaskLogSizeBytes() })
	if !called {
		t.Fatal("task log threshold interleaving was not exercised")
	}
	if want := int64(db.DefaultTaskLogSizeMB) * 1024 * 1024; got != want {
		t.Fatalf("task log threshold=%d, want fallback %d", got, want)
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
}

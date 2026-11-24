package services

import (
	"database/sql"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// autobanRequireNoPanic 断言调用在关停交错窗口内不 panic：nil 接收者
// 解引用会直接把 panic 抛给调用方（引擎 runGuarded / gin.Recovery 只能
// 掩盖不能修复）。
func autobanRequireNoPanic(t *testing.T, run func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("shutdown interleaving panicked: %v", recovered)
		}
	}()
	run()
}

type autobanHandleProbe struct {
	database *sql.DB
	called   bool
}

// autobanShutdownHandle 在注入缝里执行真实关停链（db.Close 的
// SetDB(nil) + 包级句柄置 nil + 关闭句柄）。
func autobanShutdownHandle(handle *autobanHandleProbe) func() {
	handle.called = false
	return func() {
		handle.called = true
		db.SetDB(nil)
		db.DB = nil
		_ = handle.database.Close()
	}
}

func TestGetAutobanConfig_shutdownBeforeReadDoesNotPanic(t *testing.T) {
	initServicesDB(t)
	probe := &autobanHandleProbe{database: db.DB}
	previous := beforeAutobanConfigRead
	beforeAutobanConfigRead = autobanShutdownHandle(probe)
	t.Cleanup(func() { beforeAutobanConfigRead = previous })

	var (
		cfg AutobanConfig
		err error
	)
	autobanRequireNoPanic(t, func() { cfg, err = GetAutobanConfig() })
	if !probe.called {
		t.Fatal("config read interleaving was not exercised")
	}
	if err == nil {
		t.Fatalf("closed snapshot must return its read error, got cfg=%+v", cfg)
	}
	if cfg.Threshold != db.DefaultAutobanThreshold {
		t.Fatalf("失败必须返回默认配置快照，got threshold=%d", cfg.Threshold)
	}
}

func TestSetAutobanConfig_shutdownBeforeWriteReturnsError(t *testing.T) {
	initServicesDB(t)
	probe := &autobanHandleProbe{database: db.DB}
	previous := beforeAutobanConfigWrite
	beforeAutobanConfigWrite = autobanShutdownHandle(probe)
	t.Cleanup(func() { beforeAutobanConfigWrite = previous })

	cfg, err := GetAutobanConfig()
	if err != nil {
		t.Fatalf("前置读取应成功: %v", err)
	}
	var writeErr error
	autobanRequireNoPanic(t, func() { writeErr = SetAutobanConfig(cfg) })
	if !probe.called {
		t.Fatal("config write interleaving was not exercised")
	}
	if writeErr == nil {
		t.Fatal("closed snapshot must return its write error")
	}
}

func TestEnsureAutobanPresetListID_shutdownBeforeQueryReturnsError(t *testing.T) {
	initServicesDB(t)
	probe := &autobanHandleProbe{database: db.DB}
	previous := beforeAutobanPresetListQuery
	beforeAutobanPresetListQuery = autobanShutdownHandle(probe)
	t.Cleanup(func() { beforeAutobanPresetListQuery = previous })

	var (
		id  int64
		err error
	)
	autobanRequireNoPanic(t, func() { id, err = ensureAutobanPresetListID() })
	if !probe.called {
		t.Fatal("preset list query interleaving was not exercised")
	}
	if err == nil {
		t.Fatalf("closed snapshot must return its query error, got id=%d", id)
	}
}

func TestAutobanMergeEntries_shutdownBeforeTxReturnsError(t *testing.T) {
	initServicesDB(t)
	probe := &autobanHandleProbe{database: db.DB}
	previous := beforeAutobanMergeTx
	beforeAutobanMergeTx = autobanShutdownHandle(probe)
	t.Cleanup(func() { beforeAutobanMergeTx = previous })

	var mergeErr error
	autobanRequireNoPanic(t, func() {
		_, mergeErr = autobanMergeEntries(AutobanConfig{Escalation: AutobanEscalationOff}, nil)
	})
	if !probe.called {
		t.Fatal("merge tx interleaving was not exercised")
	}
	if mergeErr == nil {
		t.Fatal("closed snapshot must return its transaction error")
	}
}

func TestAutobanListEntries_shutdownBeforeQueryReturnsError(t *testing.T) {
	initServicesDB(t)
	probe := &autobanHandleProbe{database: db.DB}
	previous := beforeAutobanListEntriesQuery
	beforeAutobanListEntriesQuery = autobanShutdownHandle(probe)
	t.Cleanup(func() { beforeAutobanListEntriesQuery = previous })

	var (
		entries []models.IPListEntry
		listID  int64
		err     error
	)
	autobanRequireNoPanic(t, func() { entries, listID, err = AutobanListEntries() })
	if !probe.called {
		t.Fatal("list entries query interleaving was not exercised")
	}
	if err == nil {
		t.Fatalf("closed snapshot must return its query error, got %d entries (list=%d)", len(entries), listID)
	}
}

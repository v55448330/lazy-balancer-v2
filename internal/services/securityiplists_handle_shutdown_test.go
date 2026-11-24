package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 引用名单装载在关停窗口内必须 fail-visible：db.Close（SetDB(nil)+DB=nil）
// 与判空/传参交错时，旧实现把 nil store 交给 loadIPListEntriesVia，递归回落
// 到本函数后返回「空映射 + nil 错误」——引用该名单的 ACL/信任策略静默按
// inline-only 渲染（deny 零命中 / allow 恒拒），日志零信号。
func TestLoadIPListEntriesByID_shutdownBeforeLoadSurfacesError(t *testing.T) {
	initServicesDB(t)
	database := db.DB
	previous := beforeIPListEntriesByIDLoad
	called := false
	beforeIPListEntriesByIDLoad = func() {
		called = true
		db.SetDB(nil)
		db.DB = nil
		_ = database.Close()
	}
	t.Cleanup(func() { beforeIPListEntriesByIDLoad = previous })

	var (
		entries map[int64][]string
		err     error
	)
	autobanRequireNoPanic(t, func() { entries, err = LoadIPListEntriesByID([]int64{2}) })
	if !called {
		t.Fatal("ip list load interleaving was not exercised")
	}
	if err == nil {
		t.Fatalf("closed snapshot must surface the load error, got silent empty result: %v", entries)
	}
}

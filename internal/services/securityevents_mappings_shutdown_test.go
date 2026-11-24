package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 映射装载在关停窗口内必须 fail-visible 而非 panic：db.Close 的
// SetDB(nil)+DB=nil 落在「版本读取成功」与「四条映射查询」之间时，旧实现
// 二次读包级 db.DB 会把 nil *sql.DB 当接收者解引用——后台采集 goroutine 与
// IPC 同步入口都会被整进程退出，映射缓存键与实际数据源也可能跨代错配。
func TestSecurityEventsLoadMappings_shutdownBeforeQueriesSurfacesError(t *testing.T) {
	initServicesDB(t)
	resetSecurityEventsMappingsCacheForTest()
	database := db.DB
	previous := beforeSecurityEventsMappingsQuery
	called := false
	beforeSecurityEventsMappingsQuery = func() {
		called = true
		db.SetDB(nil)
		db.DB = nil
		_ = database.Close()
	}
	t.Cleanup(func() {
		beforeSecurityEventsMappingsQuery = previous
		resetSecurityEventsMappingsCacheForTest()
	})

	var err error
	autobanRequireNoPanic(t, func() {
		_, _, _, err = securityEventsLoadMappings()
	})
	if !called {
		t.Fatal("mappings query interleaving was not exercised")
	}
	if err == nil {
		t.Fatal("closed snapshot must surface the query error")
	}
	if entry := securityEventsMappingsCache.entry; entry.loaded {
		t.Fatal("失败不得缓存映射代际")
	}
}

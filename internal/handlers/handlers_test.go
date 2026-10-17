package handlers

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestNewHandlers_does_not_repeat_database_initialization(t *testing.T) {
	// Given：数据库未初始化（nil）——NewHandlers 只组装依赖，不得触发初始化
	oldDB := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = oldDB })

	// When
	h := NewHandlers(Dependencies{})

	// Then
	if h == nil {
		t.Fatal("NewHandlers returned nil")
	}
	// U13-04（第 78 轮）：此前仅断言 h != nil，测试名称承诺的「不重建数据库」
	// 从未验证——任何在构造器内 db.Initialize 的实现都会静默通过。真实断言：
	// 调用后全局库句柄必须仍为 nil。
	if db.DB != nil {
		t.Fatal("NewHandlers must not re-initialize database")
	}
}

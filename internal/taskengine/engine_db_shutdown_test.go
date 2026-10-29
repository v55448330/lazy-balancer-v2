package taskengine

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 关停窗口：StopTaskEngine→db.Close 把包级句柄置 nil 与任务视图读并发。
// 「先判 nil、再二次读全局句柄」在两次读之间被置 nil 时就是 nil 解引用
// panic（进程级崩溃，不是降级），因此句柄必须单次快照后判定并使用。
//
// 注入缝落在判定与使用之间（生产恒等 no-op），把真实关停交错变成确定性用例。
func TestTaskRunsReadsSnapshotHandleAcrossShutdown(t *testing.T) {
	e := newTestEngine(t)
	database := db.DB
	previous := beforeTaskRunsRead
	t.Cleanup(func() {
		beforeTaskRunsRead = previous
		db.DB = database
	})

	cases := []struct {
		name string
		read func()
	}{
		{"History", func() { e.History("t-shutdown", 5) }},
		{"RecoverOrphans", func() { e.RecoverOrphans() }},
		{"RunOverview", func() { e.RunOverview() }},
		{"Stats24h", func() { e.Stats24h("t-shutdown") }},
		{"Stats24hHourlySeries", func() { e.Stats24hHourlySeries() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db.DB = database
			exercised := false
			beforeTaskRunsRead = func() {
				exercised = true
				db.DB = nil
			}
			defer func() { beforeTaskRunsRead = previous }()

			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("关停交错：句柄在判定与使用之间被置 nil 时 panic（须单次快照）: %v", p)
				}
			}()
			tc.read()
			if !exercised {
				t.Fatal("关停交错注入点未被触达")
			}
		})
	}
}

package services

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// TASK-L3（第 69 轮 P3）：聚合视图两处 db.DB 裸用（collectCertJobRows 的
// cert_jobs 查询、cluster-sync 节奏的 sync_interval 查询）补 nil 防护——与
// 引擎侧导出 DB 函数（History/Stats24h 等 7 处）同形契约。
//
// Given db.DB 未初始化（nil）。
// When 调用 cert 任务行收集与引擎族聚合（含 cluster-sync 节奏查询）。
// Then 不 panic：cert 行返回 nil，引擎族聚合返回降级视图（节奏兜底文案）。
func TestCollectSystemTasks_nilDBGuards(t *testing.T) {
	old := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = old })

	if rows := collectCertJobRows(); rows != nil {
		t.Fatalf("nil DB 时 collectCertJobRows=%v, want nil", rows)
	}

	e := taskengine.NewEngine(taskengine.Options{})
	t.Cleanup(e.Stop)
	e.Register(taskengine.Descriptor{ID: "cluster-sync", Family: "cluster", Name: "集群同步",
		Kind: taskengine.KindPeriodic, IntervalFn: func() time.Duration { return 60 * time.Second },
		Run: func(taskengine.RunContext) error { return nil }})
	out := collectEngineFamilies(e)
	if len(out) != 1 {
		t.Fatalf("nil DB 时 collectEngineFamilies 行数=%d, want 1（降级视图）", len(out))
	}
	if out[0].Cadence == "" {
		t.Fatal("nil DB 时节奏列应有兜底文案（每 1 分钟）")
	}
}

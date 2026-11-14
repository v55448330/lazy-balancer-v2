package services

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CLI 预检快照/回滚与单规则预检渲染必须串行：预检渲染新建的投影若被写路径
// 回滚清单误收，Rollback 会删除另一条只读渲染刚生成的在役投影。
func TestGenerateSingleRuleCaddyConfig_serializesWithProjectionSnapshot(t *testing.T) {
	_, database := newClusterTestService(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	t.Cleanup(EndIPListProjectionPass)
	if _, err := database.Exec(`UPDATE global_config SET request_body_max_size_mb=128, trusted_proxy_enabled=1, trusted_proxy_ranges='["203.0.113.0/24"]', trusted_proxy_range_refs='[]', trusted_proxy_headers='["CF-Connecting-IP"]' WHERE id=1`); err != nil {
		t.Fatalf("seed trusted proxy: %v", err)
	}

	snapshot, err := SnapshotIPListProjections()
	if err != nil {
		t.Fatalf("snapshot projections: %v", err)
	}
	rendered := make(chan struct{})
	// 正握手（entered 通道）：快照生命周期持有 ipListProjectionRenderMu，
	// 串行化实现下预检渲染必然阻塞在入口。测试先确认渲染 goroutine 已到达
	// 锁等待（而不是依赖「100ms 内渲染不完」的负窗口调度假设——慢机上
	// 串行化回归会假绿），再执行回滚：未串行化实现此刻已写完 tp.txt 并登记
	// 进本轮新建清单，回滚会把它当渲染新增删除；串行化实现下渲染尚未动盘，
	// 回滚清单为空，tp.txt 在回滚后才生成并存活。
	entered := make(chan struct{})
	go func() {
		close(entered)
		defer close(rendered)
		config := GenerateSingleRuleCaddyConfig(SingleRuleConfig{
			CaddyID:                       "lb_projection_race",
			Protocol:                      "http",
			Domain:                        "projection.example.test",
			ListenPort:                    8080,
			GlobalRequestBodyMaxSizeMB:    128,
			HealthCheckInterval:           10,
			HealthCheckTimeout:            5,
			HealthCheckUnhealthyThreshold: 3,
			HealthCheckHealthyThreshold:   2,
			Upstreams:                     []UpstreamConfig{{Host: "10.0.0.1", Port: 80, Weight: 1, Enabled: true}},
		})
		if _, failed := config["error"]; failed {
			t.Errorf("single rule render failed: %v", config["error"])
		}
	}()
	<-entered
	// 给渲染 goroutine 到达锁等待的宽限（正握手只证明「已启动」，此处
	// 让出调度使其必然停在入口；串行化与否的区分由回滚终态断言承载）。
	time.Sleep(50 * time.Millisecond)
	if err := RestoreIPListProjections(snapshot); err != nil {
		t.Fatalf("restore projections: %v", err)
	}
	select {
	case <-rendered:
	case <-time.After(5 * time.Second):
		t.Fatal("单规则渲染在投影回滚后仍未完成（可能死锁）")
	}
	if _, err := os.Stat(filepath.Join(IPListDataDir, "tp.txt")); err != nil {
		t.Fatalf("只读预检渲染的 tp.txt 被另一轮回滚删除: %v", err)
	}
}

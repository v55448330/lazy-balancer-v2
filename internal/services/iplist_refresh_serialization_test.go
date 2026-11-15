package services

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 投影刷新入口与快照/回滚生命周期必须共用同一把渲染串行锁：刷新渲染
// （已提交视图）与在途快照回滚窗口交错时，刷新渲染新建的投影会被回滚清单
// 误收（Restore 删除在役文件），两轮渲染的投影写盘也会互相穿插。
// 与 TestGenerateSingleRuleCaddyConfig_serializesWithProjectionSnapshot 同构，
// 写者换成投影刷新入口（三变体的共同咽喉点）。
func TestRefreshIPListProjections_serializesWithProjectionSnapshot(t *testing.T) {
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
	// 正握手（entered 通道，与姊妹文件单规则预检同模式）：先确认刷新
	// goroutine 已启动，再让出调度使其到达锁等待——不依赖「100ms 内渲染
	// 不完」的负窗口调度假设（慢机上串行化回归会假绿）。串行化与否的
	// 区分由回滚终态断言承载：未串行化实现此刻已写完 tp.txt 并登记进
	// 本轮回滚清单，回滚把它当渲染新增删除；串行化实现下刷新尚未动盘，
	// tp.txt 在回滚后才生成并存活。
	entered := make(chan struct{})
	go func() {
		close(entered)
		defer close(rendered)
		// DB 视图刷新变体（自取 CaddyOpLock）：无运行中 Caddy 时按
		// ProjectionFallback 收尾（运行配置不可读），但投影写盘（渲染
		// 副作用）先行发生，收尾语义与本钉测无关。
		service := NewCaddyService("")
		if _, err := service.RefreshIPListProjections(); err != nil {
			t.Errorf("refresh projections: %v", err)
		}
	}()
	<-entered
	// 正握手只证明「已启动」；宽限让出调度使刷新停在锁入口。
	time.Sleep(50 * time.Millisecond)
	if err := RestoreIPListProjections(snapshot); err != nil {
		t.Fatalf("restore projections: %v", err)
	}
	select {
	case <-rendered:
	case <-time.After(5 * time.Second):
		t.Fatal("投影刷新在回滚后仍未完成（可能死锁）")
	}
	data, err := os.ReadFile(filepath.Join(IPListDataDir, "tp.txt"))
	if err != nil {
		t.Fatalf("投影刷新的 tp.txt 被另一轮回滚删除: %v", err)
	}
	if string(data) != "203.0.113.0/24\n" {
		t.Fatalf("tp.txt=%q, want 已提交视图内容", data)
	}
}

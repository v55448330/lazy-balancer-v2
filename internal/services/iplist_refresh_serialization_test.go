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
	go func() {
		defer close(rendered)
		// DB 视图刷新变体（自取 CaddyOpLock）：无运行中 Caddy 时按
		// ProjectionFallback 收尾（运行配置不可读），但投影写盘（渲染
		// 副作用）先行发生，收尾语义与本钉测无关。
		service := NewCaddyService("")
		if _, err := service.RefreshIPListProjections(); err != nil {
			t.Errorf("refresh projections: %v", err)
		}
	}()
	select {
	case <-rendered:
		// 未串行实现会先渲染完并把 tp.txt 登记进本轮回滚清单。
	case <-time.After(100 * time.Millisecond):
	}
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

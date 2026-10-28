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
	go func() {
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
	case <-time.After(2 * time.Second):
		t.Fatal("单规则渲染在投影回滚后仍未完成（可能死锁）")
	}
	if _, err := os.Stat(filepath.Join(IPListDataDir, "tp.txt")); err != nil {
		t.Fatalf("只读预检渲染的 tp.txt 被另一轮回滚删除: %v", err)
	}
}

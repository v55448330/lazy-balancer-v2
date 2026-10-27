package services

// 的 sync_interval 展示 clamp
// 被插入 if err != nil 分支 return 之后(unreachable,go vet 机器诊断)——
// Status() 展示链对存量脏值(0/负/1-9s)仍原样展示,与运行时 60s clamp 分叉。
// 本测试钉住:脏值入库 → Status() 读出已 clamp 值。

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestClusterStatus_syncIntervalDisplayClamp(t *testing.T) {
	// 每个子用例 db.Initialize 后必须 Close 并恢复
	// 全局句柄（与 newClusterTestService 同款）——此前覆盖全局 db.DB 却无
	// cleanup，-race/并行执行下可与其他用例互相污染，句柄也随全局注册表泄漏。
	oldDB, oldMetricsDB, oldAuditDB, oldCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	t.Cleanup(func() {
		_ = db.Close()
		restoreGlobalDBHandles(oldDB, oldMetricsDB, oldAuditDB, oldCurrent)
	})
	cases := []struct {
		stored int
		want   int
	}{
		{0, 60},    // 脏值 0 → clamp 60
		{-5, 60},   // 负值 → 60
		{5, 60},    // 1-9s → 60
		{10, 10},   // 边界 10 不 clamp
		{60, 60},   // 正常值不变
		{120, 120}, // 大于 60 不变
		{86400, 86400},
		{86401, 86400},
		{1000000, 86400},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("stored_%d", tc.stored), func(t *testing.T) {
			if err := db.Initialize(t.TempDir()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = db.Close()
				restoreGlobalDBHandles(oldDB, oldMetricsDB, oldAuditDB, oldCurrent)
			})
			if _, err := db.DB.Exec("UPDATE global_config SET sync_interval=? WHERE id=1", tc.stored); err != nil {
				t.Fatal(err)
			}
			svc := NewClusterService(db.DB, t.TempDir())
			t.Cleanup(func() { unregisterClusterService(svc) })
			status, err := svc.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if status.SyncInterval != tc.want {
				t.Fatalf("Status().SyncInterval=%d (stored %d), want %d", status.SyncInterval, tc.stored, tc.want)
			}
		})
	}
}

func TestNodeOfflineThreshold_clampsExcessiveSyncInterval(t *testing.T) {
	if got := nodeOfflineThreshold(1000000); got != 2*86400*time.Second {
		t.Fatalf("nodeOfflineThreshold=%v, want %v", got, 2*86400*time.Second)
	}
}

// 同一坏 health_json 行按 nodeID 60s 限频告警。
func TestNodes_throttlesCorruptedHealthWarnings(t *testing.T) {
	_, database := newClusterTestService(t)
	service := NewClusterService(database, "")
	t.Cleanup(func() { unregisterClusterService(service) })
	ctx := context.Background()
	nodeHealthWarnMu.Lock()
	savedHealthWarn := nodeHealthWarnSeen
	nodeHealthWarnSeen = map[int]time.Time{}
	nodeHealthWarnMu.Unlock()
	t.Cleanup(func() {
		nodeHealthWarnMu.Lock()
		nodeHealthWarnSeen = savedHealthWarn
		nodeHealthWarnMu.Unlock()
	})
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,is_approved,health_json,last_seen) VALUES (21,'bad','10.0.0.21',8000,1,'{not-json',?)`, now.Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	if _, err := service.Nodes(ctx, now); err != nil {
		t.Fatalf("nodes first call: %v", err)
	}
	if _, err := service.Nodes(ctx, now.Add(10*time.Second)); err != nil {
		t.Fatalf("nodes second call: %v", err)
	}
	if got := strings.Count(buf.String(), "解析节点 21 健康状态失败"); got != 1 {
		t.Fatalf("health parse warn count=%d, want 1 within window", got)
	}
	if _, err := service.Nodes(ctx, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("nodes after window: %v", err)
	}
	if got := strings.Count(buf.String(), "解析节点 21 健康状态失败"); got != 2 {
		t.Fatalf("health parse warn count=%d, want 2 after window", got)
	}
}

package services

// 角色翻转清 autoban 计数器钉测：角色翻转（Promote/BecomeSlave）必须清 autoban 内存计数器——
// 主→从→主往返后旧主时代陈旧计数不得按新口径执法（错误封禁+累犯升档永久化）。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func seedAutobanWindowForRoleTest(t *testing.T) {
	t.Helper()
	autobanMu.Lock()
	autobanWindows["10.9.9.9"] = &autobanCounter{}
	autobanMu.Unlock()
}

func autobanWindowCountForRoleTest() int {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	return len(autobanWindows)
}

// 升主清桶：从节点期间冻结的陈旧计数升主后必须清空（防旧口径执法）。
func TestClusterService_Promote_resetsAutobanCounters(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB, oldCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		restoreGlobalDBHandles(oldDB, oldMetricsDB, oldAuditDB, oldCurrent)
		ResetAutobanCounters()
	})
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	te := InitTaskEngine("", t.TempDir()+"/app.log")
	te.SetRole(false)
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=0, is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedAutobanWindowForRoleTest(t)
	if autobanWindowCountForRoleTest() == 0 {
		t.Fatal("前置失败：陈旧计数未种入")
	}
	service := NewClusterService(db.DB, "")
	t.Cleanup(func() { unregisterClusterService(service) })
	installGlobalConfigVersionTrigger(t, db.DB)
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if n := autobanWindowCountForRoleTest(); n != 0 {
		t.Fatalf("升主必须清 autoban 陈旧计数（防旧口径执法），残留 %d 桶", n)
	}
}

// 降级清桶：主节点陈旧计数降级后必须清空（防升主往返残留）。
func TestClusterService_BecomeSlave_resetsAutobanCounters(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB, oldCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		restoreGlobalDBHandles(oldDB, oldMetricsDB, oldAuditDB, oldCurrent)
		ResetAutobanCounters()
	})
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	te := InitTaskEngine("", t.TempDir()+"/app.log")
	te.SetRole(true)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedAutobanWindowForRoleTest(t)
	service := NewClusterService(db.DB, "")
	t.Cleanup(func() { unregisterClusterService(service) })
	installGlobalConfigVersionTrigger(t, db.DB)
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}
	if n := autobanWindowCountForRoleTest(); n != 0 {
		t.Fatalf("降级必须清 autoban 陈旧计数（防升主往返残留），残留 %d 桶", n)
	}
}

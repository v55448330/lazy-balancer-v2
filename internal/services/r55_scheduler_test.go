package services

import (
	"context"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// waitCRSRunFinished 等待在途 CRS 更新跑完（测试收尾用，避免后台 run 与
// 测试拆除期关闭的 DB 竞态）。
func waitCRSRunFinished(m *CRSUpdateManager) {
	m.mu.Lock()
	runDone := m.runDone
	m.mu.Unlock()
	if runDone != nil {
		<-runDone
	}
}

// TestClusterService_BecomeSlave_returnsPromptly_whenCRSUpdateInFlight 验证
// R55-A-#1：调度器 tick 已启动自动更新并阻塞在 rearm 等待时，降级（BecomeSlave
// → StopScheduler）必须立即返回，不得挂在 HTTP 降级请求上等到在途更新跑完
// （有界 6-7 分钟）。在途更新仍在后台完成，其写入由下次快照全量重放覆盖。
func TestClusterService_BecomeSlave_returnsPromptly_whenCRSUpdateInFlight(t *testing.T) {
	// Given 主节点 + 到期的 CRS 自动更新排程，更新在 fetch 阶段被卡住
	service, _ := newClusterTestService(t)
	InitCRSUpdateManager(func() error { return nil })
	t.Cleanup(ResetCRSUpdateManagerForTest)
	crsManager := GetCRSUpdateManager()
	if _, err := db.DB.Exec("UPDATE security_crs_version SET auto_update=1, next_update=? WHERE id=1",
		time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)); err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	entered := make(chan struct{})
	crsManager.fetchLatestTag = func(context.Context) (string, error) {
		close(entered)
		<-block
		return CRSBundledVersion, nil // 与当前版本相同 → 放行后快速成功收尾
	}
	crsManager.StartScheduler()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("given: due scheduler tick should start an auto update")
	}

	// When 节点降级注册进另一集群
	demoted := make(chan error, 1)
	go func() {
		demoted <- service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"})
	}()

	// Then 降级请求立即返回，不等待在途更新完成
	select {
	case err := <-demoted:
		if err != nil {
			t.Fatalf("become slave: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("BecomeSlave blocked on the in-flight CRS update (must stop scheduling without waiting for the update)")
	}

	close(block)
	waitCRSRunFinished(crsManager)
}

// TestIP2RegionStopScheduler_returnsPromptly_whenUpdateInFlight 验证 R55-A-#1
// 对 IP2Region 调度器同样的语义：StopScheduler 不等待在途更新。
func TestIP2RegionStopScheduler_returnsPromptly_whenUpdateInFlight(t *testing.T) {
	// Given 主节点 + 到期的 IP2Region 自动更新排程，更新在 fetch 阶段被卡住
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET next_update=? WHERE id=1",
		time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)); err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	entered := make(chan struct{})
	m.fetchLatestTag = func(context.Context) (string, error) {
		close(entered)
		<-block
		return "v3.0.0", nil // 与当前版本相同 → 放行后快速成功收尾
	}
	m.StartScheduler()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("given: due scheduler tick should start an auto update")
	}

	// When 调度器被停止（降级路径）
	stopped := make(chan struct{})
	go func() {
		m.StopScheduler()
		close(stopped)
	}()

	// Then 停止立即返回，不等待在途更新完成
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("StopScheduler blocked on the in-flight IP2Region update")
	}

	close(block)
	m.mu.Lock()
	runDone := m.runDone
	m.mu.Unlock()
	<-runDone
}

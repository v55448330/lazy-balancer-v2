package services

import (
	"context"
	"errors"
	"sync/atomic"
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

// TestCRSScheduler_promoteRestoresFailedBackoff_afterStopWinsAbandonedRearm 验证
// R56 N-2：tick 启动更新时已写 next_update=+24h，降级 stop 获胜使 rearm 的
// 失败退避重写被跳过（R55-A-#1 有意取舍），在途更新失败后再提升的节点仍按
// 残留的 +24h 排程，失败重试被无谓推迟（设计退避 1h 起）。提升为主（启动
// 调度器）时必须把失败状态的过期排程拉回连续失败次数对应的退避点。
func TestCRSScheduler_promoteRestoresFailedBackoff_afterStopWinsAbandonedRearm(t *testing.T) {
	// Given 主节点 + 到期的 CRS 自动更新排程，更新在 fetch 阶段被卡住（随后失败）
	_, _ = newClusterTestService(t)
	InitCRSUpdateManager(func() error { return nil })
	t.Cleanup(ResetCRSUpdateManagerForTest)
	m := GetCRSUpdateManager()
	if _, err := db.DB.Exec("UPDATE security_crs_version SET auto_update=1, next_update=? WHERE id=1",
		time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)); err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	entered := make(chan struct{})
	m.fetchLatestTag = func(context.Context) (string, error) {
		close(entered)
		<-block
		return "", errors.New("upstream unreachable")
	}
	m.StartScheduler()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("given: due scheduler tick should start an auto update")
	}

	// When 降级（stop 获胜）→ 在途更新失败
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	m.StopScheduler()
	close(block)
	waitCRSRunFinished(m)

	// Then 失败已落库，且退避重写确被跳过（N-4 固化）：next_update 仍是 tick
	// 启动时写入的 +24h
	_, status, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update status=%q, want failed", status)
	}
	due, err := time.Parse(crsTimeLayout, nextUpdate)
	if err != nil {
		t.Fatalf("parse next_update %q: %v", nextUpdate, err)
	}
	if remain := time.Until(due); remain < 23*time.Hour {
		t.Fatalf("next_update remaining=%v, want ≈24h (stop-wins must skip the backoff rewrite)", remain)
	}

	// When 节点再提升为主（启动调度器）
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	m.StartScheduler()

	// Then 过期排程被拉回正常退避（1 次失败 → 1h），不再残留 +24h
	_, _, _, _, _, nextUpdate, _ = crsVersionRow(t)
	due, err = time.Parse(crsTimeLayout, nextUpdate)
	if err != nil {
		t.Fatalf("parse next_update %q: %v", nextUpdate, err)
	}
	if remain := time.Until(due); remain < 50*time.Minute || remain > 70*time.Minute {
		t.Fatalf("next_update remaining=%v, want ≈1h backoff restored on promotion", remain)
	}
}

// TestIP2RegionScheduler_promoteRestoresFailedBackoff 验证 R56 N-2 对 IP2Region
// 调度器同样生效：失败状态 + 残留远期 next_update 在调度器启动（提升/进程
// 重启）时被拉回连续失败次数对应的退避点。
func TestIP2RegionScheduler_promoteRestoresFailedBackoff(t *testing.T) {
	// Given 主节点 + 连续失败 2 次、next_update 残留 +24h（停-wins 放弃退避后的形态）
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET update_status='failed', consecutive_failures=2, next_update=? WHERE id=1",
		time.Now().UTC().Add(24*time.Hour).Format(crsTimeLayout)); err != nil {
		t.Fatal(err)
	}

	// When 提升为主（启动调度器）
	m.StartScheduler()
	defer m.StopScheduler()

	// Then next_update 拉回 2 次失败对应的 2h 退避
	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	due, err := time.Parse(crsTimeLayout, nextUpdate)
	if err != nil {
		t.Fatalf("parse next_update %q: %v", nextUpdate, err)
	}
	if remain := time.Until(due); remain < 100*time.Minute || remain > 130*time.Minute {
		t.Fatalf("next_update remaining=%v, want ≈2h backoff (2 consecutive failures)", remain)
	}
}

// TestCRSScheduler_startKeepsSuccessSchedule 验证提升恢复只针对失败退避残留：
// 成功状态的正常 +24h 排程不得被改写。
func TestCRSScheduler_startKeepsSuccessSchedule(t *testing.T) {
	// Given 主节点 + 成功状态 + 正常 +24h 排程
	_, _ = newClusterTestService(t)
	InitCRSUpdateManager(func() error { return nil })
	t.Cleanup(ResetCRSUpdateManagerForTest)
	m := GetCRSUpdateManager()
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET update_status='success', consecutive_failures=0, next_update=? WHERE id=1",
		time.Now().UTC().Add(24*time.Hour).Format(crsTimeLayout)); err != nil {
		t.Fatal(err)
	}

	// When 启动调度器（提升/进程重启路径）
	m.StartScheduler()

	// Then next_update 保持 +24h 不动
	_, _, _, _, _, nextUpdate, _ := crsVersionRow(t)
	due, err := time.Parse(crsTimeLayout, nextUpdate)
	if err != nil {
		t.Fatalf("parse next_update %q: %v", nextUpdate, err)
	}
	if remain := time.Until(due); remain < 23*time.Hour {
		t.Fatalf("next_update remaining=%v, want ≈24h untouched (success schedule is legitimate)", remain)
	}
}

// TestCRSScheduler_noFurtherTicks_afterStopWins 验证 R56 N-4：stop 获胜后调度器
// 不再产生任何 tick——停止路径（StopScheduler/ResetForTest/进程关闭）是 stop
// 通道的唯一关闭者，泄漏的调度 goroutine 会在排程到期后继续驱动自动更新。
func TestCRSScheduler_noFurtherTicks_afterStopWins(t *testing.T) {
	// Given 主节点 + 短间隔调度器 + 到期排程，更新在 fetch 阶段被卡住
	_, _ = newClusterTestService(t)
	InitCRSUpdateManager(func() error { return nil })
	t.Cleanup(ResetCRSUpdateManagerForTest)
	m := GetCRSUpdateManager()
	m.schedulerInterval = 50 * time.Millisecond
	if _, err := db.DB.Exec("UPDATE security_crs_version SET auto_update=1, next_update=? WHERE id=1",
		time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)); err != nil {
		t.Fatal(err)
	}
	var fetchCalls atomic.Int32
	block := make(chan struct{})
	entered := make(chan struct{})
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalls.Add(1)
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-block
		return CRSBundledVersion, nil // 与当前版本相同 → 放行后快速成功收尾
	}
	m.StartScheduler()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("given: due scheduler tick should start an auto update")
	}

	// When 调度器停止（stop 获胜）→ 在途更新放行完成 → 排程重新到期
	m.StopScheduler()
	close(block)
	waitCRSRunFinished(m)
	if _, err := db.DB.Exec("UPDATE security_crs_version SET next_update=? WHERE id=1",
		time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * m.schedulerInterval)

	// Then 停止后零新增 tick（fetch 未被再次调用——泄漏的 tick 在到期排程下
	// 必然立刻再启动一次更新）
	if got := fetchCalls.Load(); got != 1 {
		t.Fatalf("fetch calls=%d after stop, want 1 (stopped scheduler must not tick)", got)
	}
}

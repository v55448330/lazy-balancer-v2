package services

import (
	"errors"
	"log"
	"time"

	"lazy-balancer-v2/internal/db"
)

// StartScheduler launches the daily auto-update loop (24h cadence, hourly
// check). It is a no-op on slave nodes and while an update is running.
func (m *IP2RegionUpdateManager) StartScheduler() {
	m.schedulerMu.Lock()
	defer m.schedulerMu.Unlock()
	if m.schedulerStop != nil {
		return
	}
	restoreFailedUpdateBackoff("security_ip2region_version", time.Now().UTC())
	stop := make(chan struct{})
	done := make(chan struct{})
	m.schedulerStop = stop
	m.schedulerDone = done
	go func() {
		defer close(done)
		m.schedulerTick(time.Now().UTC(), stop)
		ticker := time.NewTicker(m.schedulerInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-ticker.C:
				m.schedulerTick(now.UTC(), stop)
			}
		}
	}()
}

func (m *IP2RegionUpdateManager) StopScheduler() {
	m.schedulerMu.Lock()
	stop := m.schedulerStop
	done := m.schedulerDone
	m.schedulerStop = nil
	m.schedulerDone = nil
	m.schedulerMu.Unlock()
	if stop != nil {
		close(stop)
	}
	if done != nil {
		<-done
	}
}

// SetMasterRole 按集群角色启停 ip2region 自动更新调度器：主节点启动，从节点
// 停止。停止立即生效（含等待在途更新的 rearm，R55-A-#1）；已启动的更新仍在
// 后台有界跑完，其在从节点上的写入由下次快照全量重放覆盖（drift 自愈）。
func (m *IP2RegionUpdateManager) SetMasterRole(isMaster bool) {
	if isMaster {
		m.StartScheduler()
		return
	}
	m.StopScheduler()
}

func (m *IP2RegionUpdateManager) schedulerTick(now time.Time, stop <-chan struct{}) {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return
	}
	var autoUpdate bool
	if err := db.DB.QueryRow("SELECT auto_update FROM security_ip2region_version WHERE id=1").Scan(&autoUpdate); err != nil || !autoUpdate {
		return
	}
	if m.IsRunning() {
		return
	}
	next := now.Add(24 * time.Hour).Format(crsTimeLayout)
	var nextStr string
	if err := db.DB.QueryRow("SELECT COALESCE(next_update,'') FROM security_ip2region_version WHERE id=1").Scan(&nextStr); err != nil {
		return
	}
	if nextStr != "" {
		due, err := time.Parse(crsTimeLayout, nextStr)
		if err == nil && now.Before(due) {
			return
		}
	}
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET next_update=? WHERE id=1", next); err != nil {
		log.Printf("ip2region update: failed to record next_update: %v", err)
	}
	if nextStr == "" {
		return // first tick only schedules the first run
	}
	// StartUpdate 唯一可预期错误是 ErrIP2RegionUpdateRunning——IsRunning 前置
	// 守卫与取锁之间存在微秒窗口（R57 B-#5，与 CRS 侧同形）：手动更新恰在窗口
	// 内启动时返回该错误，此时同样走 rearm 复查，避免 +24h 排程落库而退避
	// 重写被跳过。其他启动失败形态退避分支不可达（R36 F4 删除）。
	if err := m.StartUpdate("auto"); err == nil {
		m.rearmAfterIP2RegionUpdate(now, stop)
	} else if errors.Is(err, ErrIP2RegionUpdateRunning) {
		m.rearmAfterIP2RegionUpdate(now, stop)
	}
}

// rearmAfterIP2RegionUpdate 等待异步更新结束后复查结果：失败（网络瞬断等）时把
// next_update 改为 1 小时后重试，成功维持运行前写入的 +24h 排程（R34 I）。
// 等待可被 stop 打断（R55-A-#1）：降级时 StopScheduler 关闭 stop，调度立即
// 退出而不被在途更新时长拖住；被打断时跳过失败退避重写，在途更新本身仍在
// 后台完成。跳过留下的远期 next_update 由下次启动调度器时的
// restoreFailedUpdateBackoff 拉回退避排程（R56 N-2）。
func (m *IP2RegionUpdateManager) rearmAfterIP2RegionUpdate(now time.Time, stop <-chan struct{}) {
	m.mu.Lock()
	runDone := m.runDone
	m.mu.Unlock()
	if runDone != nil {
		select {
		case <-runDone:
		case <-stop:
			return
		}
	}
	m.mu.Lock()
	failed := m.state.status == IP2RegionStatusFailed
	m.mu.Unlock()
	if !failed {
		return
	}
	// 失败按连续失败次数指数退避（1h→2h→4h→8h→24h 封顶，成功复位，R35 I1）；
	// fail() 已把 consecutive_failures +1。
	retry := now.Add(updateRetryBackoff(readConsecutiveFailures("security_ip2region_version"))).Format(crsTimeLayout)
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET next_update=? WHERE id=1", retry); err != nil {
		log.Printf("ip2region update: failed to record retry next_update: %v", err)
	}
}

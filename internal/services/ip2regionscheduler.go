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
	stop := make(chan struct{})
	done := make(chan struct{})
	m.schedulerStop = stop
	m.schedulerDone = done
	go func() {
		defer close(done)
		m.schedulerTick(time.Now().UTC())
		ticker := time.NewTicker(m.schedulerInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-ticker.C:
				m.schedulerTick(now.UTC())
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

// SetMasterRole 按集群角色启停 ip2region 自动更新调度器：主节点启动，从节点停止。
func (m *IP2RegionUpdateManager) SetMasterRole(isMaster bool) {
	if isMaster {
		m.StartScheduler()
		return
	}
	m.StopScheduler()
}

func (m *IP2RegionUpdateManager) schedulerTick(now time.Time) {
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
	err := m.StartUpdate("auto")
	if err != nil && !errors.Is(err, ErrIP2RegionUpdateRunning) {
		log.Printf("ip2region update: failed to start scheduled update: %v", err)
		// 启动即失败：1 小时后再试，而不是等整整 24 小时（R34 I）
		retry := now.Add(1 * time.Hour).Format(crsTimeLayout)
		if _, dbErr := db.DB.Exec("UPDATE security_ip2region_version SET next_update=? WHERE id=1", retry); dbErr != nil {
			log.Printf("ip2region update: failed to record retry next_update: %v", dbErr)
		}
		return
	}
	if err == nil {
		m.rearmAfterIP2RegionUpdate(now)
	}
}

// rearmAfterIP2RegionUpdate 等待异步更新结束后复查结果：失败（网络瞬断等）时把
// next_update 改为 1 小时后重试，成功维持运行前写入的 +24h 排程（R34 I）。
func (m *IP2RegionUpdateManager) rearmAfterIP2RegionUpdate(now time.Time) {
	m.mu.Lock()
	runDone := m.runDone
	m.mu.Unlock()
	if runDone != nil {
		<-runDone
	}
	m.mu.Lock()
	failed := m.state.status == IP2RegionStatusFailed
	m.mu.Unlock()
	if !failed {
		return
	}
	retry := now.Add(1 * time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET next_update=? WHERE id=1", retry); err != nil {
		log.Printf("ip2region update: failed to record retry next_update: %v", err)
	}
}

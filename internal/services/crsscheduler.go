package services

import (
	"context"
	"errors"
	"log"
	"time"

	"lazy-balancer-v2/internal/db"
)

// LatestVersionCached returns the last fetched upstream tag without network I/O.
func (m *CRSUpdateManager) LatestVersionCached() (string, bool) {
	m.latestMu.Lock()
	defer m.latestMu.Unlock()
	return m.latestTag, m.latestKnown
}

// RefreshLatestAsync refreshes the cached upstream tag in the background when
// the cache is older than 10 minutes; it never blocks the caller.
func (m *CRSUpdateManager) RefreshLatestAsync() {
	m.latestMu.Lock()
	if m.latestRefreshing || time.Since(m.latestFetchedAt) < 10*time.Minute {
		m.latestMu.Unlock()
		return
	}
	m.latestRefreshing = true
	m.latestMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		tag, err := m.fetchLatestTag(ctx)
		m.latestMu.Lock()
		m.latestRefreshing = false
		if err == nil {
			m.latestTag = tag
			m.latestKnown = true
			m.latestFetchedAt = time.Now()
		}
		m.latestMu.Unlock()
		if err != nil {
			log.Printf("crs update: background version check failed: %v", err)
			return
		}
		// 上游 tag 检查是只读网络请求，从节点允许执行；但 last_checked 落库必须
		// 仅主节点进行，避免从节点（只读）打开 CRS 页面时写本地库。
		var isMaster bool
		if err := db.DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
			return
		}
		if _, dbErr := db.DB.Exec("UPDATE security_crs_version SET last_checked=datetime('now') WHERE id=1"); dbErr != nil {
			log.Printf("crs update: failed to record last_checked: %v", dbErr)
		}
	}()
}

// StartScheduler launches the daily auto-update loop (24h cadence, hourly
// check). It is a no-op on slave nodes and while an update is running.
func (m *CRSUpdateManager) StartScheduler() {
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

func (m *CRSUpdateManager) StopScheduler() {
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

// SetMasterRole 按集群角色启停 CRS 自动更新调度器：主节点启动，从节点停止。
// 角色切换（提升为主/降级为从）时调用；重复调用安全。
func (m *CRSUpdateManager) SetMasterRole(isMaster bool) {
	if isMaster {
		m.StartScheduler()
		return
	}
	m.StopScheduler()
}

func (m *CRSUpdateManager) schedulerTick(now time.Time) {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return
	}
	var autoUpdate bool
	if err := db.DB.QueryRow("SELECT auto_update FROM security_crs_version WHERE id=1").Scan(&autoUpdate); err != nil || !autoUpdate {
		return
	}
	if m.IsRunning() {
		return
	}
	next := now.Add(24 * time.Hour).Format(crsTimeLayout)
	var nextStr string
	if err := db.DB.QueryRow("SELECT COALESCE(next_update,'') FROM security_crs_version WHERE id=1").Scan(&nextStr); err != nil {
		return
	}
	if nextStr != "" {
		due, err := time.Parse(crsTimeLayout, nextStr)
		if err == nil && now.Before(due) {
			return
		}
	}
	if _, err := db.DB.Exec("UPDATE security_crs_version SET next_update=? WHERE id=1", next); err != nil {
		log.Printf("crs update: failed to record next_update: %v", err)
	}
	if nextStr == "" {
		return // first tick only schedules the first run
	}
	err := m.StartUpdate("auto")
	if err != nil && !errors.Is(err, ErrCRSUpdateRunning) {
		log.Printf("crs update: failed to start scheduled update: %v", err)
		// 启动即失败：1 小时后再试，而不是等整整 24 小时（R34 I）
		retry := now.Add(1 * time.Hour).Format(crsTimeLayout)
		if _, dbErr := db.DB.Exec("UPDATE security_crs_version SET next_update=? WHERE id=1", retry); dbErr != nil {
			log.Printf("crs update: failed to record retry next_update: %v", dbErr)
		}
		return
	}
	if err == nil {
		m.rearmAfterCRSUpdate(now)
	}
}

// rearmAfterCRSUpdate 等待异步更新结束后复查结果：失败（网络瞬断等）时把
// next_update 改为 1 小时后重试，成功维持运行前写入的 +24h 排程（R34 I：
// 原先运行前写死 +24h，失败整天不重试）。
func (m *CRSUpdateManager) rearmAfterCRSUpdate(now time.Time) {
	m.mu.Lock()
	runDone := m.runDone
	m.mu.Unlock()
	if runDone != nil {
		<-runDone
	}
	m.mu.Lock()
	failed := m.state.status == CRSStatusFailed
	m.mu.Unlock()
	if !failed {
		return
	}
	retry := now.Add(1 * time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec("UPDATE security_crs_version SET next_update=? WHERE id=1", retry); err != nil {
		log.Printf("crs update: failed to record retry next_update: %v", err)
	}
}

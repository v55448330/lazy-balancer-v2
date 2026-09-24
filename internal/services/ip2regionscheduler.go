package services

import (
	"time"

	"lazy-balancer-v2/internal/db"
)

// StartScheduler launches the auto-update loop（分钟级 tick：排程槽准点触发，
// 迟到 ≤1min，2026-09-25 用户裁定）。从节点与更新在途时为 no-op。
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
// 后台有界跑完，其版本行写入由 waf_files 差分门控重放覆盖
// （2026-09-11 版本行归位；文件态由 wafFilesDrifted 兜底自愈）。
func (m *IP2RegionUpdateManager) SetMasterRole(isMaster bool) {
	if isMaster {
		m.StartScheduler()
		return
	}
	m.StopScheduler()
}

func (m *IP2RegionUpdateManager) schedulerTick(now time.Time, stop <-chan struct{}) {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return
	}
	var autoUpdate bool
	if err := db.DB.QueryRow("SELECT auto_update FROM security_ip2region_version WHERE id=1").Scan(&autoUpdate); err != nil || !autoUpdate {
		return
	}
	if m.IsRunning() {
		return
	}
	next := versionTableNextSlot("security_ip2region_version", now)
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
		Logf("error", "ip2region update: failed to record next_update: %v", err)
	}
	if nextStr == "" {
		return // first tick only schedules the first run
	}
	// 失败退避机器已撤除（2026-09-25 用户裁定，与 CRS 侧同形）：重试在任务内
	// 完成，next_update 恒为排程槽；手动插队竞态静默忽略。
	_, _ = m.StartUpdate("auto")
}

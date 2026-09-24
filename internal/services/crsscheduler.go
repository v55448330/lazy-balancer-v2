package services

import (
	"context"
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
// latestFetchedAt 记录最近一次尝试（含失败）：失败路径同样受 10 分钟守卫约束，
// 否则前端轮询期间每次 GetCRSInfo 都会重发一个 30s 超时的上游请求，持续失败
// 时加速触发 GitHub 403 限流（R53 新-1）。
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
		m.latestFetchedAt = time.Now()
		if err == nil {
			m.latestTag = tag
			m.latestKnown = true
		}
		m.latestMu.Unlock()
		// last_checked 记录检查尝试（含失败，R54-N4）：持续上游故障期间 UI 的
		// 「上次检查时间」随之推进，避免「已是最新 + checked long ago」的静默
		// 假象。写库仅主节点进行，从节点（只读）打开 CRS 页面不写本地库。
		var isMaster bool
		if qerr := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); qerr == nil && isMaster {
			if _, dbErr := db.DB.Exec("UPDATE security_crs_version SET last_checked=datetime('now') WHERE id=1"); dbErr != nil {
				Logf("error", "crs update: failed to record last_checked: %v", dbErr)
			}
		}
		if err != nil {
			Logf("error", "crs update: background version check failed: %v", err)
			return
		}
	}()
}

// StartScheduler launches the auto-update loop（分钟级 tick：排程槽准点触发，
// 迟到 ≤1min，2026-09-25 用户裁定；原小时级 tick 槽位最多迟到 59min）。从节点
// 与更新在途时为 no-op。
func (m *CRSUpdateManager) StartScheduler() {
	m.schedulerMu.Lock()
	defer m.schedulerMu.Unlock()
	if m.schedulerStop != nil {
		return
	}
	// 退避 restore 已撤除（重试在任务内完成，next_update 恒为排程槽）。
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
// 角色切换（提升为主/降级为从）时调用；重复调用安全。停止立即生效（含等待
// 在途更新的 rearm，R55-A-#1）；已启动的更新仍在后台有界跑完（fetch 30s +
// 下载 5min + reload 30s），其版本行写入由 waf_files 差分门控重放覆盖
// （2026-09-11 版本行归位；文件态由 wafFilesDrifted 兜底自愈）。
func (m *CRSUpdateManager) SetMasterRole(isMaster bool) {
	if isMaster {
		m.StartScheduler()
		return
	}
	m.StopScheduler()
}

func (m *CRSUpdateManager) schedulerTick(now time.Time, stop <-chan struct{}) {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return
	}
	var autoUpdate bool
	if err := db.DB.QueryRow("SELECT auto_update FROM security_crs_version WHERE id=1").Scan(&autoUpdate); err != nil || !autoUpdate {
		return
	}
	if m.IsRunning() {
		return
	}
	next := versionTableNextSlot("security_crs_version", now)
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
		Logf("error", "crs update: failed to record next_update: %v", err)
	}
	if nextStr == "" {
		return // first tick only schedules the first run
	}
	// 失败退避机器已撤除（2026-09-25 用户裁定）：重试在任务内完成（run 内
	// runWithInTaskRetry），next_update 恒为排程槽——失败落定后下一运行=下一排程槽。
	// StartUpdate 唯一可预期错误是 ErrXXXUpdateRunning——IsRunning 前置守卫与取锁
	// 之间的微秒窗口被手动更新插队时返回，属正常竞态，静默忽略（手动 run 的终态
	// 由操作者直接观察）。
	_, _ = m.StartUpdate("auto")
}

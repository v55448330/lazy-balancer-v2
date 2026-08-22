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
		if qerr := db.DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); qerr == nil && isMaster {
			if _, dbErr := db.DB.Exec("UPDATE security_crs_version SET last_checked=datetime('now') WHERE id=1"); dbErr != nil {
				log.Printf("crs update: failed to record last_checked: %v", dbErr)
			}
		}
		if err != nil {
			log.Printf("crs update: background version check failed: %v", err)
			return
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
	restoreFailedUpdateBackoff("security_crs_version", time.Now().UTC())
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
// 下载 5min + reload 30s），其在从节点上的写入由下次快照全量重放覆盖
// （security 节在 driftGuardSections 内，drift 自愈）。
func (m *CRSUpdateManager) SetMasterRole(isMaster bool) {
	if isMaster {
		m.StartScheduler()
		return
	}
	m.StopScheduler()
}

func (m *CRSUpdateManager) schedulerTick(now time.Time, stop <-chan struct{}) {
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
	// StartUpdate 唯一可预期错误是 ErrCRSUpdateRunning——IsRunning 前置守卫
	// 与取锁之间存在微秒窗口：手动更新恰在此窗口启动时返回该错误（R57 B-#5）。
	// 此时必须同样走 rearm 复查——否则 +24h 排程已落库而失败退避重写被跳过，
	// 下次自动重试被推迟 24h（手动更新失败时）。启动失败的其他形态退避分支
	// 不可达（R36 F4 删除）。
	if runDone, err := m.StartUpdate("auto"); err == nil {
		m.rearmAfterCRSUpdate(now, stop, runDone)
	} else if errors.Is(err, ErrCRSUpdateRunning) {
		m.rearmAfterCRSUpdate(now, stop, nil)
	}
}

// rearmAfterCRSUpdate 等待异步更新结束后复查结果：失败（网络瞬断等）时把
// next_update 改为 1 小时后重试，成功维持运行前写入的 +24h 排程（R34 I：
// 原先运行前写死 +24h，失败整天不重试）。等待可被 stop 打断（R55-A-#1）：
// 降级时 StopScheduler 关闭 stop，调度立即退出而不被在途更新时长（有界
// 6-7min）拖住；被打断时跳过失败退避重写——调度器已停，rearm 无意义，
// 在途更新本身仍在后台完成。跳过留下的远期 next_update 由下次启动调度器
// （提升为主/进程重启）时的 restoreFailedUpdateBackoff 拉回退避排程（R56 N-2）。
// R64 B-F2：runDone 为本次 tick 启动的 run 的完成通道（ErrCRSUpdateRunning
// 插队分支传 nil，回退等待现行 m.runDone——那是手动 run，其终态由操作者直接
// 观察管理）。终态读取附带归属校验：等待结束时若 m.runDone 已被更新的 run
// 接管（手动更新在微秒窗口插队），本 tick 的 run 已非最新——跳过退避重写，
// 由接管 run 的操作者/后续 tick 决定排程，不再按他人终态误判。
// 已知取舍（R65 B-S1）：「auto 失败 + 手动插队 + 手动也失败」时 auto 的失败
// 退避被跳过，next_update 停留 tick 预写的 +24h（本应 2h 档）——影响有界
// （≤24h）且经 restoreFailedUpdateBackoff 在下次 StartScheduler 时拉回；反向
// 按接管者终态重写则会在「手动成功复位计数」场景错写 +1h。取保守跳过。
func (m *CRSUpdateManager) rearmAfterCRSUpdate(now time.Time, stop <-chan struct{}, runDone chan struct{}) {
	wait := runDone
	if wait == nil {
		m.mu.Lock()
		wait = m.runDone
		m.mu.Unlock()
	}
	if wait != nil {
		select {
		case <-wait:
		case <-stop:
			return
		}
	}
	m.mu.Lock()
	failed := m.state.status == CRSStatusFailed
	overtaken := runDone != nil && m.runDone != runDone
	m.mu.Unlock()
	if !failed || overtaken {
		return
	}
	// 失败按连续失败次数指数退避（1h→2h→4h→8h→24h 封顶，成功复位，R35 I1）；
	// fail() 已把 consecutive_failures +1。
	retry := now.Add(updateRetryBackoff(readConsecutiveFailures("security_crs_version"))).Format(crsTimeLayout)
	if _, err := db.DB.Exec("UPDATE security_crs_version SET next_update=? WHERE id=1", retry); err != nil {
		log.Printf("crs update: failed to record retry next_update: %v", err)
	}
}

// updateRetryBackoff 返回连续失败后的下次重试间隔：1h→2h→4h→8h→24h 封顶
// （failures≥5 起固定 24h）。成功更新会把计数复位，退避随之回到 1h。
func updateRetryBackoff(failures int) time.Duration {
	backoff := time.Hour
	for i := 2; i <= failures && i <= 4; i++ {
		backoff *= 2
	}
	if failures >= 5 {
		backoff = 24 * time.Hour
	}
	return backoff
}

// restoreFailedUpdateBackoff 修正「停-wins 放弃退避重写」（R55-A-#1）留下的
// 过期排程（R56 N-2）：tick 启动更新时写 next_update=+24h，降级打断 rearm 后
// 在途更新失败，再提升的节点仍按残留的 +24h 排程，失败重试被无谓推迟。调度器
// 启动（提升为主/进程重启）时，若状态为 failed 且 next_update 晚于按当前连续
// 失败次数应有的退避点，将其拉回退避排程；成功状态的正常 +24h 排程、以及本就
// 早于退避点的 next_update 均不动。仅主节点写库（从节点版本行由快照管辖）。
func restoreFailedUpdateBackoff(table string, now time.Time) {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return
	}
	var status, nextStr string
	if err := db.DB.QueryRow("SELECT COALESCE(update_status,''), COALESCE(next_update,'') FROM "+table+" WHERE id=1").Scan(&status, &nextStr); err != nil {
		return
	}
	if status != string(CRSStatusFailed) || nextStr == "" {
		return
	}
	due, err := time.Parse(crsTimeLayout, nextStr)
	if err != nil {
		return
	}
	retry := now.Add(updateRetryBackoff(readConsecutiveFailures(table)))
	if !due.After(retry) {
		return
	}
	if _, err := db.DB.Exec("UPDATE "+table+" SET next_update=? WHERE id=1", retry.Format(crsTimeLayout)); err != nil {
		log.Printf("update scheduler: failed to restore backoff next_update: %v", err)
	}
}

// readConsecutiveFailures 读取组件状态表的连续失败计数（R35 I1 持久化列）；
// 读取失败按 0 处理，退避退化为固定 1h，不影响排程推进。
func readConsecutiveFailures(table string) int {
	var failures int
	if err := db.DB.QueryRow("SELECT consecutive_failures FROM " + table + " WHERE id=1").Scan(&failures); err != nil {
		return 0
	}
	return failures
}

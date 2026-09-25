package services

import (
	"errors"
	"fmt"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 威胁情报库调度器（v2.3.x）：主节点专属——启动即检查一次（从未更新过的源
// 立即首轮更新），随后分钟级 tick 检查到期源（next_update<=now 或空）；成功的
// 源按排程槽节奏（任务级星期+时间，默认每天 04:00）落定 next_update，失败源
// 由任务内重试（runWithInTaskRetry 3 次）兜底，落定后下一运行=下一排程槽。
// 从节点不更新——文件经 waf-files 通道下发（见 cluster_sync.go）。

// SetMasterRole 按集群角色启停调度器（镜像 ip2region 同族语义）。
func (m *ThreatUpdateManager) SetMasterRole(isMaster bool) {
	if isMaster {
		m.StartScheduler()
		return
	}
	m.StopScheduler()
}

// 威胁库自动更新总开关（v2.3.2 用户裁定）：global_config.threat_auto_update
// 为任务级总闸（规则库卡片父行开关）；逐源 update_enabled 决定任务更新
// 哪些源（弹框内开关）。两者解耦——总闸关闭时整任务不启动。
func SetThreatAutoUpdate(enabled bool) error {
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_auto_update=?, updated_at=datetime('now') WHERE id=1`, enabled); err != nil {
		return fmt.Errorf("更新威胁库自动更新开关: %w", err)
	}
	return nil
}

// ThreatAutoUpdateEnabled 读任务级总闸（读错 fail-closed=视为关）。
func ThreatAutoUpdateEnabled() bool {
	var v int
	if err := db.DB.QueryRow(`SELECT COALESCE(threat_auto_update,1) FROM global_config WHERE id=1`).Scan(&v); err != nil {
		return false
	}
	return v != 0
}

func (m *ThreatUpdateManager) StartScheduler() {
	m.mu.Lock()
	defer m.mu.Unlock()
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
		ticker := time.NewTicker(time.Minute)
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

func (m *ThreatUpdateManager) StopScheduler() {
	m.mu.Lock()
	stop, done := m.schedulerStop, m.schedulerDone
	m.schedulerStop, m.schedulerDone = nil, nil
	m.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
}

func (m *ThreatUpdateManager) schedulerTick(now time.Time) {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return
	}
	// 任务级总闸：关闭时整任务不启动（逐源开关决定更新哪些源，与总闸解耦）。
	if !ThreatAutoUpdateEnabled() {
		return
	}
	if m.IsRunning() {
		return
	}
	// 有启用且到期的源才启动任务
	due, err := threatDueSources("auto")
	if err != nil || len(due) == 0 {
		return
	}
	if _, err := m.StartUpdate("auto"); err != nil && !errors.Is(err, ErrThreatUpdateRunning) {
		Logf("error", "威胁情报库: 调度启动失败: %v", err)
	}
}

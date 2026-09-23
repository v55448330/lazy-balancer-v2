package services

import (
	"errors"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 威胁情报库调度器（v2.3.x）：主节点专属——启动即检查一次（从未更新过的源
// 立即首轮更新），随后每小时检查到期源（next_update<=now 或空）；成功的源
// 24h 节奏、失败的源指数退避（行状态由 threatupdate.go 写）。
// 从节点不更新——文件经 waf-files 通道下发（见 cluster_sync.go）。

// SetMasterRole 按集群角色启停调度器（镜像 ip2region 同族语义）。
func (m *ThreatUpdateManager) SetMasterRole(isMaster bool) {
	if isMaster {
		m.StartScheduler()
		return
	}
	m.StopScheduler()
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
		ticker := time.NewTicker(time.Hour)
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

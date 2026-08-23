package services

import (
	"context"
	"log"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

const (
	securityEventsRetentionDefaultDays = 30
	securityEventsRetentionDefaultMax  = 100000
	// securityEventsRetentionDeleteBatch 是 count 超限裁剪的单批删除行数：
	// 大批量单语句 DELETE 会长时间持指标库写锁，阻塞摄取 tick（R33 F9）。
	securityEventsRetentionDeleteBatch = 5000
)

var (
	securityEventsRetentionMu     sync.Mutex
	securityEventsRetentionCancel context.CancelFunc
	securityEventsRetentionDone   chan struct{}
)

// securityEventsRetentionSettings reads the retention policy from global_config,
// falling back to the defaults when the stored values are unset or non-positive.
func securityEventsRetentionSettings() (days, max int) {
	days, max = securityEventsRetentionDefaultDays, securityEventsRetentionDefaultMax
	database := db.DB
	if database == nil {
		return days, max
	}
	var retentionMonths int
	if err := database.QueryRow(`SELECT COALESCE(audit_retention_months,0) FROM global_config WHERE id=1`).Scan(&retentionMonths); err != nil {
		return days, max
	}
	if retentionMonths > 0 {
		days = retentionMonths * 30
	}
	return days, max
}

// securityEventsRetentionCleanup deletes events older than the configured
// retention window, then trims the oldest rows while the table still holds
// more rows than the configured maximum. The DB handle is captured locally so
// a concurrent test teardown (db.DB = nil) cannot nil-deref mid-pass.
func securityEventsRetentionCleanup() {
	database := db.MetricsDB
	if database == nil {
		return
	}
	days, max := securityEventsRetentionSettings()
	// 年龄裁剪同样分批执行（与 count 裁剪同口径）：大表单条 DELETE 长时间持
	// 指标库写锁，阻塞摄取 tick（R34 E）。
	for {
		res, err := database.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events WHERE event_time < datetime('now', printf('-%d days', ?)) ORDER BY id ASC LIMIT ?)`, days, securityEventsRetentionDeleteBatch)
		if err != nil {
			log.Printf("security events retention: age-based cleanup failed: %v", err)
			break
		}
		affected, _ := res.RowsAffected()
		if affected == 0 {
			break
		}
		// 批间短暂让出写锁，避免长时间阻塞摄取 INSERT
		time.Sleep(10 * time.Millisecond)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		log.Printf("security events retention: row count failed: %v", err)
		return
	}
	if overflow := count - max; overflow > 0 {
		remaining := overflow
		for remaining > 0 {
			batch := remaining
			if batch > securityEventsRetentionDeleteBatch {
				batch = securityEventsRetentionDeleteBatch
			}
			res, err := database.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events ORDER BY id ASC LIMIT ?)`, batch)
			if err != nil {
				log.Printf("security events retention: count-based cleanup failed: %v", err)
				break
			}
			affected, _ := res.RowsAffected()
			if affected == 0 {
				break
			}
			remaining -= int(affected)
			// 批间短暂让出写锁，避免长时间阻塞摄取 INSERT
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// StartSecurityEventsRetention launches the daily cleanup worker. It is a no-op
// when the worker is already running. The worker runs one cleanup pass at start
// so a fresh boot does not wait a full day, then repeats every 24 hours.
func StartSecurityEventsRetention(ctx context.Context) {
	securityEventsRetentionMu.Lock()
	if securityEventsRetentionDone != nil {
		securityEventsRetentionMu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	securityEventsRetentionCancel = cancel
	securityEventsRetentionDone = done
	securityEventsRetentionMu.Unlock()

	go func() {
		defer func() {
			close(done)
			securityEventsRetentionMu.Lock()
			if securityEventsRetentionDone == done {
				securityEventsRetentionCancel = nil
				securityEventsRetentionDone = nil
			}
			securityEventsRetentionMu.Unlock()
		}()
		securityEventsRetentionCleanup()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				securityEventsRetentionCleanup()
			}
		}
	}()
}

// securityEventsRetentionStop terminates the worker and waits for it to exit.
func securityEventsRetentionStop() {
	securityEventsRetentionMu.Lock()
	cancel := securityEventsRetentionCancel
	done := securityEventsRetentionDone
	securityEventsRetentionCancel = nil
	securityEventsRetentionDone = nil
	securityEventsRetentionMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// SetSecurityEventsRetentionMasterRole 安全事件保留清理的幂等启动钩子。
// R62 B-NEW-2（注释修正）：保留清理针对本节点本地 security_events 表，与集群角色
// 无关——main.go 启动即无条件运行（从节点也摄入事件），降级为从节点【不应】停止：
// 若按旧注释在 BecomeSlave 补 stop，从节点事件表将越过 10 万行上限无界增长。
// R66 B-N2：false 分支从 stop 改为 no-op——函数与 CRS/IP2Region 的 SetMasterRole
// （按角色启停）同形，极易诱使未来在降级路径补 false 调用（恰是 R62 纠正过的
// 错误）；保留签名以兼容既有调用点（cluster.go 提升路径传 true），false 不再
// 有可观察效果。生产停止路径仅 main.go 优雅退出。
func SetSecurityEventsRetentionMasterRole(isMaster bool) {
	if isMaster {
		StartSecurityEventsRetention(context.Background())
	}
}

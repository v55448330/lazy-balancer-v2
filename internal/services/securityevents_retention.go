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
	// securityEventsRetentionDeleteBatch 是年龄裁剪与 count 超限裁剪共用的单批
	// 删除行数（R34 E 起年龄裁剪亦按此批次执行，同口径）：大批量单语句 DELETE
	// 会长时间持指标库写锁，阻塞摄取 tick（R33 F9）。
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

// StopSecurityEventsRetention terminates the worker and waits for it to exit.
// 停止路径仅 main.go 优雅退出（F5-2：原私有 stopper 无生产调用方，导出供关停接线）。
func StopSecurityEventsRetention() {
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

// （R69 过度修复审查 REMOVE：SetSecurityEventsRetentionMasterRole wrapper 已删除。
// worker 生命周期由 main.go 单点拥有——启动即无条件 StartSecurityEventsRetention
//（从节点也摄入事件，与集群角色无关，R62 B-NEW-2 确立）；Promote 路径的传 true
// 调用是幂等 no-op、false 分支生产不可达；停止路径仅 main.go 优雅退出。）

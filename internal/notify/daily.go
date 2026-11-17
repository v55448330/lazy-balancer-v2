package notify

// 每日日报：渲染昨日摘要（请求/拦截/攻击 TOP/证书/集群/封禁）→ Publish。
// Scheduled 任务（09:00，NextSlot 由注册侧承载）。

import (
	"context"
	"fmt"
	"time"

	"lazy-balancer-v2/internal/db"
)

// RenderAndPublishDailyReport 渲染昨日摘要并发布 daily_report 事件
// （投递全走 delivery Daemon；本任务只生产内容）。
func RenderAndPublishDailyReport(ctx context.Context, now time.Time) error {
	y0 := now.AddDate(0, 0, -1).Truncate(24 * time.Hour)
	y1 := y0.Add(24 * time.Hour)
	fmtRange := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") }

	var requests, blocked, bans int
	_ = db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<?`, fmtRange(y0), fmtRange(y1)).Scan(&requests)
	_ = db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='blocked'`, fmtRange(y0), fmtRange(y1)).Scan(&blocked)
	_ = db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE last_ban_at>=?`, fmtRange(y0)).Scan(&bans)

	topRule := "无"
	var rn string
	err := db.MetricsDB.QueryRow(`SELECT rule_name, COUNT(*) c FROM security_events
		WHERE event_time>=? AND event_time<? GROUP BY rule_name ORDER BY c DESC LIMIT 1`, fmtRange(y0), fmtRange(y1)).Scan(&rn, new(int))
	if err == nil && rn != "" {
		topRule = rn
	}

	certsActive, certsFailed := 0, 0
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE status IN ('issued','wait_reschedule','downloading')`).Scan(&certsActive)
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE status='failed'`).Scan(&certsFailed)

	summary := fmt.Sprintf("请求数 %d，拦截 %d（TOP 规则 %s），自动封禁 %d 次，证书活跃 %d/失败 %d",
		requests, blocked, topRule, bans, certsActive, certsFailed)
	Publish(Event{
		Type: EvtDailyReport, Level: LevelInfo,
		Title:  "每日日报",
		Body:   summary,
		Fields: map[string]string{"1": summary},
	})
	return nil
}

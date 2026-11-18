package notify

// 投递 Daemon 的核心扫描与状态机：pending → sent / failed(retry) / dead。
// 通道发送由 senders 注册表执行；通道展开=该用户全部启用通道（type×target）。

import (
	"log"
	"time"

	"lazy-balancer-v2/internal/db"
)

// deliveryTarget 单通道投递目标。
type deliveryTarget struct {
	ChannelID   int64
	Type        string
	Target      string // JSON 配置（webhook URL / email / qq openid / clawbot endpoint…）
	StyleConfig string // 消息样式 JSON（payload_template/subject_template/msg_type/daily_format）
}

// pendingDeliveries 取一批 pending 投递行（FIFO，单批上限防长时间占锁）。
func pendingDeliveries(limit int) ([]struct {
	ID        int64
	UserID    int64
	EventType string
	Level     string
	Title     string
	Body      string
}, error) {
	rows, err := db.DB.Query(`SELECT id, user_id, event_type, level, title, body
		FROM notification_deliveries WHERE status='pending' ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		ID        int64
		UserID    int64
		EventType string
		Level     string
		Title     string
		Body      string
	}
	for rows.Next() {
		var d struct {
			ID        int64
			UserID    int64
			EventType string
			Level     string
			Title     string
			Body      string
		}
		if err := rows.Scan(&d.ID, &d.UserID, &d.EventType, &d.Level, &d.Title, &d.Body); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// channelsForUser 取用户全部启用通道（类型+目标）。
func channelsForUser(userID int64) ([]deliveryTarget, error) {
	rows, err := db.DB.Query(`SELECT id, type, target, COALESCE(style_config,'{}') FROM notification_channels WHERE user_id=? AND enabled=1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []deliveryTarget
	for rows.Next() {
		var t deliveryTarget
		if err := rows.Scan(&t.ChannelID, &t.Type, &t.Target, &t.StyleConfig); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// markDelivery 更新投递行状态。
func markDelivery(id int64, status string, incrAttempts bool, errMsg string) {
	if incrAttempts {
		_, err := db.DB.Exec(`UPDATE notification_deliveries SET status=?, attempts=attempts+1, error=?, sent_at=? WHERE id=?`,
			status, errMsg, time.Now().UTC().Format("2006-01-02 15:04:05"), id)
		if err != nil {
			log.Printf("WARN: notify 投递状态更新失败（id=%d）: %v", id, err)
		}
		return
	}
	_, err := db.DB.Exec(`UPDATE notification_deliveries SET status=?, error=?, sent_at=? WHERE id=?`,
		status, errMsg, time.Now().UTC().Format("2006-01-02 15:04:05"), id)
	if err != nil {
		log.Printf("WARN: notify 投递状态更新失败（id=%d）: %v", id, err)
	}
}

// requeueStalePending 启动兜底：把历史 pending 行留在队首（delivery Daemon
// 每 tick 自然重扫），超龄（>7 天）判 dead——事实早过期，重投无意义。
func requeueStalePending() {
	_, err := db.DB.Exec(`UPDATE notification_deliveries SET status='dead', error='超过 7 天未投递（已过期）'
		WHERE status='pending' AND created_at < datetime('now', '-7 days')`)
	if err != nil {
		log.Printf("WARN: notify 过期 pending 清理失败: %v", err)
	}
}

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
	Name        string // 通道名（每通道结果行快照——通道删除后投递记录仍可读）
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
	Node      string
}, error) {
	rows, err := db.DB.Query(`SELECT id, user_id, event_type, level, title, body, COALESCE(node,'')
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
		Node      string
	}
	for rows.Next() {
		var d struct {
			ID        int64
			UserID    int64
			EventType string
			Level     string
			Title     string
			Body      string
			Node      string
		}
		if err := rows.Scan(&d.ID, &d.UserID, &d.EventType, &d.Level, &d.Title, &d.Body, &d.Node); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// channelsForUser 取用户全部启用通道（名/类型+目标）。
func channelsForUser(userID int64) ([]deliveryTarget, error) {
	rows, err := db.DB.Query(`SELECT id, name, type, target, COALESCE(style_config,'{}') FROM notification_channels WHERE user_id=? AND enabled=1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []deliveryTarget
	for rows.Next() {
		var t deliveryTarget
		if err := rows.Scan(&t.ChannelID, &t.Name, &t.Type, &t.Target, &t.StyleConfig); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// markDelivery 更新投递行状态。sent_at 只在「已送达」语义（sent/partial）
// 写入；failed/dead 必须置 NULL——旧实现四个状态都写 sent_at，失败/过期行
// 在投递记录里显示成已发送时刻（误导排查）。
func markDelivery(id int64, status string, incrAttempts bool, errMsg string) {
	var sentAt any
	switch status {
	case "sent", "partial":
		sentAt = time.Now().UTC().Format("2006-01-02 15:04:05")
	}
	if incrAttempts {
		_, err := db.DB.Exec(`UPDATE notification_deliveries SET status=?, attempts=attempts+1, error=?, sent_at=? WHERE id=?`,
			status, errMsg, sentAt, id)
		if err != nil {
			log.Printf("WARN: notify 投递状态更新失败（id=%d）: %v", id, err)
		}
		return
	}
	_, err := db.DB.Exec(`UPDATE notification_deliveries SET status=?, error=?, sent_at=? WHERE id=?`,
		status, errMsg, sentAt, id)
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

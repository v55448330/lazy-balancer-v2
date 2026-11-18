package notify

// 日报配置与三格式渲染（html/json/markdown）。
// 配置落 notification_daily（user_id 主键）；发送时间 per-user（Scheduled
// NextSlotFn 取全部用户时间集的最早槽，投递时按各用户配置分桶）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
)

// DailyConfig 单用户日报配置。
type DailyConfig struct {
	UserID   int64    `json:"user_id"`
	Enabled  bool     `json:"enabled"`
	SendTime string   `json:"send_time"` // "09:00"
	Items    []string `json:"items"`     // 勾选项目（见 DailyItemIDs）
	Format   string   `json:"format"`    // 投递渲染格式（text/markdown/html/json）
}

// DailyFormats 投递格式白名单（渲染分支一一对应；text=纯文本行）。
var DailyFormats = []string{"text", "markdown", "html", "json"}

// dailyFormatValid 格式白名单校验；空值回退 markdown。
func dailyFormatValid(f string) bool {
	for _, ok := range DailyFormats {
		if f == ok {
			return true
		}
	}
	return false
}

// DailyItemIDs 日报可定制项目（勾选清单契约）。
var DailyItemIDs = []string{
	"requests", "blocked", "attack_top", "autoban", "cert_status", "cluster_status",
}

// DailyItemLabels 项目中文标签（前端渲染+正文模板共用）。
var DailyItemLabels = map[string]string{
	"requests":       "请求数",
	"blocked":        "拦截次数",
	"attack_top":     "攻击 TOP 规则",
	"autoban":        "自动封禁次数",
	"cert_status":    "证书状态",
	"cluster_status": "集群状态",
}

// GetDailyConfig 读单用户配置（无行=默认：启用+全项目+09:00+markdown）。
func GetDailyConfig(userID int64) (DailyConfig, error) {
	cfg := DailyConfig{UserID: userID, Enabled: true, SendTime: "09:00",
		Items: append([]string{}, DailyItemIDs...), Format: "markdown"}
	var raw string
	err := db.DB.QueryRow(`SELECT COALESCE(config,'') FROM notification_daily WHERE user_id=?`, userID).Scan(&raw)
	if err != nil {
		return cfg, nil // 无行=默认
	}
	_ = errors.New
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, fmt.Errorf("日报配置解析失败: %w", err)
	}
	if cfg.Items == nil {
		cfg.Items = append([]string{}, DailyItemIDs...)
	}
	if !dailyFormatValid(cfg.Format) {
		cfg.Format = "markdown"
	}
	return cfg, nil
}

// SaveDailyConfig 落库单用户配置（format 白名单校验，非法回退 markdown）。
func SaveDailyConfig(cfg DailyConfig) error {
	if !dailyFormatValid(cfg.Format) {
		cfg.Format = "markdown"
	}
	raw, err := json.Marshal(map[string]any{
		"enabled": cfg.Enabled, "send_time": cfg.SendTime,
		"items": cfg.Items, "format": cfg.Format,
	})
	if err != nil {
		return err
	}
	_, err = db.DB.Exec(`INSERT INTO notification_daily (user_id, config, updated_at) VALUES (?,?,datetime('now'))
		ON CONFLICT(user_id) DO UPDATE SET config=excluded.config, updated_at=excluded.updated_at`,
		cfg.UserID, string(raw))
	return err
}

// DeliverDailyForAll 遍历全部启用日报的用户：按各自配置渲染昨日摘要并直接
// 落 pending 投递（不经事件订阅面——日报是独立区块，不走订阅矩阵过滤）。
// 返回渲染成功的用户数。Scheduled 任务体与管理员手动触发共用本函数（单源）。
func DeliverDailyForAll(now time.Time) (int, error) {
	rows, err := db.DB.Query(`SELECT user_id FROM notification_daily WHERE COALESCE(json_extract(config,'$.enabled'),1)=1`)
	if err != nil {
		return 0, err
	}
	var users []int64
	for rows.Next() {
		var u int64
		if rows.Scan(&u) == nil {
			users = append(users, u)
		}
	}
	rows.Close()
	rendered := 0
	for _, u := range users {
		cfg, err := GetDailyConfig(u)
		if err != nil || !cfg.Enabled {
			continue
		}
		data, err := CollectDailyData(context.Background(), now)
		if err != nil {
			continue
		}
		content := RenderDaily(data, cfg.Items, cfg.Format)
		if err := deliverDaily(u, content, now); err != nil {
			continue
		}
		rendered++
	}
	return rendered, nil
}

// deliverDaily 日报直接落 pending 投递（content 为渲染后正文；事件键
// sys.daily_report 仅作投递记录展示——不在事件目录）。
func deliverDaily(userID int64, content string, now time.Time) error {
	_, err := db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, created_at)
		VALUES (?,?,?,?,?, 'pending', 0, ?)`,
		userID, EvtDailyReport, LevelInfo, "每日日报", content,
		now.UTC().Format("2006-01-02 15:04:05"))
	return err
}

// AllDailySendTimes 全部启用日报的用户发送时间集（去重升序）——Scheduled
// NextSlotFn 的槽集合来源。
func AllDailySendTimes() ([]string, error) {
	rows, err := db.DB.Query(`SELECT DISTINCT COALESCE(json_extract(config,'$.send_time'),'09:00')
		FROM notification_daily WHERE COALESCE(json_extract(config,'$.enabled'),1)=1 ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DailyData 昨日摘要数据（渲染输入）。
type DailyData struct {
	Date        string
	Requests    int64
	Blocked     int64
	TopRule     string
	Autobans    int64
	CertsActive int64
	CertsFailed int64
	ClusterOK   bool
	ClusterNote string
}

// CollectDailyData 采集昨日摘要（全项目数据一次查询；未勾选项目由渲染层裁剪）。
func CollectDailyData(ctx context.Context, now time.Time) (DailyData, error) {
	y0 := now.AddDate(0, 0, -1).Truncate(24 * time.Hour)
	y1 := y0.Add(24 * time.Hour)
	d := DailyData{Date: y0.Format("2006-01-02")}
	f0, f1 := y0.Format("2006-01-02 15:04:05"), y1.Format("2006-01-02 15:04:05")
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<?`, f0, f1).Scan(&d.Requests)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='blocked'`, f0, f1).Scan(&d.Blocked)
	if e := db.MetricsDB.QueryRowContext(ctx, `SELECT rule_name FROM security_events WHERE event_time>=? AND event_time<? GROUP BY rule_name ORDER BY COUNT(*) DESC LIMIT 1`, f0, f1).Scan(&d.TopRule); e != nil {
		d.TopRule = "无"
	}
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM autoban_recidivism WHERE last_ban_at>=?`, f0).Scan(&d.Autobans)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_jobs WHERE status IN ('issued','wait_reschedule','downloading')`).Scan(&d.CertsActive)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_jobs WHERE status='failed'`).Scan(&d.CertsFailed)
	var master int
	_ = db.DB.QueryRowContext(ctx, `SELECT COALESCE(is_master,1) FROM global_config WHERE id=1`).Scan(&master)
	d.ClusterOK = master == 1
	d.ClusterNote = map[bool]string{true: "正常（主节点）", false: "从节点/未启用"}[d.ClusterOK && master == 1]
	return d, nil
}

// RenderDaily 按格式渲染日报（items 裁剪；html 转义；text/markdown/json 纯文本）。
func RenderDaily(data DailyData, items []string, format string) string {
	enabled := map[string]bool{}
	for _, it := range items {
		enabled[it] = true
	}
	label := func(id string) string {
		if l, ok := DailyItemLabels[id]; ok {
			return l
		}
		return id
	}
	val := func(id string) string {
		switch id {
		case "requests":
			return fmt.Sprintf("%d", data.Requests)
		case "blocked":
			return fmt.Sprintf("%d", data.Blocked)
		case "attack_top":
			return data.TopRule
		case "autoban":
			return fmt.Sprintf("%d", data.Autobans)
		case "cert_status":
			return fmt.Sprintf("活跃 %d / 失败 %d", data.CertsActive, data.CertsFailed)
		case "cluster_status":
			return data.ClusterNote
		}
		return ""
	}
	switch format {
	case "json":
		obj := map[string]any{"date": data.Date}
		for _, it := range DailyItemIDs {
			if enabled[it] {
				obj[it] = val(it)
			}
		}
		raw, _ := json.MarshalIndent(obj, "", "  ")
		return string(raw)
	case "html":
		var b strings.Builder
		fmt.Fprintf(&b, "<h3>Lazy Balancer 日报（%s）</h3><ul>", html.EscapeString(data.Date))
		for _, it := range DailyItemIDs {
			if !enabled[it] {
				continue
			}
			fmt.Fprintf(&b, "<li><b>%s</b>：%s</li>", html.EscapeString(label(it)), html.EscapeString(val(it)))
		}
		b.WriteString("</ul>")
		return b.String()
	case "markdown":
		var b strings.Builder
		fmt.Fprintf(&b, "## Lazy Balancer 日报（%s）\n\n", data.Date)
		for _, it := range DailyItemIDs {
			if !enabled[it] {
				continue
			}
			fmt.Fprintf(&b, "- **%s**：%s\n", label(it), val(it))
		}
		return b.String()
	default: // text（白名单兜底；纯文本行）
		var b strings.Builder
		fmt.Fprintf(&b, "Lazy Balancer 日报（%s）\n", data.Date)
		for _, it := range DailyItemIDs {
			if !enabled[it] {
				continue
			}
			fmt.Fprintf(&b, "%s：%s\n", label(it), val(it))
		}
		return b.String()
	}
}

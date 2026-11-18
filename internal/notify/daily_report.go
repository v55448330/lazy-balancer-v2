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
	UserID   int64             `json:"user_id"`
	Enabled  bool              `json:"enabled"`
	SendTime string            `json:"send_time"` // "09:00"
	Items    []string          `json:"items"`     // 勾选项目（见 DailyItemIDs）
	Formats  map[string]string `json:"formats"`   // 通道类型→渲染格式（缺省=自动映射：webhook=json/email=html/qq·wx=markdown）
}

// DailyFormats 渲染格式白名单。
var DailyFormats = []string{"text", "markdown", "html", "json"}

// DailyFormatChannels 格式可配通道白名单（与通知通道类型一致）。
var DailyFormatChannels = []string{"webhook", "email", "qq", "wx_clawbot"}

// dailyFormatValid 格式白名单校验；空值=用自动映射默认。
func dailyFormatValid(f string) bool {
	for _, ok := range DailyFormats {
		if f == ok {
			return true
		}
	}
	return false
}

// DefaultFormatForChannel 通道缺省格式（自动映射单源；派发与预览共用）。
func DefaultFormatForChannel(channelType string) string {
	switch channelType {
	case "webhook":
		return "json"
	case "email":
		return "html"
	case "qq", "wx_clawbot":
		return "markdown"
	}
	return "text"
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
		Items: append([]string{}, DailyItemIDs...), Formats: map[string]string{}}
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
	return cfg, nil
}

// SaveDailyConfig 落库单用户配置（formats 键=通道白名单、值=格式白名单，
// 非法键值丢弃）。
func SaveDailyConfig(cfg DailyConfig) error {
	validChannels := map[string]bool{}
	for _, ch := range DailyFormatChannels {
		validChannels[ch] = true
	}
	formats := map[string]string{}
	for ch, f := range cfg.Formats {
		if validChannels[ch] && dailyFormatValid(f) {
			formats[ch] = f
		}
	}
	raw, err := json.Marshal(map[string]any{
		"enabled": cfg.Enabled, "send_time": cfg.SendTime,
		"items": cfg.Items, "formats": formats,
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
		if err := deliverDaily(u, cfg, data, now); err != nil {
			continue
		}
		rendered++
	}
	return rendered, nil
}

// deliverDaily 日报落 pending 投递：body 存**数据载荷 JSON**（非成品正文）
// ——投递 Daemon 派发时按通道格式渲染（用户裁定「不同通道用不同样式」；
// renderDailyForChannel 单源）。事件键 sys.daily_report 仅作投递记录展示
// （不在事件目录）。
func deliverDaily(userID int64, cfg DailyConfig, data DailyData, now time.Time) error {
	values := dailyValues(data)
	payload, err := json.Marshal(map[string]any{
		"date": data.Date, "items": cfg.Items, "values": values, "formats": cfg.Formats,
	})
	if err != nil {
		return err
	}
	_, err = db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, created_at)
		VALUES (?,?,?,?,?, 'pending', 0, ?)`,
		userID, EvtDailyReport, LevelInfo, "每日日报", string(payload),
		now.UTC().Format("2006-01-02 15:04:05"))
	return err
}

// dailyValues 数据→值映射（渲染共用底座）。
func dailyValues(data DailyData) map[string]string {
	return map[string]string{
		"requests":       fmt.Sprintf("%d", data.Requests),
		"blocked":        fmt.Sprintf("%d", data.Blocked),
		"attack_top":     data.TopRule,
		"autoban":        fmt.Sprintf("%d", data.Autobans),
		"cert_status":    fmt.Sprintf("活跃 %d / 失败 %d", data.CertsActive, data.CertsFailed),
		"cluster_status": data.ClusterNote,
	}
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
	return renderDailyFromValues(data.Date, dailyValues(data), items, format)
}

// renderDailyForChannel 投递派发时的按通道格式渲染（deliverOne 挂钩）：
// body 为日报数据载荷 JSON→用户 per-channel 配置优先，缺省自动映射
// （webhook=JSON、email=HTML、QQ/微信=markdown、未知=text）；
// 非日报事件原样透传。
func renderDailyForChannel(msg Message, channelType, styleFormat string) string {
	if msg.EventType != EvtDailyReport {
		return msg.Body
	}
	var payload struct {
		Date    string            `json:"date"`
		Items   []string          `json:"items"`
		Values  map[string]string `json:"values"`
		Formats map[string]string `json:"formats"`
	}
	if err := json.Unmarshal([]byte(msg.Body), &payload); err != nil || payload.Date == "" {
		return msg.Body // 载荷解析失败回退原文（fail-visible，不静默吞）
	}
	format := payload.Formats[channelType]
	if format == "" {
		format = styleFormat // 通道卡「消息样式」里的日报格式覆盖
	}
	if format == "" {
		format = DefaultFormatForChannel(channelType)
	}
	return renderDailyFromValues(payload.Date, payload.Values, payload.Items, format)
}

// renderDailyFromValues 渲染底座（值映射→格式化文本；html 转义）。
func renderDailyFromValues(date string, values map[string]string, items []string, format string) string {
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
	val := func(id string) string { return values[id] }
	switch format {
	case "json":
		obj := map[string]any{"date": date}
		for _, it := range DailyItemIDs {
			if enabled[it] {
				obj[it] = val(it)
			}
		}
		raw, _ := json.MarshalIndent(obj, "", "  ")
		return string(raw)
	case "html":
		var b strings.Builder
		fmt.Fprintf(&b, "<h3>Lazy Balancer 日报（%s）</h3><ul>", html.EscapeString(date))
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
		fmt.Fprintf(&b, "## Lazy Balancer 日报（%s）\n\n", date)
		for _, it := range DailyItemIDs {
			if !enabled[it] {
				continue
			}
			fmt.Fprintf(&b, "- **%s**：%s\n", label(it), val(it))
		}
		return b.String()
	default: // text（白名单兜底；纯文本行）
		var b strings.Builder
		fmt.Fprintf(&b, "Lazy Balancer 日报（%s）\n", date)
		for _, it := range DailyItemIDs {
			if !enabled[it] {
				continue
			}
			fmt.Fprintf(&b, "%s：%s\n", label(it), val(it))
		}
		return b.String()
	}
}

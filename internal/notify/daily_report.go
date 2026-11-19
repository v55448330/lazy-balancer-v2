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
	case "qq":
		return "markdown"
	case "wx_clawbot":
		return "text" // 微信 iLink 仅纯文本协议，缺省不裹 markdown
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
func DeliverDailyForAll(ctx context.Context, now time.Time) (int, error) {
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
		data, err := CollectDailyData(ctx, now)
		if err != nil {
			taskLogWarn(ctx, "daily", "日报数据采集失败（user=%d）: %v", u, err)
			continue
		}
		if err := deliverDaily(u, cfg, data, now, false); err != nil {
			taskLogWarn(ctx, "daily", "日报投递失败（user=%d）: %v", u, err)
			continue
		}
		rendered++
	}
	taskLogf(ctx, "daily", "日报轮完成：启用用户 %d · 渲染投递 %d", len(users), rendered)
	return rendered, nil
}

// deliverDaily 日报落 pending 投递：body 存**数据载荷 JSON**（非成品正文）
// ——投递 Daemon 派发时按通道格式渲染（用户裁定「不同通道用不同样式」；
// renderDailyForChannel 单源）。事件键 sys.daily_report 仅作投递记录展示
// （不在事件目录）。isTest=单用户测试发送标记（定时全员日报=false）。
func deliverDaily(userID int64, cfg DailyConfig, data DailyData, now time.Time, isTest bool) error {
	values := dailyValues(data)
	payload, err := json.Marshal(map[string]any{
		"date": data.Date, "items": cfg.Items, "values": values, "formats": cfg.Formats,
	})
	if err != nil {
		return err
	}
	testFlag := 0
	if isTest {
		testFlag = 1
	}
	_, err = db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, is_test, created_at)
		VALUES (?,?,?,?,?, 'pending', 0, ?, ?)`,
		userID, EvtDailyReport, LevelInfo, "每日日报", string(payload), testFlag,
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
// （webhook=JSON、email=HTML、QQ=markdown、微信=纯文本、未知=text）；
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

// DailyFieldsFromBody 解析日报载荷→模板变量映射（含 date），供内容模板
// {{requests}} 等日报变量替换；非日报/解析失败返回 nil（不替换）。
func DailyFieldsFromBody(body string) map[string]string {
	var payload struct {
		Date   string            `json:"date"`
		Values map[string]string `json:"values"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil || payload.Date == "" {
		return nil
	}
	fields := make(map[string]string, len(payload.Values)+1)
	for k, v := range payload.Values {
		fields[k] = v
	}
	fields["date"] = payload.Date
	return fields
}

// dailySection 日报分节（emoji+标题+所属项目），渲染按节聚合出表格/列表，
// 对齐运营日报视觉（图标+分节+指标表）；items 裁剪仍生效（空节省略）。
var dailySections = []struct {
	emoji string
	title string
	items []string
}{
	{"🌐", "全局概览", []string{"requests"}},
	{"🛡", "安全风险", []string{"blocked", "attack_top", "autoban"}},
	{"🔒", "证书状态", []string{"cert_status"}},
	{"🖥", "集群状态", []string{"cluster_status"}},
}

// renderDailyFromValues 渲染底座（值映射→分节格式化文本；html 转义）。
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
		fmt.Fprintf(&b, "<h3>📊 Lazy Balancer 每日报告（%s）</h3>", html.EscapeString(date))
		for _, sec := range dailySections {
			rows := secRows(sec.items, enabled, label, val)
			if len(rows) == 0 {
				continue
			}
			fmt.Fprintf(&b, "<h4>%s %s</h4><table border=\"1\" cellspacing=\"0\" cellpadding=\"6\"><tr><th>指标</th><th>数值</th></tr>", sec.emoji, html.EscapeString(sec.title))
			for _, r := range rows {
				fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td></tr>", html.EscapeString(r[0]), html.EscapeString(r[1]))
			}
			b.WriteString("</table>")
		}
		return b.String()
	case "markdown":
		var b strings.Builder
		fmt.Fprintf(&b, "## 📊 Lazy Balancer 每日报告（%s）\n\n", date)
		for _, sec := range dailySections {
			rows := secRows(sec.items, enabled, label, val)
			if len(rows) == 0 {
				continue
			}
			// QQ 官方 markdown 不支持表格（仅标题/加粗/列表/引用/链接/图片），
			// 用加粗列表行呈现指标，避免表格在 QQ 端退化为纯文本竖线。
			fmt.Fprintf(&b, "### %s %s\n\n", sec.emoji, sec.title)
			for _, r := range rows {
				fmt.Fprintf(&b, "- **%s**：%s\n", r[0], r[1])
			}
			b.WriteString("\n")
		}
		return b.String()
	default: // text（白名单兜底；纯文本分节行）
		var b strings.Builder
		fmt.Fprintf(&b, "📊 Lazy Balancer 每日报告（%s）\n", date)
		for _, sec := range dailySections {
			rows := secRows(sec.items, enabled, label, val)
			if len(rows) == 0 {
				continue
			}
			fmt.Fprintf(&b, "\n%s %s\n", sec.emoji, sec.title)
			for _, r := range rows {
				fmt.Fprintf(&b, "%s：%s\n", r[0], r[1])
			}
		}
		return b.String()
	}
}

// secRows 节内启用项目→[label,value] 行（空节省略）。
func secRows(items []string, enabled map[string]bool, label, val func(string) string) [][2]string {
	var rows [][2]string
	for _, it := range items {
		if enabled[it] {
			rows = append(rows, [2]string{label(it), val(it)})
		}
	}
	return rows
}

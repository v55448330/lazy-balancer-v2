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
	"requests", "allowed", "logged", "distinct_ips", "bandwidth", "peak_qps",
	"blocked", "attack_top", "top_ip", "top_ips", "top_paths", "cc_triggered", "autoban",
	"cert_status", "cert_expiring", "cluster_status", "uptime", "threat_db", "app_version",
	"api_calls", "mcp_calls", "task_status", "backup_status", "login_status",
}

// DailyItemLabels 项目中文标签（前端渲染+正文模板共用）。
var DailyItemLabels = map[string]string{
	"requests":       "请求数",
	"allowed":        "放行次数",
	"logged":         "观察次数",
	"distinct_ips":   "独立 IP 数",
	"bandwidth":      "总带宽",
	"peak_qps":       "峰值请求/窗",
	"blocked":        "拦截次数",
	"attack_top":     "攻击 TOP 规则",
	"top_ip":         "TOP 攻击源",
	"top_ips":        "TOP 攻击源 IP",
	"top_paths":      "TOP 攻击路径",
	"cc_triggered":   "CC 触发次数",
	"autoban":        "自动封禁次数",
	"cert_status":    "证书状态",
	"cert_expiring":  "临期证书明细",
	"cluster_status": "集群状态",
	"uptime":         "运行时长",
	"threat_db":      "威胁库版本",
	"app_version":    "应用版本",
	"api_calls":      "API 调用(今日)",
	"mcp_calls":      "MCP 调用",
	"task_status":    "定时任务",
	"backup_status":  "自动备份",
	"login_status":   "登录认证",
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
		"allowed":        fmt.Sprintf("%d", data.Allowed),
		"logged":         fmt.Sprintf("%d", data.Logged),
		"distinct_ips":   fmt.Sprintf("%d", data.DistinctIPs),
		"bandwidth":      data.Bandwidth,
		"peak_qps":       fmt.Sprintf("%d", data.PeakQPS),
		"blocked":        fmt.Sprintf("%d", data.Blocked),
		"attack_top":     data.TopRule,
		"top_ip":         data.TopIP,
		"top_ips":        data.TopIPs,
		"top_paths":      data.TopPaths,
		"cc_triggered":   fmt.Sprintf("%d", data.CCTriggered),
		"autoban":        fmt.Sprintf("%d", data.Autobans),
		"cert_status":    fmt.Sprintf("活跃 %d / 失败 %d", data.CertsActive, data.CertsFailed),
		"cert_expiring":  data.CertExpiring,
		"cluster_status": data.ClusterNote,
		"uptime":         data.Uptime,
		"threat_db":      data.ThreatDB,
		"app_version":    data.AppVersion,
		"api_calls":      fmt.Sprintf("%d", data.APICalls),
		"mcp_calls":      fmt.Sprintf("%d", data.MCPCalls),
		"task_status":    fmt.Sprintf("成功 %d / 失败 %d", data.TaskOK, data.TaskFailed),
		"backup_status":  fmt.Sprintf("成功 %d / 失败 %d", data.BackupOK, data.BackupFailed),
		"login_status":   fmt.Sprintf("成功 %d / 失败 %d / MFA失败 %d", data.LoginOK, data.LoginFailed, data.MFAFailed),
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
	Date         string
	Requests     int64
	Allowed      int64
	Logged       int64
	DistinctIPs  int64
	Bandwidth    string
	PeakQPS      int64
	Blocked      int64
	TopRule      string
	TopIP        string
	TopIPs       string
	TopPaths     string
	CCTriggered  int64
	Autobans     int64
	CertsActive  int64
	CertsFailed  int64
	CertExpiring string
	ClusterOK    bool
	ClusterNote  string
	Uptime       string
	ThreatDB     string
	AppVersion   string
	APICalls     int64
	MCPCalls     int64
	TaskOK       int64
	TaskFailed   int64
	BackupOK     int64
	BackupFailed int64
	LoginOK      int64
	LoginFailed  int64
	MFAFailed    int64
}

// CollectDailyData 采集昨日摘要（全项目数据一次查询；未勾选项目由渲染层裁剪）。
func CollectDailyData(ctx context.Context, now time.Time) (DailyData, error) {
	y0 := now.AddDate(0, 0, -1).Truncate(24 * time.Hour)
	y1 := y0.Add(24 * time.Hour)
	d := DailyData{Date: y0.Format("2006-01-02")}
	f0, f1 := y0.Format("2006-01-02 15:04:05"), y1.Format("2006-01-02 15:04:05")
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<?`, f0, f1).Scan(&d.Requests)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='blocked'`, f0, f1).Scan(&d.Blocked)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='allowed'`, f0, f1).Scan(&d.Allowed)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='logged'`, f0, f1).Scan(&d.Logged)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(DISTINCT client_ip) FROM security_events WHERE event_time>=? AND event_time<?`, f0, f1).Scan(&d.DistinctIPs)
	if e := db.MetricsDB.QueryRowContext(ctx, `SELECT rule_name FROM security_events WHERE event_time>=? AND event_time<? GROUP BY rule_name ORDER BY COUNT(*) DESC LIMIT 1`, f0, f1).Scan(&d.TopRule); e != nil {
		d.TopRule = "无"
	}
	if e := db.MetricsDB.QueryRowContext(ctx, `SELECT client_ip FROM security_events WHERE event_time>=? AND event_time<? AND action='blocked' GROUP BY client_ip ORDER BY COUNT(*) DESC LIMIT 1`, f0, f1).Scan(&d.TopIP); e != nil {
		d.TopIP = "无"
	}
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM autoban_recidivism WHERE last_ban_at>=?`, f0).Scan(&d.Autobans)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_jobs WHERE status IN ('issued','wait_reschedule','downloading')`).Scan(&d.CertsActive)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_jobs WHERE status='failed'`).Scan(&d.CertsFailed)
	var master int
	_ = db.DB.QueryRowContext(ctx, `SELECT COALESCE(is_master,1) FROM global_config WHERE id=1`).Scan(&master)
	d.ClusterOK = master == 1
	d.ClusterNote = map[bool]string{true: "正常（主节点）", false: "从节点/未启用"}[d.ClusterOK && master == 1]
	// 流量：带宽（入+出）与峰值请求/采样窗。
	var bw int64
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes_in+bytes_out),0) FROM metrics_history WHERE timestamp>=? AND timestamp<?`, f0, f1).Scan(&bw)
	d.Bandwidth = formatBytes(bw)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COALESCE(MAX(requests_total),0) FROM metrics_history WHERE timestamp>=? AND timestamp<?`, f0, f1).Scan(&d.PeakQPS)
	// 安全明细：TOP 攻击源 IP / TOP 路径（各 5）/ CC 触发。
	d.TopIPs = joinLimitRows(topPairs(ctx, `SELECT client_ip, COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='blocked' GROUP BY client_ip ORDER BY COUNT(*) DESC LIMIT 5`, f0, f1))
	d.TopPaths = joinLimitRows(topPairs(ctx, `SELECT uri, COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='blocked' GROUP BY uri ORDER BY COUNT(*) DESC LIMIT 5`, f0, f1))
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND event_type='cc'`, f0, f1).Scan(&d.CCTriggered)
	// 证书临期明细：30 天内到期的已签发证书（域名+到期日）。
	d.CertExpiring = certExpiringList(ctx, now)
	// 系统运行：时长/威胁库版本/应用版本。
	d.Uptime = formatUptime(time.Since(processStartedAt))
	d.ThreatDB = threatDBVersion(ctx)
	d.AppVersion = AppVersion
	// 接入与任务：REST 当日调用/MCP 昨日调用/任务/备份。
	if DailyRESTCalls != nil {
		d.APICalls = DailyRESTCalls()
	}
	_ = db.DB.QueryRowContext(ctx, `SELECT COALESCE(SUM(calls),0) FROM mcp_tool_stats WHERE date=?`, y0.Format("2006-01-02")).Scan(&d.MCPCalls)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM task_runs WHERE started_at>=? AND started_at<? AND status='success'`, f0, f1).Scan(&d.TaskOK)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM task_runs WHERE started_at>=? AND started_at<? AND status='failed'`, f0, f1).Scan(&d.TaskFailed)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM auto_backups WHERE created_at>=? AND created_at<? AND status='success'`, f0, f1).Scan(&d.BackupOK)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM auto_backups WHERE created_at>=? AND created_at<? AND status='failed'`, f0, f1).Scan(&d.BackupFailed)
	// 用户认证：当日登录成功/失败/MFA 失败（Publish 累加）。
	d.LoginOK, d.LoginFailed, d.MFAFailed = readAuthCounters()
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
	if format == "" && channelType != "qq" && channelType != "wx_clawbot" {
		format = styleFormat // 通道卡日报格式覆盖（机器人协议固定，不接受样式覆盖）
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
	{"🌐", "全局概览", []string{"requests", "allowed", "logged", "distinct_ips", "bandwidth", "peak_qps"}},
	{"🛡", "安全风险", []string{"blocked", "attack_top", "top_ips", "top_paths", "cc_triggered", "autoban"}},
	{"🔒", "证书状态", []string{"cert_status", "cert_expiring"}},
	{"🖥", "集群与运行", []string{"cluster_status", "uptime", "threat_db", "app_version"}},
	{"🔌", "接入与任务", []string{"api_calls", "mcp_calls", "task_status", "backup_status"}},
	{"👤", "用户认证", []string{"login_status"}},
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
	brand := BrandName()
	now := time.Now().Format("2006-01-02 15:04")
	switch format {
	case "json":
		obj := map[string]any{"date": date, "brand": brand, "generated_at": now}
		for _, it := range DailyItemIDs {
			if enabled[it] {
				obj[it] = val(it)
			}
		}
		raw, _ := json.MarshalIndent(obj, "", "  ")
		return string(raw)
	case "html":
		var b strings.Builder
		b.WriteString(`<div style="max-width:640px;margin:0 auto;font-family:'Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif;">`)
		fmt.Fprintf(&b, `<div style="background:#1e293b;padding:16px 24px;"><table style="width:100%%;border-collapse:collapse;"><tr><td style="color:#f8fafc;font-size:16px;font-weight:600;">📊 %s 每日报告</td><td style="text-align:right;"><span style="background:#3b82f6;color:#fff;font-size:11px;padding:2px 10px;">%s</span></td></tr></table></div>`,
			html.EscapeString(brand), html.EscapeString(date))
		b.WriteString(`<div style="border:1px solid #e2e8f0;border-top:none;padding:24px;">`)
		fmt.Fprintf(&b, `<p style="margin:0 0 16px;color:#6b7280;font-size:12px;">%s · 生成于 %s</p>`, html.EscapeString(date), now)
		for _, sec := range dailySections {
			rows := secRows(sec.items, enabled, label, val)
			if len(rows) == 0 {
				continue
			}
			fmt.Fprintf(&b, `<h4 style="margin:16px 0 8px;font-size:14px;color:#0f172a;">%s %s</h4><table style="width:100%%;border-collapse:collapse;font-size:13px;"><tr style="background:#f9fafb;"><th align="left" style="padding:8px 10px;border:1px solid #e5e7eb;color:#374151;">指标</th><th align="left" style="padding:8px 10px;border:1px solid #e5e7eb;color:#374151;">数值</th></tr>`, sec.emoji, html.EscapeString(sec.title))
			for _, r := range rows {
				fmt.Fprintf(&b, `<tr><td style="padding:8px 10px;border:1px solid #e5e7eb;color:#6b7280;">%s</td><td style="padding:8px 10px;border:1px solid #e5e7eb;color:#111827;font-weight:600;">%s</td></tr>`, html.EscapeString(r[0]), html.EscapeString(r[1]))
			}
			b.WriteString("</table>")
		}
		fmt.Fprintf(&b, `<p style="margin:16px 0 0;color:#9ca3af;font-size:12px;text-align:center;">此邮件由 %s 通知中心自动发送 · %s</p></div></div>`, html.EscapeString(brand), now)
		return b.String()
	case "markdown":
		var b strings.Builder
		fmt.Fprintf(&b, "## 📊 %s 每日报告（%s）\n\n", brand, date)
		for _, sec := range dailySections {
			rows := secRows(sec.items, enabled, label, val)
			if len(rows) == 0 {
				continue
			}
			// QQ 端实测支持 markdown 表格（用户提供的 QQ 渲染截图为准，
			// 纠正此前"不支持表格"的误判）；指标/数值两列表格呈现。
			fmt.Fprintf(&b, "### %s %s\n\n| 指标 | 数值 |\n| --- | --- |\n", sec.emoji, sec.title)
			for _, r := range rows {
				fmt.Fprintf(&b, "| %s | %s |\n", r[0], r[1])
			}
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "> %s · %s\n", brand, now)
		return b.String()
	default: // text（白名单兜底；纯文本分节行）
		var b strings.Builder
		fmt.Fprintf(&b, "📊 %s 每日报告（%s）\n", brand, date)
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
		fmt.Fprintf(&b, "\n—— %s · %s\n", brand, now)
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

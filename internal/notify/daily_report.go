package notify

// 日报配置与三格式渲染（html/json/markdown）。
// 配置落 notification_daily（user_id 主键）；发送时间 per-user（Scheduled
// NextSlotFn 取全部用户时间集的最早槽，投递时按各用户配置分桶）。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/db"
)

// dailyReportTaskID 日报定时任务 ID（services 注册的 notification-daily-report；
// 任务日志落 tasks/notification-daily-report.log 的落点键）。
const dailyReportTaskID = "notification-daily-report"

// dailyTimeLayout 库内墙钟串布局（各库统一秒级、无时区后缀）。
const dailyTimeLayout = "2006-01-02 15:04:05"

// DailySlotGrace 用户 send_time 槽的到期宽限：引擎 tick 抖动/启动补跑允许迟到
// 数分钟仍按该槽投递；超出宽限不追溯（昨日摘要跨天已无意义）。排程侧
// （services.nextDailyReportSlot）与投递侧（dailySlotDue）共用本单源。
const DailySlotGrace = 5 * time.Minute

// DailyLocation 日报「本地日历日」时区单源（services 启动装配注入
// CurrentLocation——与全站配置时区/task_runs 墙钟同源；未注入=进程 TZ）。
var DailyLocation func() *time.Location

// dailySlotScopeKey 定时分槽标记（引擎自动 tick 注入）：只有它存在时才按
// 各用户 send_time 分桶；管理端「立即全员发送」与任务页手动执行保持强发。
type dailySlotScopeKey struct{}

func withDailySlotScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, dailySlotScopeKey{}, true)
}

func dailySlotScoped(ctx context.Context) bool {
	v, _ := ctx.Value(dailySlotScopeKey{}).(bool)
	return v
}

func dailyLocation() *time.Location {
	if DailyLocation != nil {
		if loc := DailyLocation(); loc != nil {
			return loc
		}
	}
	return time.Local
}

// dailyDayBounds 昨日本地日历日半开区间 [day0, day1)（配置时区墙钟）。
// 不用 Truncate(24h)：那是「自 UTC 零点起算的整日」，在 +08:00 会得到本地
// 08:00→08:00 的窗口（历史缺陷）。
func dailyDayBounds(now time.Time) (day0, day1 time.Time) {
	loc := dailyLocation()
	n := now.In(loc)
	day0 = time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, -1)
	day1 = day0.AddDate(0, 0, 1)
	return day0, day1
}

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
	"blocked", "attack_top", "top_ips", "top_paths", "cc_triggered", "autoban",
	"cert_status", "cert_expiring", "cluster_status", "nodes_summary", "uptime", "threat_db", "app_version",
	"api_calls", "mcp_calls", "task_status", "backup_status", "login_status",
}

// legacyDailyItemIDs 已从清单移除的历史项目（2026-11-21 裁定：top_ip 与
// top_ips 同源同值的重复项，保留 top_ips）。存量配置读到这些键即丢弃——
// 渲染层本就按分节项目裁剪，丢弃是为了让配置/预览/导出三面不再出现幽灵项。
var legacyDailyItemIDs = []string{"top_ip"}

// normalizeDailyItems 过滤已移除的历史项目（未知键保留：可能是更新版本写入
// 的配置，跨版本回滚时不该被静默清空）。
func normalizeDailyItems(items []string) []string {
	if len(items) == 0 {
		return items
	}
	drop := make(map[string]bool, len(legacyDailyItemIDs))
	for _, id := range legacyDailyItemIDs {
		drop[id] = true
	}
	out := make([]string, 0, len(items)+1)
	hasCluster, hasNodes := false, false
	for _, id := range items {
		if drop[id] {
			continue
		}
		if id == "cluster_status" {
			hasCluster = true
		}
		if id == "nodes_summary" {
			hasNodes = true
		}
		out = append(out, id)
	}
	// 存量配置升级（2026-11-22）：集群模块老配置只含 cluster_status——
	// 自动补「各节点摘要」，避免升级后集群视角静默缺失。UI 模块勾选会整组
	// 增删（取消集群模块连 cluster_status 一起去掉），不会出现「反复复活」。
	if hasCluster && !hasNodes {
		out = append(out, "nodes_summary")
	}
	return out
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
	"top_ips":        "TOP 攻击源 IP",
	"top_paths":      "TOP 攻击路径",
	"cc_triggered":   "CC 触发次数",
	"autoban":        "自动封禁次数",
	"cert_status":    "证书状态",
	"cert_expiring":  "临期证书明细",
	"cluster_status": "集群状态",
	"nodes_summary":  "各节点摘要",
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
// 查询失败必须上抛：把「库坏了」伪装成「无配置」会让日报静默改回默认项目/时间，
// 用户看到的覆盖范围变化与真实故障无法区分（SYSH-152-14）。
func GetDailyConfig(userID int64) (DailyConfig, error) {
	cfg := DailyConfig{UserID: userID, Enabled: true, SendTime: "09:00",
		Items: append([]string{}, DailyItemIDs...), Formats: map[string]string{}}
	var raw string
	err := db.DB.QueryRow(`SELECT COALESCE(config,'') FROM notification_daily WHERE user_id=?`, userID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return cfg, nil // 无行=默认
	}
	if err != nil {
		return cfg, fmt.Errorf("读取日报配置失败: %w", err)
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, fmt.Errorf("日报配置解析失败: %w", err)
	}
	if cfg.Items == nil {
		cfg.Items = append([]string{}, DailyItemIDs...)
	}
	cfg.Items = normalizeDailyItems(cfg.Items)
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

// DeliverDailyForAll 遍历启用日报的用户：按各自配置渲染昨日摘要并直接落
// pending 投递（不经事件订阅面——日报是独立区块，不走订阅矩阵过滤）。
// 分槽：引擎自动 tick 路径（ctx 带 dailySlotScope 标记）只投递各自 send_time
// 槽到期的用户（槽取全部用户时间集，见 AllDailySendTimes）；管理端手动触发
// 与任务页「立即执行」不带标记=立即全员强发，不受槽约束。
// 返回渲染成功的用户数。
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
	scheduled := dailySlotScoped(ctx)
	loc := dailyLocation()
	rendered, skipped := 0, 0
	for _, u := range users {
		cfg, err := GetDailyConfig(u)
		if err != nil {
			taskLogWarn(ctx, "daily", "日报配置读取失败（user=%d）: %v", u, err)
			continue
		}
		if !cfg.Enabled {
			continue
		}
		if scheduled && !dailySlotDue(u, cfg, now, loc) {
			skipped++
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
	taskLogf(ctx, "daily", "日报轮完成：启用用户 %d · 渲染投递 %d · 非本槽跳过 %d（定时=%v）", len(users), rendered, skipped, scheduled)
	return rendered, nil
}

// dailySlotDue 定时路径判定：该用户 send_time 槽已到期且在宽限窗内，
// 且本槽尚未投递过（同槽重入/重复 tick 不重复发）。槽语义与排程侧
// （services.dailyReportSlotAt）共用 DailySlotCandidate 单源——23:5x 槽的
// 宽限窗跨零点时，排程按昨日槽触发，投递侧也必须认昨日槽（NOTIF154-P3-01）。
func dailySlotDue(userID int64, cfg DailyConfig, now time.Time, loc *time.Location) bool {
	slot, ok := DailySlotCandidate(now, cfg.SendTime, loc)
	if !ok {
		return false
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries
		WHERE user_id=? AND event_type=? AND is_test=0 AND created_at>=?`,
		userID, EvtDailyReport, slot.UTC().Format(dailyTimeLayout)).Scan(&n); err != nil {
		// 读失败按「未投递」继续：宁可重复一份日报，也不让故障吞掉当天日报。
		taskLogWarn(context.Background(), "daily", "日报槽水位查询失败（user=%d）: %v", userID, err)
		return true
	}
	return n == 0
}

// DailySlotCandidate 用户 send_time 在 now 时刻的「到期槽」与是否到期：
// 槽 ≤ now 且落在 DailySlotGrace 宽限内，含昨日同一时刻（宽限窗跨零点）。
// 排程侧（services.dailyReportSlotAt）与投递侧（dailySlotDue）共用本单源，
// 两处判定不允许各自实现（23:58 槽在次日 00:02 排程触发而投递侧按今日
// 23:58 判未到期 → 0 投递 + 宽限窗内重复空跑，NOTIF154-P3-01）。
func DailySlotCandidate(now time.Time, sendTime string, loc *time.Location) (time.Time, bool) {
	if loc == nil {
		loc = time.Local
	}
	today := dailySlotAt(now, sendTime, loc)
	// 昨日同刻先查：跨零点宽限窗内最多只有一个候选在窗内。
	if prev := today.AddDate(0, 0, -1); !prev.After(now) && now.Sub(prev) <= DailySlotGrace {
		return prev, true
	}
	if !today.After(now) && now.Sub(today) <= DailySlotGrace {
		return today, true
	}
	return time.Time{}, false
}

// DailySlotAt 当日 send_time 槽时刻（配置时区；非法 send_time 按 09:00
// 兜底，与 DailySlotCandidate 同源）。排程侧推算「下一个未来槽」用。
func DailySlotAt(now time.Time, sendTime string, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.Local
	}
	return dailySlotAt(now, sendTime, loc)
}

// dailySlotAt 当日 send_time 槽时刻（配置时区）。
func dailySlotAt(now time.Time, sendTime string, loc *time.Location) time.Time {
	n := now.In(loc)
	hh, mm := 9, 0
	if t, err := time.ParseInLocation("15:04", sendTime, loc); err == nil {
		hh, mm = t.Hour(), t.Minute()
	}
	return time.Date(n.Year(), n.Month(), n.Day(), hh, mm, 0, 0, loc)
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
		"top_ips":        data.TopIPs,
		"top_paths":      data.TopPaths,
		"cc_triggered":   fmt.Sprintf("%d", data.CCTriggered),
		"autoban":        fmt.Sprintf("%d", data.Autobans),
		"cert_status":    fmt.Sprintf("活跃 %d / 失败 %d", data.CertsActive, data.CertsFailed),
		"cert_expiring":  data.CertExpiring,
		"cluster_status": data.ClusterNote,
		"nodes_summary":  data.NodesSummary,
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
	TopIPs       string
	TopPaths     string
	CCTriggered  int64
	Autobans     int64
	CertsActive  int64
	CertsFailed  int64
	CertExpiring string
	ClusterOK    bool
	ClusterNote  string
	NodesSummary string // 各从节点昨日统计摘要（多行；主节点本地表聚合）
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
//
// 时间口径（三库混存，必须按各自口径派生窗口，否则时区偏移会把昨日事件切出窗口）：
//   - security_events.event_time / metrics_history.timestamp / audit_log.created_at /
//     auto_backups.created_at：UTC 墙钟串 → 窗口用 UTC 串；
//   - task_runs.started_at：配置时区墙钟串 → 窗口用本地串；
//   - mcp_tool_stats.date：本地日历日 → 直接比日期标签。
func CollectDailyData(ctx context.Context, now time.Time) (DailyData, error) {
	day0, day1 := dailyDayBounds(now)
	d := DailyData{Date: day0.Format("2006-01-02")}
	u0, u1 := day0.UTC().Format(dailyTimeLayout), day1.UTC().Format(dailyTimeLayout)
	l0, l1 := day0.Format(dailyTimeLayout), day1.Format(dailyTimeLayout)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<?`, u0, u1).Scan(&d.Requests)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='blocked'`, u0, u1).Scan(&d.Blocked)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='allowed'`, u0, u1).Scan(&d.Allowed)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='logged'`, u0, u1).Scan(&d.Logged)
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(DISTINCT client_ip) FROM security_events WHERE event_time>=? AND event_time<?`, u0, u1).Scan(&d.DistinctIPs)
	if e := db.MetricsDB.QueryRowContext(ctx, `SELECT rule_name FROM security_events WHERE event_time>=? AND event_time<? GROUP BY rule_name ORDER BY COUNT(*) DESC LIMIT 1`, u0, u1).Scan(&d.TopRule); e != nil {
		d.TopRule = "无"
	}
	// 自动封禁次数：audit_log 的「自动封禁」系统动作行（与 UI 状态卡
	// services.AutobanBannedToday 同源：逐 IP 行各计 1 + 单轮上限的省略量取
	// 汇总行携带数），窗口 [u0,u1) 上下界都有——旧口径查累犯表 last_ban_at>=f0
	// 既无上界、也不含升级关闭（Escalation=off 不写累犯表）时的封禁。
	d.Autobans = countAutobanBans(ctx, u0, u1)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_jobs WHERE status IN ('issued','wait_reschedule','downloading')`).Scan(&d.CertsActive)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_jobs WHERE status='failed'`).Scan(&d.CertsFailed)
	var master int
	_ = db.DB.QueryRowContext(ctx, `SELECT COALESCE(is_master,1) FROM global_config WHERE id=1`).Scan(&master)
	d.ClusterOK = master == 1
	d.ClusterNote = map[bool]string{true: "正常（主节点）", false: "从节点/未启用"}[d.ClusterOK && master == 1]
	// 流量：带宽（入+出）与峰值请求/采样窗。
	var bw int64
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes_in+bytes_out),0) FROM metrics_history WHERE timestamp>=? AND timestamp<?`, u0, u1).Scan(&bw)
	d.Bandwidth = formatBytes(bw)
	d.PeakQPS = peakWindowRequests(ctx, u0, u1)
	// 安全明细：TOP 攻击源 IP / TOP 路径（各 5）/ CC 触发。
	d.TopIPs = joinLimitRows(topPairs(ctx, `SELECT client_ip, COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='blocked' GROUP BY client_ip ORDER BY COUNT(*) DESC LIMIT 5`, u0, u1))
	d.TopPaths = joinLimitRows(topPairs(ctx, `SELECT uri, COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND action='blocked' GROUP BY uri ORDER BY COUNT(*) DESC LIMIT 5`, u0, u1))
	_ = db.MetricsDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events WHERE event_time>=? AND event_time<? AND event_type='cc'`, u0, u1).Scan(&d.CCTriggered)
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
	_ = db.DB.QueryRowContext(ctx, `SELECT COALESCE(SUM(calls),0) FROM mcp_tool_stats WHERE date=?`, d.Date).Scan(&d.MCPCalls)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM task_runs WHERE started_at>=? AND started_at<? AND status='success'`, l0, l1).Scan(&d.TaskOK)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM task_runs WHERE started_at>=? AND started_at<? AND status='failed'`, l0, l1).Scan(&d.TaskFailed)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM auto_backups WHERE created_at>=? AND created_at<? AND status='success'`, u0, u1).Scan(&d.BackupOK)
	_ = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM auto_backups WHERE created_at>=? AND created_at<? AND status='failed'`, u0, u1).Scan(&d.BackupFailed)
	// 用户认证：昨日（日期标签同源）登录成功/失败/MFA 失败（Publish 累加）。
	d.LoginOK, d.LoginFailed, d.MFAFailed = readAuthCounters(d.Date)
	// 集群从节点昨日统计（2026-11-22 主节点集中汇聚；已批准从节点逐行列出，
	// 当日未上报的标「未上报」——数据缺失可见，不静默).
	d.NodesSummary = collectNodesSummary(ctx, d.Date)
	return d, nil
}

// collectNodesSummary 主节点本地表聚合各从节点昨日统计摘要（多行文本）。
// nodes 表左连当日统计：已批准从节点逐行列出，当日未上报的标「未上报」
// （数据缺失可见，不静默）；单机/未声明集群（无已批准从节点行）返回空串=
// 该行整项在渲染层省略。孤儿统计行（节点已删除/未批准）不渲染——nodes 是
// 集群声明的唯一事实源。查询失败返回可见降级文案并留痕，不伪装成「无节点」。
func collectNodesSummary(ctx context.Context, date string) string {
	if db.DB == nil {
		return ""
	}
	rows, err := db.DB.QueryContext(ctx, `SELECT n.name, s.stats_json
		FROM nodes n
		LEFT JOIN cluster_node_daily_stats s ON s.node = n.name AND s.date = ?
		WHERE COALESCE(n.mode,'slave')='slave' AND COALESCE(n.is_approved,0)=1
		ORDER BY n.name`, date)
	if err != nil {
		taskLogWarn(ctx, "daily", "各节点统计查询失败（date=%s）: %v", date, err)
		return "节点统计读取失败（详见任务日志）"
	}
	defer rows.Close()
	var lines []string
	seen := map[string]bool{}
	for rows.Next() {
		var node string
		var raw sql.NullString
		if err := rows.Scan(&node, &raw); err != nil {
			continue
		}
		if seen[node] {
			continue // 节点名无 UNIQUE 约束；同名行只报一次
		}
		seen[node] = true
		if !raw.Valid || strings.TrimSpace(raw.String) == "" {
			lines = append(lines, node+"：未上报")
			continue
		}
		var st ClusterNodeStats
		if err := json.Unmarshal([]byte(raw.String), &st); err != nil {
			lines = append(lines, fmt.Sprintf("%s：数据损坏", node))
			continue
		}
		line := fmt.Sprintf("%s：请求 %d · 拦截 %d · 独立IP %d", node, st.Requests, st.Blocked, st.DistinctIPs)
		if st.TopRule != "" && st.TopRule != "无" {
			line += " · TOP 规则 " + st.TopRule
		}
		if st.CCTriggered > 0 {
			line += fmt.Sprintf(" · CC %d", st.CCTriggered)
		}
		if st.Autobans > 0 {
			line += fmt.Sprintf(" · 自动封禁 %d", st.Autobans)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		taskLogWarn(ctx, "daily", "各节点统计读取中断（date=%s）: %v", date, err)
		return "节点统计读取失败（详见任务日志）"
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

// peakWindowRequests 昨日采样窗峰值请求数（相邻全局累计采样的最大增量）。
// metrics_history.requests_total 是**累计快照**：MAX(requests_total) 得到的是
// 窗口末尾的累计总量（旧实现把「当日总量」当日峰值报出）。口径：
//   - 只取全局行（rule_id IS NULL）——规则级行是同一流量的明细拆分，重复计入会翻倍；
//   - 增量 = 当前 − 上一样本；负值（/load/重启归零）取当前值，与
//     metrics_counter_checkpoint 的重置钳制同源；
//   - 窗口首样本的上一样本取窗口前最后一条（无基线则首样本不产增量）。
func peakWindowRequests(ctx context.Context, u0, u1 string) int64 {
	if db.MetricsDB == nil {
		return 0
	}
	var prev int64
	hasPrev := false
	if err := db.MetricsDB.QueryRowContext(ctx, `SELECT requests_total FROM metrics_history
		WHERE rule_id IS NULL AND timestamp<? ORDER BY timestamp DESC LIMIT 1`, u0).Scan(&prev); err == nil {
		hasPrev = true
	}
	rows, err := db.MetricsDB.QueryContext(ctx, `SELECT requests_total FROM metrics_history
		WHERE rule_id IS NULL AND timestamp>=? AND timestamp<? ORDER BY timestamp`, u0, u1)
	if err != nil {
		return 0
	}
	defer rows.Close()
	var peak int64
	for rows.Next() {
		var cur int64
		if rows.Scan(&cur) != nil {
			continue
		}
		if hasPrev {
			delta := cur - prev
			if delta < 0 {
				delta = cur
			}
			if delta > peak {
				peak = delta
			}
		}
		prev, hasPrev = cur, true
	}
	return peak
}

// autobanAuditSummaryPrefix 单轮逐 IP 审计行超限时的汇总行前缀。与
// services.autobanAuditSummaryPrefix 必须一字一致（notify 不可反向 import
// services；两处同源契约，改动时同步）。
const autobanAuditSummaryPrefix = "汇总：其余 "

// countAutobanBans 窗口内自动封禁次数。折算公式与 services.AutobanBannedToday
// 的 SQL 同口径：前缀命中行取前缀后的省略数（解析不出按 1 保守计），其余
// 「自动封禁」行各计 1——行数上限不会让洪峰轮次的封禁数被截断或重复计。
func countAutobanBans(ctx context.Context, u0, u1 string) int64 {
	if db.AuditDB == nil {
		return 0
	}
	prefixRunes := utf8.RuneCountInString(autobanAuditSummaryPrefix)
	var n int64
	err := db.AuditDB.QueryRowContext(ctx, `SELECT COALESCE(SUM(
		CASE WHEN substr(COALESCE(detail,''),1,?) = ?
		THEN MAX(CAST(substr(COALESCE(detail,''),?) AS INTEGER), 1)
		ELSE 1 END), 0)
		FROM audit_log WHERE action=? AND created_at>=? AND created_at<?`,
		prefixRunes, autobanAuditSummaryPrefix, prefixRunes+1, "自动封禁", u0, u1).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// RenderDaily 按格式渲染日报（items 裁剪；html 转义；text/markdown/json 纯文本）。
func RenderDaily(data DailyData, items []string, format string) string {
	return renderDailyFromValues(data.Date, dailyValues(data), items, format)
}

// renderDailyForChannel 投递派发时的按通道格式渲染（deliverOne 挂钩）：
// body 为日报数据载荷 JSON→用户 per-channel 配置优先，缺省自动映射
// （webhook=JSON、email=HTML、QQ=markdown、微信=纯文本、未知=text）；
// 非日报事件原样透传。不关心格式的调用方（模板链路/测试）用本入口；
// 需要 Content-Type 决序的派发侧用 renderDailyForChannelFormat。
func renderDailyForChannel(msg Message, channelType, styleFormat string) string {
	body, _ := renderDailyForChannelFormat(msg, channelType, styleFormat)
	return body
}

// renderDailyForChannelFormat 同 renderDailyForChannel，并返回正文实际采用的
// 渲染格式（"html"/"markdown"/"text"/"json"；非日报/载荷损坏回空串=未知）。
// 派发侧把它写入 Message.ContentFormat，邮件通道据此决定 Content-Type
// （NOTIF153-02：只有 html 渲染可按 text/html 发送；text/markdown/json 必须
// text/plain，否则日报值里的 '<script>' 会被邮件客户端当 HTML 执行）。
func renderDailyForChannelFormat(msg Message, channelType, styleFormat string) (string, string) {
	if msg.EventType != EvtDailyReport {
		return msg.Body, ""
	}
	var payload struct {
		Date    string            `json:"date"`
		Items   []string          `json:"items"`
		Values  map[string]string `json:"values"`
		Formats map[string]string `json:"formats"`
	}
	if err := json.Unmarshal([]byte(msg.Body), &payload); err != nil || payload.Date == "" {
		return msg.Body, "" // 载荷解析失败回退原文（fail-visible，不静默吞）
	}
	// 机器人日报格式协议固定（QQ=markdown 表格、微信=纯文本），不受用户/
	// 通道配置覆盖（§14）；非机器人按 日报页配置 > 通道样式 > 自动映射。
	format := dailyChannelFormat(payload.Formats, channelType, styleFormat)
	return renderDailyFromValues(payload.Date, payload.Values, payload.Items, format), format
}

// dailyChannelFormat 日报格式决序单源（渲染与邮件 Content-Type 共用）：
// 机器人协议固定；其余 日报页配置 > 通道样式 > 自动映射。
func dailyChannelFormat(payloadFormats map[string]string, channelType, styleFormat string) string {
	switch channelType {
	case "qq":
		return "markdown"
	case "wx_clawbot":
		return "text"
	}
	if format := payloadFormats[channelType]; format != "" {
		return format
	}
	if styleFormat != "" {
		return styleFormat
	}
	return DefaultFormatForChannel(channelType)
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
	// 顺序（2026-11-22 用户裁定第四轮）：先答「服务是否正常」再看统计——
	// 服务状态（集群节点/运行时长/库版本）→ 流量概览 → 安全风险 → 证书 →
	// 接入任务 → 用户认证。四格式与 DailyModules 共用本单源。
	{"🖥", "服务状态", []string{"cluster_status", "nodes_summary", "uptime", "threat_db", "app_version"}},
	{"🌐", "全局概览", []string{"requests", "allowed", "logged", "distinct_ips", "bandwidth", "peak_qps"}},
	{"🛡", "安全风险", []string{"blocked", "attack_top", "top_ips", "top_paths", "cc_triggered", "autoban"}},
	{"🔒", "证书状态", []string{"cert_status", "cert_expiring"}},
	{"🔌", "接入与任务", []string{"api_calls", "mcp_calls", "task_status", "backup_status"}},
	{"👤", "用户认证", []string{"login_status"}},
}

// DailyModuleExport 日报大模块（配置 UI 按模块勾选的契约形状）。
type DailyModuleExport struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Emoji string   `json:"emoji"`
	Items []string `json:"items"`
}

// DailyModules 模块全集导出（2026-11-21 用户裁定：配置按大模块选择，
// 项目级勾选粒度太细；items 存储与渲染契约不变——模块=项目的稳定分组）。
func DailyModules() []DailyModuleExport {
	out := make([]DailyModuleExport, 0, len(dailySections))
	for i, sec := range dailySections {
		out = append(out, DailyModuleExport{
			ID:    fmt.Sprintf("mod%d", i+1),
			Label: sec.title,
			Emoji: sec.emoji,
			Items: append([]string{}, sec.items...),
		})
	}
	return out
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
			// 空值整项省略（与 html/markdown/text 的 secRows 同口径）：
			// nodes_summary 单机恒空、top_ips 无攻击时为空——渲染空键会让
			// 接收端误以为「有该项目但值为空」。
			if enabled[it] && val(it) != "" {
				obj[it] = val(it)
			}
		}
		raw, _ := json.MarshalIndent(obj, "", "  ")
		return string(raw)
	case "html":
		escBR := func(s string) string { return strings.ReplaceAll(html.EscapeString(s), "\n", "<br>") }
		// 版式（2026-11-22 第四轮裁定）：表头带/数据周期行/分区/指标表/页脚
		// 共用同一 28px 内容列（旧版表头全宽+分区 24px 缩进+周期条独立内边距
		// 三种错位）；分区用色条标题+分隔线，不再嵌套缩进卡。
		sectionAccent := []string{"#3b82f6", "#ef4444", "#f59e0b", "#8b5cf6", "#06b6d4", "#64748b"}
		var b strings.Builder
		b.WriteString(`<div style="max-width:640px;margin:0 auto;font-family:'Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif;background:#ffffff;border:1px solid #e2e8f0;">`)
		fmt.Fprintf(&b, `<div style="background:linear-gradient(135deg,#1e293b 0%%,#334155 100%%);padding:22px 28px;"><table style="width:100%%;border-collapse:collapse;"><tr><td style="color:#f8fafc;font-size:17px;font-weight:600;letter-spacing:.5px;">📊 %s 每日报告</td><td align="right" style="vertical-align:middle;"><span style="background:rgba(255,255,255,.14);color:#e2e8f0;font-size:12px;padding:4px 12px;border:1px solid rgba(255,255,255,.22);">%s</span></td></tr></table></div>`,
			html.EscapeString(brand), html.EscapeString(date))
		fmt.Fprintf(&b, `<div style="padding:0 28px;"><p style="margin:14px 0 4px;color:#94a3b8;font-size:12px;">数据周期 %s · 生成于 %s</p>`, html.EscapeString(date), now)
		first := true
		for si, sec := range dailySections {
			rows := secRows(sec.items, enabled, label, val)
			if len(rows) == 0 {
				continue
			}
			accent := sectionAccent[si%len(sectionAccent)]
			divider := "border-top:1px solid #f1f5f9;"
			if first {
				divider = ""
				first = false
			}
			fmt.Fprintf(&b, `<div style="%spadding:16px 0 14px;">`, divider)
			fmt.Fprintf(&b, `<div style="display:inline-block;width:4px;height:14px;background:%s;margin-right:8px;vertical-align:-1px;"></div><span style="font-size:14px;font-weight:600;color:#0f172a;">%s %s</span>`, accent, sec.emoji, html.EscapeString(sec.title))
			b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:10px;">`)
			for ri, r := range rows {
				bg := "#ffffff"
				if ri%2 == 1 {
					bg = "#f8fafc"
				}
				fmt.Fprintf(&b, `<tr style="background:%s;"><td style="padding:7px 10px 7px 12px;color:#64748b;border-bottom:1px solid #f1f5f9;vertical-align:top;white-space:nowrap;">%s</td><td align="right" style="padding:7px 0 7px 10px;color:#0f172a;font-weight:600;border-bottom:1px solid #f1f5f9;">%s</td></tr>`, bg, html.EscapeString(r[0]), escBR(r[1]))
			}
			b.WriteString(`</table></div>`)
		}
		fmt.Fprintf(&b, `<p style="margin:8px 0 18px;color:#94a3b8;font-size:11px;text-align:center;">此邮件由 %s 通知中心自动发送</p></div></div>`, html.EscapeString(brand))
		return b.String()
	case "markdown":
		// QQ 原生 markdown 支持 #/## 标题、**加粗**、> 引用、- 列表（官方文档），
		// 表格经用户实测可渲染。标量入指标表，多值用加粗标签+无序列表拆行。
		var b strings.Builder
		fmt.Fprintf(&b, "# 📊 %s 每日报告\n> 数据周期 %s · 生成于 %s\n\n", brand, date, now)
		for _, sec := range dailySections {
			rows := secRows(sec.items, enabled, label, val)
			if len(rows) == 0 {
				continue
			}
			fmt.Fprintf(&b, "## %s %s\n\n", sec.emoji, sec.title)
			var tbl, lists strings.Builder
			for _, r := range rows {
				if strings.Contains(r[1], "\n") {
					if md, ok := mdMultiValueTable(r[2], r[1]); ok {
						// 标签与表格间、相邻块间必须空行：粘连时 markdown 解析器把
						// 下一块的标签行/表头/分隔行吞成上一表的正文行（2026-11-22
						// 用户实测攻击路径表头变数据行）。
						fmt.Fprintf(&lists, "**%s**\n\n%s\n", r[0], md)
					} else {
						// 解析失败（未知形态/数据损坏行）：整项回退加粗标签+列表。
						// 块间空行与表格分支同口径——粘连时下一块标签会被
						// markdown 解析器吞成上一块的列表项/表行（NOTIF154-P3-05）。
						fmt.Fprintf(&lists, "**%s**\n\n", r[0])
						for _, ln := range strings.Split(r[1], "\n") {
							fmt.Fprintf(&lists, "- %s\n", ln)
						}
						lists.WriteString("\n")
					}
				} else {
					fmt.Fprintf(&tbl, "| %s | %s |\n", r[0], r[1])
				}
			}
			if tbl.Len() > 0 {
				b.WriteString("| 指标 | 数值 |\n| :--- | ---: |\n" + tbl.String() + "\n")
			}
			if lists.Len() > 0 {
				b.WriteString(lists.String() + "\n")
			}
		}
		fmt.Fprintf(&b, "---\n> %s\n", brand)
		return b.String()
	default: // text（微信 iLink 纯文本协议；无 markdown 标记，多值独立行）
		var b strings.Builder
		fmt.Fprintf(&b, "📊 %s 每日报告\n%s · 生成于 %s\n────────────\n", brand, date, now)
		for _, sec := range dailySections {
			rows := secRows(sec.items, enabled, label, val)
			if len(rows) == 0 {
				continue
			}
			fmt.Fprintf(&b, "\n%s %s\n", sec.emoji, sec.title)
			for _, r := range rows {
				if strings.Contains(r[1], "\n") {
					fmt.Fprintf(&b, "%s：\n", r[0])
					for _, ln := range strings.Split(r[1], "\n") {
						fmt.Fprintf(&b, "  · %s\n", ln)
					}
				} else {
					fmt.Fprintf(&b, "%s：%s\n", r[0], r[1])
				}
			}
		}
		fmt.Fprintf(&b, "\n—— %s · %s\n", brand, now)
		return b.String()
	}
}

// mdMultiValueTable 多值项按内容语义出 markdown 表格（2026-11-22 用户裁定
// 的日报样式设计）：节点摘要=节点/请求/拦截/独立IP/备注；TOP 攻击源/路径=
// 名目/次数（右对齐）；临期证书=域名/到期日。任何行解析失败整项回退 ok=false
// （fail-safe，不半表半列表）。转义：单元格内管道符会破坏表格，替换为全角。
func mdMultiValueTable(item, value string) (string, bool) {
	cell := func(x string) string { return strings.ReplaceAll(x, "|", "｜") }
	lines := strings.Split(value, "\n")
	switch item {
	case "nodes_summary":
		type nodeRow struct{ node, req, blocked, ips, note string }
		var out []nodeRow
		for _, ln := range lines {
			m := nodesSummaryLine.FindStringSubmatch(ln)
			if m == nil {
				return "", false
			}
			note := "—"
			if strings.TrimSpace(m[5]) != "" {
				note = strings.TrimPrefix(strings.TrimSpace(m[5]), "· ")
			}
			out = append(out, nodeRow{m[1], m[2], m[3], m[4], cell(note)})
		}
		var b strings.Builder
		b.WriteString("| 节点 | 请求 | 拦截 | 独立IP | 备注 |\n| --- | ---: | ---: | ---: | --- |\n")
		for _, r := range out {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", cell(r.node), r.req, r.blocked, r.ips, r.note)
		}
		return b.String(), true
	case "top_ips", "top_paths":
		head := "| 攻击源 IP | 次数 |"
		if item == "top_paths" {
			head = "| 攻击路径 | 次数 |"
		}
		var b strings.Builder
		b.WriteString(head + "\n| --- | ---: |\n")
		for _, ln := range lines {
			i := strings.LastIndex(ln, "×")
			if i < 0 {
				return "", false
			}
			fmt.Fprintf(&b, "| %s | %s |\n", cell(strings.TrimSpace(ln[:i])), strings.TrimSpace(ln[i+len("×"):]))
		}
		return b.String(), true
	case "cert_expiring":
		var b strings.Builder
		b.WriteString("| 域名 | 到期日 |\n| --- | ---: |\n")
		for _, ln := range lines {
			i := strings.LastIndex(ln, "·")
			if i < 0 {
				return "", false
			}
			fmt.Fprintf(&b, "| %s | %s |\n", cell(strings.TrimSpace(ln[:i])), strings.TrimSpace(ln[i+len("·"):]))
		}
		return b.String(), true
	}
	return "", false
}

// nodesSummaryLine 节点摘要行契约：`节点：请求 N · 拦截 N · 独立IP N[ · 附加]`
var nodesSummaryLine = regexp.MustCompile(`^([^：]+)：请求 (\d+) · 拦截 (\d+) · 独立IP (\d+)(.*)$`)

// secRows 节内启用项目→[label,value] 行（空节省略）。空值项目整项省略：
// 单机默认配置的 nodes_summary、无攻击时的 top_ips 等不得渲染空行
// （NOTIF154-P3-02：注释一直承诺渲染层省略，实现此前仍出空标签行）。
func secRows(items []string, enabled map[string]bool, label, val func(string) string) [][3]string {
	var rows [][3]string
	for _, it := range items {
		if !enabled[it] {
			continue
		}
		v := val(it)
		if v == "" {
			continue
		}
		rows = append(rows, [3]string{label(it), v, it})
	}
	return rows
}

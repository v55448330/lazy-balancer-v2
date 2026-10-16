package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// LogStorageInfo 描述一类日志的体量与治理状态。
// SizeBytes 为当前活跃文件/库的大小；RotatedBytes 为轮转副本合计（DB 类为 0）。
// 大小型日志（达到 LimitBytes 即轮转）提供 LimitBytes 与 KeepCount；
// 时间型清理（每日按保留期删除）提供 RetentionNote。
type LogStorageInfo struct {
	Key           string `json:"key"`
	Name          string `json:"name"`
	SizeBytes     int64  `json:"size_bytes"`
	RotatedBytes  int64  `json:"rotated_bytes"`
	RotatedCount  int    `json:"rotated_count"` // 当前归档份数(与 keep_count 上限对照)
	LimitBytes    *int64 `json:"limit_bytes,omitempty"`
	LimitRows     *int64 `json:"limit_rows,omitempty"`
	DBBytes       *int64 `json:"db_bytes,omitempty"`
	KeepCount     int    `json:"keep_count"`
	Rows          *int64 `json:"rows,omitempty"`
	RetentionNote string `json:"retention_note,omitempty"`
	ConfigSource  string `json:"config_source"`
}

// dirBytes 返回 path 的活跃文件大小与轮转副本合计。两类轮转家族都统计
// (SYS-1,2026-09-10 审计):自研 .1..9 shift 后缀;时间戳后缀家族——运行日志
// <path>.YYYYMMDD-HHMMSS(logrotate.go)与 Caddy/timberjack 的 <name>-<ts>-size.log
// isTimberjackRotationCopy 判定文件名是否为 timberjack 轮转副本
// (<stem>-<ts>-size.log / .gz,ts 首字符为数字)。与 timestampedRotationStats
// 的 timberjack 分支同口径(B-2 数字边界校验),聚合枚举时跳过这些副本
// ——它们已由 base 文件的 timestampedRotationStats 计入 rotated,
// 再计入 active 即双计(F-A,第 6 轮审计)。
func isTimberjackRotationCopy(name string) bool {
	suffix := ""
	if strings.HasSuffix(name, "-size.log.gz") {
		suffix = "-size.log.gz"
	} else if strings.HasSuffix(name, "-size.log") {
		suffix = "-size.log"
	} else {
		return false
	}
	trimmed := name[:len(name)-len(suffix)]
	idx := strings.LastIndex(trimmed, "-")
	if idx < 0 || idx+1 >= len(trimmed) {
		return false
	}
	return trimmed[idx+1] >= '0' && trimmed[idx+1] <= '9'
}

func dirBytes(path string) (int64, int64, int) {
	var active, rotated int64
	count := 0
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		active = st.Size()
	}
	for i := 1; i <= 9; i++ {
		if st, err := os.Stat(path + "." + strconv.Itoa(i)); err == nil {
			rotated += st.Size()
			count++
		}
	}
	rotBytes, rotCount := timestampedRotationStats(path)
	rotated += rotBytes
	count += rotCount
	return active, rotated, count
}

// timestampedRotationStats 统计同目录下以「去扩展名 base + 分隔符 + 时间戳」
// 命名的轮转副本的字节数与份数——dirBytes 消费,供 LogStorageBar
// 「已归档 N/M 份」展示。(U4-P3-1:计数弱化版 timestampedRotations/mustSecond
// 生产零调用,已删。)
func timestampedRotationStats(path string) (int64, int) {
	dir := filepath.Dir(path)
	// Sys-N1 根因(第 3 轮审计):运行日志 path=/app/logs/lazy-balancer.log,
	// TrimSuffix 去 .log 后 base=lazy-balancer,而轮转副本实际是
	// lazy-balancer.log.YYYYMMDD-HHMMSS → rest=.log.2026... 不匹配 16 字符判定。
	// 修复:不去扩展名,base 含 .log → rest=.YYYYMMDD-HHMMSS 恰 16 字符。
	// timberjack 族(caddy/rules)的副本 <base去ext>-<ts>-size.log 需去 ext,
	// 故两种 base 各算一次:扩展 base 匹配运行日志族,去 ext base 匹配 timberjack。
	base := filepath.Base(path)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	var total int64
	var cnt int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// 运行日志族(base 含 .log):rest = .YYYYMMDD-HHMMSS(16 字符)
		if strings.HasPrefix(name, base) {
			rest := name[len(base):]
			if len(rest) == 16 && rest[0] == '.' && isDigits(rest[1:9]) && rest[9] == '-' && isDigits(rest[10:]) {
				if info, err := e.Info(); err == nil {
					total += info.Size()
					cnt++
				}
				continue
			}
		}
		// timberjack 族(stem 去 .log):caddy-<ts>-size.log 不以 caddy.log 开头,
		// 须独立按 stem 前缀匹配。B-2(第 4 轮审计):stem='caddy' 的前缀会把
		// 兄弟文件 caddy-tls-<ts>-size.log 也吞入(聚合双计)——加 stem 边界校验:
		// stem 后紧跟的 '-<ts>' 段必须以数字开头(timberjack 时间戳以数字开头,
		// 兄弟文件名如 caddy-tls 的 '-tls' 以字母开头)。
		if strings.HasPrefix(name, stem) {
			rest2 := name[len(stem):]
			if strings.HasPrefix(rest2, "-") && (strings.HasSuffix(rest2, "-size.log") || strings.HasSuffix(rest2, "-size.log.gz")) {
				// stem 后 '-' 到下一 '-' 之间(或到 '-size' 之间)必须全数字
				// B-2:timberjack 时间戳含 T/-/. 非全数字——只需首字符为数字
				// (区分 own 'caddy-2026...' 与 brother 'caddy-tls-...')
				if len(rest2) > 1 && rest2[1] >= '0' && rest2[1] <= '9' {
					if info, err := e.Info(); err == nil {
						total += info.Size()
						cnt++ // F63-B5b-1:timberjack 族份数同计(原漏)
					}
				}
			}
		}
	}
	return total, cnt
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// sanitizeRuleID 与写入侧 sanitizePathComponent / sanitizeRuleLogName 同口径，
// 只保留 caddy_id 字母表 [A-Za-z0-9_-]，其余字符剔除。
func sanitizeRuleID(value string) string {
	out := make([]rune, 0, len(value))
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			out = append(out, r)
		}
	}
	return string(out)
}

func globalConfigInt(column string, fallback int64) int64 {
	// nil 守卫(第 41 轮 APIMCP41-2 集成事故):guardConfiguredJSONBody 经本函数
	// 读配置,无 DB 脚手架的测试/调用形态下 db.DB 为 nil,QueryRow 直接 panic
	// ——nil 与读失败同口径回退默认值。
	if db.DB == nil {
		return fallback
	}
	var v int64
	if err := db.DB.QueryRow("SELECT COALESCE("+column+",?) FROM global_config WHERE id=1", fallback).Scan(&v); err != nil {
		return fallback
	}
	return v
}

func sizeLimitMB(column string, def int64) *int64 {
	limit := globalConfigInt(column, def) * 1024 * 1024
	return &limit
}

// logPaths resolves the two distinct log roots GetLogStats probes:
//   - fixedDir is the hardcoded writer directory (/app/logs) shared by the
//     hardcoded-writer log families — caddy 四份日志（caddy.log/caddy-tls.log/
//     caddy-server.log/caddy-proxy.log）、rules/*.log。这些写入端写死 /app/logs，
//     与 LOG_FILE 无关，故其路径拼接必须固定用 /app/logs；若跟随 LogFile 目录
//     推导，自定义 LOG_FILE 时这些日志会全部显示 0B。
//     certjob-*.log 不在此列（U1-66-03≡L1-66-02）：写入端已并入统一任务日志
//     体系（{任务日志目录}/certjobs/，services.CertJobLogDir 同源）。
//   - runtimePath is the runtime log path, which follows LogFile
//     （空 → /app/logs/lazy-balancer.log）。
//
// wafAuditLogFile 是 Coraza 审计日志文件路径(包级 var 支持测试注入;
// 生产值经 services.AuditLogPath() 单一源——SYSRENDER24-2)。
var wafAuditLogFile = services.AuditLogPath()

// defaultRuntimeLogPath 空 LOG_FILE 下的运行日志兜底路径（写入端写死
// /app/logs，见 logPaths 注释）。包级 var 支持测试注入（wafAuditLogFile 同模式）。
var defaultRuntimeLogPath = "/app/logs/lazy-balancer.log"

func logPaths(cfg *config.Config) (fixedDir, runtimePath string) {
	fixedDir = "/app/logs"
	runtimePath = defaultRuntimeLogPath
	if cfg == nil {
		return fixedDir, runtimePath
	}
	if cfg.LogFile != "" {
		runtimePath = cfg.LogFile
	}
	return fixedDir, runtimePath
}

// GetLogStats 返回全部日志存储的体量与治理信息，供各日志页显示
// 「当前大小 / 阈值（保留 N 份）」与清理策略说明。caddy_id 参数可将
// 证书任务/规则访问两项收窄到单规则。
// securityEventsMaxRows 读事件上限(services 常量导出封装,供 LimitRows 与
// 进度条语义使用;2026-09-14 用户裁定 100 万)。
func securityEventsMaxRows() *int64 {
	v := int64(services.SecurityEventsRetentionMax())
	return &v
}

func (h *Handlers) GetLogStats(c *gin.Context) {
	fixedLogsDir, runtimePath := logPaths(h.cfg)
	dataDir := "/app/data"
	if h.cfg != nil && h.cfg.DataDir != "" {
		dataDir = h.cfg.DataDir
	}

	// S-7（2026-09-06 裁定）已被 2026-09-15 裁定部分覆盖:指标历史固定保留
	// 最近 7 天(services/services.go cleanupHistory),不再复用「日志保留」
	// ——ConfigSource 类目清单不得再含指标历史(SYS41-3,第 41 轮)。
	// 第 37 轮(用户裁定文案精简):可见文案短化——类目清单移 ConfigSource
	// (tooltip 展示),行内只留「每日清理 · 保留 N 个月」。
	retentionNote := "每日清理 · 保留 " + strconv.FormatInt(globalConfigInt("audit_retention_months", 3), 10) + " 个月"
	caddyLimit := sizeLimitMB("caddy_log_size_mb", 100)

	infos := []LogStorageInfo{
		{Key: "audit", Name: "操作日志", KeepCount: 0, RetentionNote: retentionNote, ConfigSource: "基础设置 · 日志保留（操作/运行/安全事件）"},
		{Key: "security_events", Name: "安全事件", KeepCount: 0, LimitRows: securityEventsMaxRows(), RetentionNote: retentionNote, ConfigSource: "基础设置 · 日志保留（操作/运行/安全事件）"},
		{Key: "certjob", Name: "证书任务日志", LimitBytes: sizeLimitMB("task_log_size_mb", 10), KeepCount: 5, ConfigSource: "基础设置 · 任务日志大小"},
		{Key: "crs_update", Name: "CRS 更新日志", LimitBytes: sizeLimitMB("task_log_size_mb", 10), KeepCount: 1, ConfigSource: "统一任务日志（tasks/crs.log）"},
		{Key: "ip2region_update", Name: "IP 库更新日志", LimitBytes: sizeLimitMB("task_log_size_mb", 10), KeepCount: 1, ConfigSource: "统一任务日志（tasks/ip2region.log）"},
		{Key: "threat_update", Name: "威胁库更新日志", LimitBytes: sizeLimitMB("task_log_size_mb", 10), KeepCount: 1, ConfigSource: "统一任务日志（tasks/threat.log）"},
		{Key: "crawlerbot_update", Name: "爬虫地址库更新日志", LimitBytes: sizeLimitMB("task_log_size_mb", 10), KeepCount: 1, ConfigSource: "统一任务日志（tasks/crawlerbot-update.log）"},
		{Key: "runtime", Name: "运行日志", LimitBytes: sizeLimitMB("runtime_log_size_mb", 100), KeepCount: 0, RetentionNote: "时间戳轮转，按保留期清理（份数随保留期）", ConfigSource: "基础设置 · 运行日志大小"},
		{Key: "caddy", Name: "Caddy 运行日志", LimitBytes: caddyLimit, KeepCount: 5, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "caddy_runtime", Name: "Caddy 运行时日志", LimitBytes: caddyLimit, KeepCount: 5, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "caddy_tls", Name: "Caddy TLS 日志", LimitBytes: caddyLimit, KeepCount: 5, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "caddy_server", Name: "Caddy HTTP 服务器日志", LimitBytes: caddyLimit, KeepCount: 5, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "caddy_proxy", Name: "Caddy 反向代理日志", LimitBytes: caddyLimit, KeepCount: 5, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "rule_access", Name: "规则访问日志", LimitBytes: caddyLimit, KeepCount: 5, ConfigSource: "Caddy 全局配置 · 日志大小"},
		// F-L3-68-03（第 68 轮审计）：原 coraza_audit 行删除——前端零消费方
		// （LogStorageBar 仅 security_events/rule_access 两键），且与
		// security_events 行同文件同统计，纯重复死面；audit_log_size_mb 配置
		// 链仍由 auditlog_rotation.go 完整消费。
	}
	byKey := func(key string) *LogStorageInfo {
		for i := range infos {
			if infos[i].Key == key {
				return &infos[i]
			}
		}
		return nil
	}

	// DB 体量按库文件大小近似；行数供 UI 显示条目规模
	if db.AuditDB != nil {
		var n int64
		if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&n); err == nil {
			byKey("audit").Rows = &n
		}
	}
	if db.MetricsDB != nil {
		var n int64
		if err := db.MetricsDB.QueryRow("SELECT COUNT(*) FROM security_events").Scan(&n); err == nil {
			byKey("security_events").Rows = &n
		}
	}
	if st, err := os.Stat(filepath.Join(dataDir, "lazy-balancer-audit.db")); err == nil {
		byKey("audit").SizeBytes = st.Size()
	}
	if st, err := os.Stat(filepath.Join(dataDir, "lazy-balancer-metrics.db")); err == nil {
		sz := st.Size()
		byKey("security_events").DBBytes = &sz
	}
	// SizeBytes=真实审计日志文件(2026-09-14 用户裁定:不再用 metrics.db 库文件
	// 虚标,DBBytes 单独展示库容量)。一次 dirBytes 供 security_events 行复用
	// (原先每次响应各调一次,重复全目录 ReadDir)。
	auditActive, auditRotated, auditRotCount := dirBytes(wafAuditLogFile)
	if info := byKey("security_events"); info != nil {
		info.SizeBytes, info.RotatedBytes, info.RotatedCount = auditActive, auditRotated, auditRotCount
	}

	if info := byKey("runtime"); info != nil {
		rtA, rtR, rtC := dirBytes(runtimePath)
		info.SizeBytes, info.RotatedBytes, info.RotatedCount = rtA, rtR, rtC
	}
	// U4-P5-3:每文件恰好一次 dirBytes——四个体行与「caddy」聚合行共用同一批
	// 结果(原先聚合行对同 4 文件再次 dirBytes,单响应 8 次 ReadDir,前端轮询放大)。
	var caddyActive, caddyRotated int64
	var caddyRotCount int
	for _, entry := range []struct{ key, file string }{
		{"caddy_runtime", "caddy.log"},
		{"caddy_tls", "caddy-tls.log"},
		{"caddy_server", "caddy-server.log"},
		{"caddy_proxy", "caddy-proxy.log"},
	} {
		a, r, c := dirBytes(filepath.Join(fixedLogsDir, entry.file))
		if info := byKey(entry.key); info != nil {
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = a, r, c
		}
		caddyActive += a
		caddyRotated += r
		caddyRotCount += c
	}
	if info := byKey("caddy"); info != nil {
		info.SizeBytes, info.RotatedBytes, info.RotatedCount = caddyActive, caddyRotated, caddyRotCount
	}
	// 单一日志数据源（2026-09-29 用户裁定）：三库更新行与任务日志同文件
	// （tasks/{crs|ip2region|threat}.log）——统计与内容同源。
	tasksDir := filepath.Join(filepath.Dir(runtimePath), "tasks")
	taskFileBytes := func(id string) (int64, int64, int) {
		return dirBytes(filepath.Join(tasksDir, id+".log"))
	}
	if info := byKey("crs_update"); info != nil {
		info.SizeBytes, info.RotatedBytes, info.RotatedCount = taskFileBytes("crs")
	}
	if info := byKey("ip2region_update"); info != nil {
		info.SizeBytes, info.RotatedBytes, info.RotatedCount = taskFileBytes("ip2region")
	}
	if info := byKey("threat_update"); info != nil {
		info.SizeBytes, info.RotatedBytes, info.RotatedCount = taskFileBytes("threat")
	}
	if info := byKey("crawlerbot_update"); info != nil {
		info.SizeBytes, info.RotatedBytes, info.RotatedCount = taskFileBytes("crawlerbot-update")
	}
	// 逐任务真实文件统计（任务监控弹框 log-key=task:<id>）：活动大小、
	// 轮转副本与归档份数均按本任务文件计算，不再使用目录聚合值冒充。
	for _, task := range services.CollectSystemTasks() {
		path := taskengine.TaskLogPath(task.ID)
		keep := 1
		if strings.HasPrefix(task.ID, "cert-job:") {
			var ruleID string
			if err := db.DB.QueryRow(`SELECT rule_id FROM cert_jobs WHERE id=?`, strings.TrimPrefix(task.ID, "cert-job:")).Scan(&ruleID); err != nil || ruleID == "" {
				services.Logf("warn", "证书任务 %s 日志路径解析失败: %v", task.ID, err)
				continue
			}
			path = services.CertJobLogPath(ruleID)
			keep = 5
		}
		active, rotated, rotCount := dirBytes(path)
		infos = append(infos, LogStorageInfo{
			Key: "task:" + task.ID, Name: task.Name + "日志",
			SizeBytes: active, RotatedBytes: rotated, RotatedCount: rotCount,
			LimitBytes: sizeLimitMB("task_log_size_mb", 10), KeepCount: keep,
			ConfigSource: "统一任务日志（" + filepath.Base(path) + "）",
		})
	}
	ruleID := strings.TrimSpace(c.Query("caddy_id"))
	if ruleID != "" {
		// caddy_id 仅允许 caddy_id 字母表（[A-Za-z0-9_-]）；读者侧与写入侧
		// sanitizePathComponent/sanitizeRuleLogName 同口径校验，非法值（如路径穿越）
		// 直接 400，绝不参与 filepath.Join 拼接。
		if sanitized := sanitizeRuleID(ruleID); sanitized != ruleID {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的规则 ID"})
			return
		}
	}
	if info := byKey("certjob"); info != nil {
		// L1-66-02 读侧同源：与写入端 CertJobLogPath 同取 {任务日志目录}/certjobs
		// （曾读写死 /app/logs 根——B3 惰性化后写入端已迁，不同源恒 0B）。
		certJobDir := services.CertJobLogDir()
		if ruleID != "" {
			cjA, cjR, cjC := dirBytes(filepath.Join(certJobDir, "certjob-"+ruleID+".log"))
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = cjA, cjR, cjC
			info.Name = "证书任务日志 #" + ruleID
		} else if entries, err := os.ReadDir(certJobDir); err == nil {
			var active, rotated int64
			for _, e := range entries {
				if e.IsDir() || !strings.HasPrefix(e.Name(), "certjob-") || !strings.HasSuffix(e.Name(), ".log") && !strings.HasSuffix(e.Name(), ".log.gz") {
					continue
				}
				if isTimberjackRotationCopy(e.Name()) {
					continue
				}
				a, r, _ := dirBytes(filepath.Join(certJobDir, e.Name()))
				active += a
				rotated += r
			}
			info.SizeBytes, info.RotatedBytes = active, rotated
		}
	}
	if info := byKey("rule_access"); info != nil {
		if ruleID != "" {
			raA, raR, raC := dirBytes(filepath.Join(fixedLogsDir, "rules", ruleID+".log"))
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = raA, raR, raC
			info.Name = "访问日志 #" + ruleID
		} else if entries, err := os.ReadDir(filepath.Join(fixedLogsDir, "rules")); err == nil {
			var active, rotated int64
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") && !strings.HasSuffix(e.Name(), ".log.gz") {
					continue
				}
				if isTimberjackRotationCopy(e.Name()) {
					continue
				}
				a, r, _ := dirBytes(filepath.Join(fixedLogsDir, "rules", e.Name()))
				active += a
				rotated += r
			}
			info.SizeBytes, info.RotatedBytes = active, rotated
		}
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]interface{}{"logs": infos}})
}

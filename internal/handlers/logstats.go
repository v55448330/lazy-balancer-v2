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

// logStatsReadDir 是统计面的目录枚举入口（包级 var 支持测试注入计数——
// U08-F07 断言聚合只做一次 ReadDir）。
var logStatsReadDir = os.ReadDir

// dirStats 单个基名日志文件的体量归并结果。
type dirStats struct {
	Active   int64
	Rotated  int64
	RotCount int
}

// aggregateDirStats 单次目录枚举归并匹配文件的活跃/轮转体量与归档份数
// （U08-F07：替代「逐目录项 dirBytes → 其内部再 ReadDir」的 O(N²) 形态；
// U08-F12：聚合累加 RotatedCount，且 .gz 归档不再冒充活跃）。
// 返回 基名 → 归并结果。分类口径与 dirBytes 一致：
//   - base（匹配、非轮转副本、非 .gz）计入 Active；
//   - .1..9 移位副本、运行日志族 base.YYYYMMDD-HHMMSS、timberjack
//     <stem>-<ts>-size.log[.gz] 副本计入所属 base 的 Rotated/RotCount；
//   - 不归属任何匹配 base 的 .gz 按归档计入 Rotated（压缩归档不是活跃文件）。
func aggregateDirStats(dir string, match func(name string) bool) map[string]dirStats {
	out := map[string]dirStats{}
	entries, err := logStatsReadDir(dir)
	if err != nil {
		return out
	}
	bases := make(map[string]struct{}, len(entries))
	stemToBase := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !match(name) || isRotationCopyShape(name) {
			continue
		}
		bases[name] = struct{}{}
		stemToBase[strings.TrimSuffix(name, filepath.Ext(name))] = name
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		info, infoErr := e.Info()
		if infoErr != nil {
			continue
		}
		if _, isBase := bases[name]; isBase {
			st := out[name]
			st.Active += info.Size()
			out[name] = st
			continue
		}
		if !match(name) {
			continue
		}
		if base, ok := rotationCopyBaseOf(name, bases, stemToBase); ok {
			st := out[base]
			st.Rotated += info.Size()
			st.RotCount++
			out[base] = st
			continue
		}
		if strings.HasSuffix(name, ".gz") {
			st := out[name]
			st.Rotated += info.Size()
			st.RotCount++
			out[name] = st
		}
	}
	return out
}

// isRotationCopyShape 按文件名形态判定轮转副本（与基名集合无关，供基名
// 预筛避免「副本被当成 base」的循环依赖）。
func isRotationCopyShape(name string) bool {
	if isTimberjackRotationCopy(name) || strings.HasSuffix(name, ".gz") {
		return true
	}
	// .1..9 移位副本
	if dot := strings.LastIndexByte(name, '.'); dot > 0 && isDigits(name[dot+1:]) {
		if n, err := strconv.Atoi(name[dot+1:]); err == nil && n >= 1 && n <= 9 {
			return true
		}
	}
	// 运行日志族 base.YYYYMMDD-HHMMSS（rest 恰 16 字符）
	if len(name) > 17 {
		rest := name[len(name)-16:]
		if rest[0] == '.' && isDigits(rest[1:9]) && rest[9] == '-' && isDigits(rest[10:]) {
			return true
		}
	}
	return false
}

// rotationCopyBaseOf 把轮转副本归到所属 base（与 dirBytes/timestampedRotationStats
// 同口径：移位后缀、运行日志时间戳后缀、timberjack 时间戳后缀三族）。
func rotationCopyBaseOf(name string, bases map[string]struct{}, stemToBase map[string]string) (string, bool) {
	if dot := strings.LastIndexByte(name, '.'); dot > 0 && isDigits(name[dot+1:]) {
		if n, err := strconv.Atoi(name[dot+1:]); err == nil && n >= 1 && n <= 9 {
			if base := name[:dot]; base != "" {
				if _, ok := bases[base]; ok {
					return base, true
				}
			}
		}
	}
	if len(name) > 17 {
		rest := name[len(name)-16:]
		if rest[0] == '.' && isDigits(rest[1:9]) && rest[9] == '-' && isDigits(rest[10:]) {
			if base := name[:len(name)-16]; base != "" {
				if _, ok := bases[base]; ok {
					return base, true
				}
			}
		}
	}
	for i := range name {
		if name[i] != '-' {
			continue
		}
		base, ok := stemToBase[name[:i]]
		if !ok {
			continue
		}
		rest := name[i:]
		if !strings.HasSuffix(rest, "-size.log") && !strings.HasSuffix(rest, "-size.log.gz") {
			continue
		}
		// B-2：stem 后紧跟的 '-<ts>' 段须以数字开头（区分 caddy 与 caddy-tls）
		if len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9' {
			return base, true
		}
	}
	return "", false
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

// requestedLogKeys 解析可选 ?key=a,b / ?keys=a,b（缺省 nil=全量）——任务监控
// 弹框只关心单行日志统计（U08-F07）。空串与空白项忽略。
func requestedLogKeys(c *gin.Context) map[string]bool {
	raw := strings.TrimSpace(c.Query("key"))
	if extra := strings.TrimSpace(c.Query("keys")); extra != "" {
		if raw != "" {
			raw += ","
		}
		raw += extra
	}
	if raw == "" {
		return nil
	}
	keys := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		if key := strings.TrimSpace(part); key != "" {
			keys[key] = true
		}
	}
	if len(keys) == 0 {
		return nil
	}
	return keys
}

// caddyLogFamilyBases caddy 四份日志基名（写入端写死 /app/logs）。
var caddyLogFamilyBases = []string{"caddy.log", "caddy-tls.log", "caddy-server.log", "caddy-proxy.log"}

// caddyLogFamilyMatch 匹配 caddy 四份日志及其轮转副本（移位/时间戳/timberjack
// 形态）——聚合一次目录枚举即可归并四文件与总行（U08-F07）。
func caddyLogFamilyMatch(name string) bool {
	for _, base := range caddyLogFamilyBases {
		if name == base || strings.HasPrefix(name, base+".") {
			return true
		}
	}
	if strings.HasSuffix(strings.TrimSuffix(name, ".gz"), "-size.log") {
		for _, base := range caddyLogFamilyBases {
			if strings.HasPrefix(name, strings.TrimSuffix(base, ".log")+"-") {
				return true
			}
		}
	}
	return false
}

func (h *Handlers) GetLogStats(c *gin.Context) {
	fixedLogsDir, runtimePath := logPaths(h.cfg)
	dataDir := "/app/data"
	if h.cfg != nil && h.cfg.DataDir != "" {
		dataDir = h.cfg.DataDir
	}

	// U08-F07：可选 key/keys 收窄——缺省（nil）保持旧全量语义；指定时跳过
	// 未请求行的 DB/文件统计并只回这些行（任务监控弹框轮询不再放大全族统计）。
	requested := requestedLogKeys(c)
	want := func(key string) bool { return requested == nil || requested[key] }

	// S-7（2026-09-06 裁定）已被 2026-09-15 裁定部分覆盖:指标历史固定保留
	// 最近 7 天(services/services.go cleanupHistory),不再复用「日志保留」
	// ——ConfigSource 类目清单不得再含指标历史(SYS41-3,第 41 轮)。
	// 第 37 轮(用户裁定文案精简):可见文案短化——类目清单移 ConfigSource
	// (tooltip 展示),行内只留「每日清理 · 保留 N 个月」。
	retentionNote := "每日清理 · 保留 " + strconv.FormatInt(globalConfigInt("audit_retention_months", 3), 10) + " 个月"
	// U08-F01：安全事件行文案/行帽由 services 单源生成（显式
	// security_events_retention_days/row_cap 生效，不再复用审计月数文案）；
	// 其写入侧与审计日志同文件，大小限值随 audit_log_size_mb。
	securityRetentionNote := services.SecurityEventsRetentionSummary()
	caddyLimit := sizeLimitMB("caddy_log_size_mb", 100)

	infos := []LogStorageInfo{
		{Key: "audit", Name: "操作日志", KeepCount: 0, RetentionNote: retentionNote, ConfigSource: "基础设置 · 日志保留（操作/运行/安全事件）"},
		{Key: "security_events", Name: "安全事件", KeepCount: 0, LimitRows: securityEventsMaxRows(), LimitBytes: sizeLimitMB("audit_log_size_mb", 10), RetentionNote: securityRetentionNote, ConfigSource: "基础设置 · 日志保留（操作/运行/安全事件）"},
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
	if want("audit") {
		if db.AuditDB != nil {
			var n int64
			if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&n); err == nil {
				byKey("audit").Rows = &n
			}
		}
		if st, err := os.Stat(filepath.Join(dataDir, "lazy-balancer-audit.db")); err == nil {
			byKey("audit").SizeBytes = st.Size()
		}
	}
	if want("security_events") {
		if db.MetricsDB != nil {
			var n int64
			if err := db.MetricsDB.QueryRow("SELECT COUNT(*) FROM security_events").Scan(&n); err == nil {
				byKey("security_events").Rows = &n
			}
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
	}

	if want("runtime") {
		if info := byKey("runtime"); info != nil {
			rtA, rtR, rtC := dirBytes(runtimePath)
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = rtA, rtR, rtC
		}
	}
	// U4-P5-3 + U08-F07:四文件与「caddy」聚合行共用一次目录枚举——聚合按
	// 基名归并（原实现每文件各一次 dirBytes、聚合行再扫一遍）。
	if want("caddy") || want("caddy_runtime") || want("caddy_tls") || want("caddy_server") || want("caddy_proxy") {
		caddyStats := aggregateDirStats(fixedLogsDir, caddyLogFamilyMatch)
		var caddyActive, caddyRotated int64
		var caddyRotCount int
		for _, entry := range []struct{ key, file string }{
			{"caddy_runtime", "caddy.log"},
			{"caddy_tls", "caddy-tls.log"},
			{"caddy_server", "caddy-server.log"},
			{"caddy_proxy", "caddy-proxy.log"},
		} {
			st := caddyStats[entry.file]
			if info := byKey(entry.key); info != nil {
				info.SizeBytes, info.RotatedBytes, info.RotatedCount = st.Active, st.Rotated, st.RotCount
			}
			caddyActive += st.Active
			caddyRotated += st.Rotated
			caddyRotCount += st.RotCount
		}
		if info := byKey("caddy"); info != nil {
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = caddyActive, caddyRotated, caddyRotCount
		}
	}
	// 单一日志数据源（2026-09-29 用户裁定）：三库更新行与任务日志同文件
	// （tasks/{crs|ip2region|threat}.log）——统计与内容同源。
	tasksDir := filepath.Join(filepath.Dir(runtimePath), "tasks")
	taskFileBytes := func(id string) (int64, int64, int) {
		return dirBytes(filepath.Join(tasksDir, id+".log"))
	}
	if want("crs_update") {
		if info := byKey("crs_update"); info != nil {
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = taskFileBytes("crs")
		}
	}
	if want("ip2region_update") {
		if info := byKey("ip2region_update"); info != nil {
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = taskFileBytes("ip2region")
		}
	}
	if want("threat_update") {
		if info := byKey("threat_update"); info != nil {
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = taskFileBytes("threat")
		}
	}
	if want("crawlerbot_update") {
		if info := byKey("crawlerbot_update"); info != nil {
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = taskFileBytes("crawlerbot-update")
		}
	}
	// 逐任务真实文件统计（任务监控弹框 log-key=task:<id>）：活动大小、
	// 轮转副本与归档份数均按本任务文件计算，不再使用目录聚合值冒充。
	// U08-F07：cert-job 行的 cert_jobs.rule_id 一次性载入（原逐行
	// systemTaskLogPath 每行一次点查 = N+1）。
	certJobRuleIDs := map[string]string{}
	certJobRuleIDsLoaded := false
	taskLogPath := func(taskID string) (string, error) {
		if !strings.HasPrefix(taskID, "cert-job:") {
			return taskengine.TaskLogPath(taskID), nil
		}
		if !certJobRuleIDsLoaded {
			certJobRuleIDsLoaded = true
			if db.DB != nil {
				rows, err := db.DB.Query(`SELECT id, rule_id FROM cert_jobs`)
				if err != nil {
					return "", err
				}
				for rows.Next() {
					var jobID int
					var ruleID string
					if scanErr := rows.Scan(&jobID, &ruleID); scanErr == nil {
						certJobRuleIDs[strconv.Itoa(jobID)] = ruleID
					}
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return "", err
				}
			}
		}
		ruleID := certJobRuleIDs[strings.TrimPrefix(taskID, "cert-job:")]
		if ruleID == "" {
			return "", nil
		}
		return services.CertJobLogPath(ruleID), nil
	}
	for _, task := range services.CollectSystemTasks() {
		key := "task:" + task.ID
		if !want(key) {
			continue
		}
		path, err := taskLogPath(task.ID)
		if err != nil {
			services.Logf("warn", "任务 %s 日志路径解析失败: %v", task.ID, err)
			continue
		}
		if path == "" {
			continue
		}
		keep := 1
		if strings.HasPrefix(task.ID, "cert-job:") {
			keep = 5
		}
		active, rotated, rotCount := dirBytes(path)
		infos = append(infos, LogStorageInfo{
			Key: key, Name: task.Name + "日志",
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
	if info := byKey("certjob"); info != nil && want("certjob") {
		// L1-66-02 读侧同源：与写入端 CertJobLogPath 同取 {任务日志目录}/certjobs
		// （曾读写死 /app/logs 根——B3 惰性化后写入端已迁，不同源恒 0B）。
		certJobDir := services.CertJobLogDir()
		if ruleID != "" {
			cjA, cjR, cjC := dirBytes(filepath.Join(certJobDir, "certjob-"+ruleID+".log"))
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = cjA, cjR, cjC
			info.Name = "证书任务日志 #" + ruleID
		} else {
			// U08-F07/F12：一次目录枚举归并（原逐文件 dirBytes = O(N²)）；
			// 归档份数与 .gz 归档同时计入（原丢弃 rotCount、.gz 冒充活跃）。
			var active, rotated int64
			var rotCount int
			for _, st := range aggregateDirStats(certJobDir, isCertJobLogName) {
				active += st.Active
				rotated += st.Rotated
				rotCount += st.RotCount
			}
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = active, rotated, rotCount
		}
	}
	if info := byKey("rule_access"); info != nil && want("rule_access") {
		if ruleID != "" {
			raA, raR, raC := dirBytes(filepath.Join(fixedLogsDir, "rules", ruleID+".log"))
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = raA, raR, raC
			info.Name = "访问日志 #" + ruleID
		} else {
			var active, rotated int64
			var rotCount int
			for _, st := range aggregateDirStats(filepath.Join(fixedLogsDir, "rules"), isRuleAccessLogName) {
				active += st.Active
				rotated += st.Rotated
				rotCount += st.RotCount
			}
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = active, rotated, rotCount
		}
	}

	if requested != nil {
		filtered := make([]LogStorageInfo, 0, len(infos))
		for _, info := range infos {
			if requested[info.Key] {
				filtered = append(filtered, info)
			}
		}
		infos = filtered
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]interface{}{"logs": infos}})
}

// isCertJobLogName 证书任务日志文件名（含 .N 移位副本与 .gz 压缩归档）。
func isCertJobLogName(name string) bool {
	if !strings.HasPrefix(name, "certjob-") {
		return false
	}
	return isTaskLogFamilyName(name)
}

// isRuleAccessLogName 规则访问日志文件名（含 .N 移位副本与 .gz 压缩归档）。
func isRuleAccessLogName(name string) bool {
	return isTaskLogFamilyName(name)
}

// isTaskLogFamilyName 任务日志文件名族：base.log[.gz] 与其 .N 移位副本
// （聚合按 base 归并，副本必须参与匹配才能归到所属 base）。
func isTaskLogFamilyName(name string) bool {
	if strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".log.gz") {
		return true
	}
	if dot := strings.LastIndexByte(name, '.'); dot > 0 && isDigits(name[dot+1:]) {
		return strings.HasSuffix(name[:dot], ".log")
	}
	return false
}

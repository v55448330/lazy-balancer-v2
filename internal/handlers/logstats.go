package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// logRotatedBackups 是读侧轮转展示统一保留份数；与 services 写侧常量由
// TestLogRotatedBackups_matchServiceWriters 钉住。
const logRotatedBackups = 5

// LogStorageInfo 描述一类日志的体量与治理状态。
// SizeBytes 为当前活跃文件/库的大小；RotatedBytes 为轮转副本合计（DB 类为 0）。
// 大小型日志（达到 LimitBytes 即轮转）提供 LimitBytes 与 KeepCount；
// 时间型清理（每日按保留期删除）提供 RetentionNote。
type LogStorageInfo struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	SizeBytes    int64  `json:"size_bytes"`
	RotatedBytes int64  `json:"rotated_bytes"`
	RotatedCount int    `json:"rotated_count"` // 当前归档份数(与 keep_count 上限对照)
	LimitBytes   *int64 `json:"limit_bytes,omitempty"`
	LimitRows    *int64 `json:"limit_rows,omitempty"`
	DBBytes      *int64 `json:"db_bytes,omitempty"`
	KeepCount    int    `json:"keep_count"`
	Rows         *int64 `json:"rows,omitempty"`
	// RowsUnavailable 行数读取失败时置位：消费方据此保持「条数口径」并标注
	// 计数暂不可用，而不是静默退回字节口径（行数缺席与「0 行」不可混淆）。
	RowsUnavailable bool   `json:"rows_unavailable,omitempty"`
	RetentionNote   string `json:"retention_note,omitempty"`
	ConfigSource    string `json:"config_source"`
	// Cache* 是安全事件行的「待补采缓存」口径（B 形态：IPC 主路径写入，失败
	// 才落 fallback spool）。四字段可选——只有 security_events 行下发；旧后端
	// 不下发时前端整段不渲染（缺席≠0 条）。
	//   - CacheEntries：spool 中待补采的审计条目数（含未封存的 active 文件）；
	//   - CacheBytes：spool 全部文件字节数；
	//   - CacheLimitEntries / CacheLimitBytes：spool 上限（与写侧同一契约）；
	//   - CacheUnavailable：计数读取失败（不得显示成 0 条——0 条=主路径全通）。
	CacheEntries      *int64 `json:"cache_entries,omitempty"`
	CacheBytes        *int64 `json:"cache_bytes,omitempty"`
	CacheLimitEntries *int64 `json:"cache_limit_entries,omitempty"`
	CacheLimitBytes   *int64 `json:"cache_limit_bytes,omitempty"`
	CacheUnavailable  bool   `json:"cache_unavailable,omitempty"`
}

// rotationCopyKind 轮转副本的形态分类（四族语法单源）。此前 dirBytes 时间戳
// 族、聚合基名预筛、副本归基、虚拟基名各写一份解析——新增一种形态只改了三处
// 就会让同一响应内的口径分叉（双重后缀 .gz 副本漏归即由此产生）。
type rotationCopyKind int

const (
	rotationCopyNone rotationCopyKind = iota
	// rotationCopyShift：<base>.1..9（自研 shift 后缀，可带 .gz）
	rotationCopyShift
	// rotationCopyTimestamp：<base>.YYYYMMDD-HHMMSS（运行日志族 16 字符时间戳，可带 .gz）
	rotationCopyTimestamp
	// rotationCopyTimberjack：<stem>-YYYYMMDD-HHMMSS-size.log[.gz]
	rotationCopyTimberjack
	// rotationCopyWholeGzip：<base>.gz（整文件 gzip 归档）
	rotationCopyWholeGzip
)

type rotationCopyName struct {
	kind rotationCopyKind
	base string // 归并基名（timberjack 族为 <stem>.log）
	stem string // timberjack 族的 stem（去扩展名）；其余形态为空
}

// classifyRotationCopyName 仅按文件名形态解析轮转副本（与目录内容无关）。
// 先剥压缩后缀（.gz/.zst）与同秒碰撞后缀再按族判定：双重后缀副本
// （<base>.<ts>.gz / <stem>-<ts>-size.log.gz）必须归到剥掉时间戳后的基名——
// 否则会派生出一个「副本名本身当基名」的非规范条目，按固定基名取值的消费方
// 取不到。
//
// 压缩后缀剥离与写侧锁键归一（taskengine.taskLogActivePath）共用
// taskengine.StripRotationCompressionSuffix：两侧各持一份曾让 .zst 副本在
// 分类器里归族、在锁键里却不归一（保留期删除因此取到副本名自己的锁）。
func classifyRotationCopyName(name string) rotationCopyName {
	core, gzipped := taskengine.StripRotationCompressionSuffix(name)
	originalCore := core
	collision := false
	if stripped, ok := stripRotationCollisionSuffix(core); ok {
		core, collision = stripped, true
	}
	// 移位后缀：<base>.1..9999（位数 ≤4——纯日期形态 <base>.YYYYMMDD 不得
	// 被当成移位副本；外部 logrotate 的历史代次可到两位数）。
	if dot := strings.LastIndexByte(core, '.'); dot > 0 && dot < len(core)-1 {
		digits := core[dot+1:]
		if len(digits) <= 4 && isDigits(digits) {
			if n, err := strconv.Atoi(digits); err == nil && n >= 1 {
				return rotationCopyName{kind: rotationCopyShift, base: core[:dot]}
			}
		}
	}
	// 运行日志族时间戳：.<8 位日期>-<6 位时刻>（16 字符）。
	if len(core) > 17 {
		rest := core[len(core)-16:]
		if rest[0] == '.' && isDigits(rest[1:9]) && rest[9] == '-' && isDigits(rest[10:]) {
			return rotationCopyName{kind: rotationCopyTimestamp, base: core[:len(core)-16]}
		}
	}
	// timberjack：<stem>-<ts>-<reason>[_<碰撞计数>].log[.gz|.zst]。stem 边界取
	// 「从右往左最后一个合法时间戳段」——规则/任务日志基名允许含 '-<数字>'
	// （存量/导入 ID，如 lb_abc-123），按首个 '-<数字>' 切分会把副本串到同前缀
	// 的兄弟规则。尺寸数字与兄弟文件段（-tls-/-1048576-）不构成时间戳，故不误切。
	// reason 家族与同毫秒碰撞后缀取自 services.CaddyLogRotationReasonPattern
	// （与删除侧白名单同源，两处不得各写一份）。
	if loc := timberjackRotationReasonSuffix.FindStringIndex(core); loc != nil {
		trimmed := core[:loc[0]]
		for i := len(trimmed) - 1; i >= 0; i-- {
			if trimmed[i] != '-' || i+1 >= len(trimmed) {
				continue
			}
			if !isRotationTimestampTail(trimmed[i+1:]) {
				continue
			}
			return rotationCopyName{kind: rotationCopyTimberjack, base: trimmed[:i] + ".log", stem: trimmed[:i]}
		}
	}
	if gzipped {
		// 无可识别轮转族时按整文件归档归并；碰撞后缀未命中任何族时按原始名
		// 归并（避免把 <base>-2.gz 这类合法基名误剥成幻影基名）。
		base := core
		if collision {
			base = originalCore
		}
		return rotationCopyName{kind: rotationCopyWholeGzip, base: base}
	}
	return rotationCopyName{}
}

// timberjackRotationReasonSuffix 匹配 timberjack 副本的 reason 尾部：
// -size.log / -size_1.log（同毫秒碰撞计数写在 reason 段内）/ -time.log /
// -time_2.log / -initial.log（现存文件不可追加打开时的回退改名）。
// reason 家族取自 services.CaddyLogRotationReasonPattern——与删除
// 侧白名单同源，避免两侧各写一份上游命名知识后漂移。
var timberjackRotationReasonSuffix = regexp.MustCompile(
	`-(?:` + services.CaddyLogRotationReasonPattern() + `)(?:_\d+)?\.log$`)

// isRotationTimestampTail 判定轮转副本名里时间戳段的开头形状（其后可带
// 尺寸/碰撞余段）：紧凑 YYYYMMDD[T|-]HHMMSS（timberjack 与运行日志族）
// 或常规的短横线分隔形态。
func isRotationTimestampTail(s string) bool {
	if len(s) >= 15 && isDigits(s[:8]) && (s[8] == 'T' || s[8] == '-') && isDigits(s[9:15]) {
		return true
	}
	if len(s) >= 19 && isDigits(s[:4]) && s[4] == '-' && isDigits(s[5:7]) && s[7] == '-' &&
		isDigits(s[8:10]) && s[10] == 'T' && isDigits(s[11:13]) && s[13] == '-' && isDigits(s[14:16]) {
		return true
	}
	return false
}

// stripRotationCollisionSuffix 剥掉同秒重复轮转的碰撞后缀 -N（N≥2，至多
// 两位）：写侧在同秒重名时产出 <副本名>-2/-3…。位数上限避免误剥时间戳
// 时刻段（-150405）。
func stripRotationCollisionSuffix(s string) (string, bool) {
	dash := strings.LastIndexByte(s, '-')
	if dash <= 0 || len(s)-dash-1 == 0 || len(s)-dash-1 > 2 {
		return "", false
	}
	digits := s[dash+1:]
	if !isDigits(digits) {
		return "", false
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 2 {
		return "", false
	}
	return s[:dash], true
}

// dirBytesWithEntries 返回 path 的活跃文件大小与轮转副本合计，与聚合行共用
// 「目录枚举 + 分类器归属」口径（移位 .N[.gz/.zst]、运行日志时间戳、timberjack、
// 同秒碰撞后缀、整文件压缩归档全族）。entries 非 nil 时复用同目录的一次
// ReadDir 结果（GetLogStats 批量任务行不再逐任务枚举整个目录）。
func dirBytesWithEntries(path string, entries []os.DirEntry) (int64, int64, int) {
	base := filepath.Base(path)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	belongs := func(name string) bool {
		if name == base {
			return true
		}
		shape := classifyRotationCopyName(name)
		if shape.kind == rotationCopyNone {
			return false
		}
		if shape.base == base {
			return true
		}
		return shape.kind == rotationCopyTimberjack && shape.stem != "" && shape.stem == stem
	}
	st := aggregateDirStatsWithEntries(filepath.Dir(path), entries, belongs)[base]
	return st.Active, st.Rotated, st.RotCount
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
// 断言聚合只做一次 ReadDir；也用于注入读失败以覆盖体量留痕）。
var logStatsReadDir = os.ReadDir

// logStatsVolumeState 日志体量读取失败的状态转换去重：首报 warn、恢复补
// info、同状态静默（面板轮询不刷屏）。ENOENT（日志尚未产生）不记——正常形态。
var logStatsVolumeState struct {
	sync.Mutex
	failed map[string]bool
}

// logStatsVolumeStateCap 状态键上限（按目录/文件路径去重，防御动态路径）。
const logStatsVolumeStateCap = 256

func logStatsVolumeReadFailure(key string, err error) {
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return
	}
	logStatsVolumeState.Lock()
	if logStatsVolumeState.failed == nil {
		logStatsVolumeState.failed = map[string]bool{}
	}
	if logStatsVolumeState.failed[key] {
		logStatsVolumeState.Unlock()
		return
	}
	if len(logStatsVolumeState.failed) >= logStatsVolumeStateCap {
		// 触顶逐出单个键而非整表清空：清空会让仍在失败的 256 个路径全部回到
		// 「首报」状态（一次性 256 条 warn），并丢掉已失败键的配对信息（日
		// 后恢复不再补「已恢复」info）。
		for victim := range logStatsVolumeState.failed {
			delete(logStatsVolumeState.failed, victim)
			break
		}
	}
	logStatsVolumeState.failed[key] = true
	logStatsVolumeState.Unlock()
	services.Logf("warn", "日志体量读取失败（%s）: %v", key, err)
}

func logStatsVolumeReadRecovered(key string) {
	logStatsVolumeState.Lock()
	if !logStatsVolumeState.failed[key] {
		logStatsVolumeState.Unlock()
		return
	}
	delete(logStatsVolumeState.failed, key)
	logStatsVolumeState.Unlock()
	services.Logf("info", "日志体量读取已恢复（%s）", key)
}

// resetLogStatsVolumeStateForTest 仅供测试隔离（跨用例的注入失败状态不得
// 让后续断言的「首报」被去重成 0 条）。
func resetLogStatsVolumeStateForTest() {
	logStatsVolumeState.Lock()
	logStatsVolumeState.failed = nil
	logStatsVolumeState.Unlock()
}

// dirStats 单个基名日志文件的体量归并结果。
type dirStats struct {
	Active   int64
	Rotated  int64
	RotCount int
}

// logStatsFileSize 读取日志/库文件体量并接入统一留痕契约：失败（非不存在）
// 按路径首报 warn、恢复 info——「没有日志」与「读不到日志」不得混为一谈
// （同函数内目录枚举已用同一契约）。
func logStatsFileSize(path string) (int64, bool) {
	st, err := os.Stat(path)
	if err != nil {
		logStatsVolumeReadFailure("logstats-stat-"+path, err)
		return 0, false
	}
	logStatsVolumeReadRecovered("logstats-stat-" + path)
	return st.Size(), true
}

// aggregateDirStatsWithEntries 单次目录枚举归并匹配文件的活跃/轮转体量与归档份数
// （替代「逐目录项重复 ReadDir」的 O(N²) 形态；聚合累加 RotatedCount，且压缩
// 归档不再冒充活跃）。返回 基名 → 归并结果，与单文件口径共用唯一实现：
//   - base（匹配、非轮转副本、非压缩归档）计入 Active；
//     .1..9 移位副本、运行日志族 base.、timberjack
//     <stem>-<ts>-size.log[.gz/.zst] 副本计入所属 base 的 Rotated/RotCount；
//   - 不归属任何匹配 base 的压缩归档（.gz/.zst）按归档计入 Rotated
//     （压缩归档不是活跃文件）。
//
// entries 非 nil 时复用调用方已枚举的目录结果。
func aggregateDirStatsWithEntries(dir string, entries []os.DirEntry, match func(name string) bool) map[string]dirStats {
	out := map[string]dirStats{}
	if entries == nil {
		var err error
		entries, err = logStatsReadDir(dir)
		if err != nil {
			logStatsVolumeReadFailure("logstats-dir-"+dir, err)
			return out
		}
		// 恢复留痕只属于「本函数真的重新读成功」：调用方传入缓存条目时（含
		// 失败窗口的空非 nil 哨兵）不得在这里报恢复，否则失败态会被同一次
		// 请求立刻抹掉，形成 warn/info 逐轮抖动。
		logStatsVolumeReadRecovered("logstats-dir-" + dir)
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
		if !match(name) {
			continue
		}
		base := name
		_, active := bases[name]
		if !active {
			var ok bool
			if base, ok = rotationCopyBaseOf(name, bases, stemToBase); !ok {
				// 虚拟 base：活跃文件缺席时按副本形态派生基名，保持单文件与聚合口径一致。
				if base, ok = rotationCopyBaseName(name); !ok || !match(base) {
					if _, compressed := taskengine.StripRotationCompressionSuffix(name); !compressed {
						continue
					}
					base = name
				}
			}
		}
		// 只对已确认归属的条目付 Info/lstat 成本；无关文件不做系统调用。
		info, infoErr := e.Info()
		if infoErr != nil {
			logStatsVolumeReadFailure("logstats-file-"+filepath.Join(dir, name), infoErr)
			continue
		}
		st := out[base]
		if active {
			st.Active += info.Size()
		} else {
			st.Rotated += info.Size()
			st.RotCount++
		}
		out[base] = st
	}
	return out
}

// isRotationCopyShape 按文件名形态判定轮转副本（与基名集合无关，供基名
// 预筛避免「副本被当成 base」的循环依赖）。
func isRotationCopyShape(name string) bool {
	return classifyRotationCopyName(name).kind != rotationCopyNone
}

// rotationCopyBaseOf 把轮转副本归到所属 base（四族语法取自
// classifyRotationCopyName 单源；成员判定以目录实际基名集合为准）。
func rotationCopyBaseOf(name string, bases map[string]struct{}, stemToBase map[string]string) (string, bool) {
	// 整文件压缩归档 <base>.gz/<base>.zst 优先按字面基名归并（<base>.gz 与
	// <base>.1.gz 同时存在时前者语义是 base 的整文件归档）。压缩后缀剥离走
	// taskengine.StripRotationCompressionSuffix 单源；此前只认 .gz，.zst 归档
	// 落入通用独立键（消费侧按固定基名取值 → 该文件字节从聚合行消失）。
	if base, compressed := taskengine.StripRotationCompressionSuffix(name); compressed {
		if _, ok := bases[base]; ok {
			return base, true
		}
	}
	shape := classifyRotationCopyName(name)
	switch shape.kind {
	case rotationCopyShift, rotationCopyTimestamp, rotationCopyWholeGzip:
		if shape.base != "" {
			if _, ok := bases[shape.base]; ok {
				return shape.base, true
			}
		}
	case rotationCopyTimberjack:
		// 按 stem 反查真实基名（基名未必是 <stem>.log，如仅按 stem 注册）。
		if base, ok := stemToBase[shape.stem]; ok {
			return base, true
		}
		// 整文件 .gz 前缀已处理；无匹配基名时允许按派生基名归并。
		if shape.base != "" {
			if _, ok := bases[shape.base]; ok {
				return shape.base, true
			}
		}
	}
	return "", false
}

// rotationCopyBaseName 仅按副本文件名形态派生所属基名（不依赖目录内是否
// 存在 base）——四族语法取自 classifyRotationCopyName 单源。
func rotationCopyBaseName(name string) (string, bool) {
	shape := classifyRotationCopyName(name)
	if shape.kind == rotationCopyNone || shape.base == "" {
		return "", false
	}
	return shape.base, true
}

func globalConfigInt(column string, fallback int64) int64 {
	// nil 守卫:guardConfiguredJSONBody 经本函数
	// 读配置,无 DB 脚手架的测试/调用形态下 db.DB 为 nil,QueryRow 直接 panic
	// ——nil 与读失败同口径回退默认值。
	database := db.DB
	if database == nil {
		return fallback
	}
	var v int64
	// 读失败回退默认必须留痕（此前静默——库故障窗口阈值展示/滚动
	// 口径失真零信号）；接 services 单源状态转换留痕（首报 warn+恢复 info，
	// 面板轮询不刷屏）。nil 与读失败同口径回退默认值。
	if err := database.QueryRow("SELECT COALESCE("+column+",?) FROM global_config WHERE id=1", fallback).Scan(&v); err != nil {
		services.LogConfigReadFailure("config-read-"+column, err)
		return fallback
	}
	services.LogConfigReadRecovered("config-read-" + column)
	return v
}

func sizeLimitMB(column string, def int64) *int64 {
	limit := globalConfigInt(column, def) * 1024 * 1024
	return &limit
}

// logStatsRowCountCacheTTL 是日志统计行数（全表 COUNT(*)）的进程内缓存窗口：
// audit_log / security_events 均为百万行级，面板全量轮询每次各付一次全表
// 计数；行数是展示性指标，5s 陈旧对用户不可感知。读失败不缓存（下一请求
// 重试），失败/恢复留痕走 services 状态转换单源（首报 warn、恢复 info）。
const logStatsRowCountCacheTTL = 5 * time.Second

type logStatsRowCountEntry struct {
	rows int64
	at   time.Time
}

var logStatsRowCounts struct {
	sync.Mutex
	entries map[string]logStatsRowCountEntry
}

// resetLogStatsRowCountCacheForTest 仅供测试隔离（跨用例的 DB 交换后不得
// 读到上一夹具的行数）。
func resetLogStatsRowCountCacheForTest() {
	logStatsRowCounts.Lock()
	logStatsRowCounts.entries = nil
	logStatsRowCounts.Unlock()
}

// cachedLogTableCount 返回表行数（TTL 缓存 + 读失败留痕）。ok=false 表示
// 本次读取失败（响应不携带该行数，与缓存前语义一致）。
func cachedLogTableCount(database *sql.DB, key, query string) (int64, bool) {
	logStatsRowCounts.Lock()
	if entry, ok := logStatsRowCounts.entries[key]; ok && time.Since(entry.at) < logStatsRowCountCacheTTL {
		logStatsRowCounts.Unlock()
		return entry.rows, true
	}
	logStatsRowCounts.Unlock()
	var n int64
	if err := database.QueryRow(query).Scan(&n); err != nil {
		// 此前两处 COUNT 失败被 `err == nil` 静默吞掉——行数缺失与「表为空」
		// 在前端不可区分，排障零信号。
		services.LogConfigReadFailure(key, err)
		return 0, false
	}
	services.LogConfigReadRecovered(key)
	logStatsRowCounts.Lock()
	if logStatsRowCounts.entries == nil {
		logStatsRowCounts.entries = map[string]logStatsRowCountEntry{}
	}
	logStatsRowCounts.entries[key] = logStatsRowCountEntry{rows: n, at: time.Now()}
	logStatsRowCounts.Unlock()
	return n, true
}

// logPaths resolves the two distinct log roots GetLogStats probes:
//   - fixedDir is the hardcoded writer directory (/app/logs) shared by the
//     hardcoded-writer log families — caddy 四份日志（caddy.log/caddy-tls.log/
//     caddy-server.log/caddy-proxy.log）、rules/*.log。这些写入端写死 /app/logs，
//     与 LOG_FILE 无关，故其路径拼接必须固定用 /app/logs；若跟随 LogFile 目录
//     推导，自定义 LOG_FILE 时这些日志会全部显示 0B。
//     certjob-*.log 不在此列：写入端已并入统一任务日志
//     体系（{任务日志目录}/certjobs/，services.CertJobLogDir 同源）。
//   - runtimePath is the runtime log path, which follows LogFile
//     （空 → /app/logs/lazy-balancer.log）。
//
// wafAuditLogFile 是 Coraza 审计日志文件路径覆盖值。空值=运行期按
// services.AuditLogPath() 解析——审计路径随 ConfigureWafDirs 按 data_dir 派生
// 而本包 init 早于 main 的派生调用，包级固化会指向陈旧的 /app
// 路径（自定义 data_dir 下统计恒 0B）。测试可注入具体路径。
var wafAuditLogFile = ""

// resolvedWafAuditLogFile 返回审计日志路径：测试注入值优先，否则运行期解析
// services.AuditLogPath()（路径随 ConfigureWafDirs 派生，包级固化
// 会在自定义 data_dir 下陈旧）。
func resolvedWafAuditLogFile() string {
	if wafAuditLogFile != "" {
		return wafAuditLogFile
	}
	return services.AuditLogPath()
}

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
// requestedLogKeys 解析可选 ?key=a,b / ?keys=a,b（缺省 nil=全量）——任务监控
// 弹框只关心单行日志统计。空串与空白项忽略。
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
// 形态）——聚合一次目录枚举即可归并四文件与总行。基名/移位/整文件归档走直接
// 前缀判定，其余副本交给 classifyRotationCopyName 单源：压缩后缀（.gz/.zst）、
// reason 家族与同毫秒碰撞后缀都不在此另写一份——各持一份曾让 family matcher
// 只认 .gz 与无碰撞形态，同一响应内聚合行与 dirBytes 分叉（.zst 归档整份
// 消失、-size_1 副本漏计）。
func caddyLogFamilyMatch(name string) bool {
	for _, base := range caddyLogFamilyBases {
		if name == base || strings.HasPrefix(name, base+".") {
			return true
		}
	}
	shape := classifyRotationCopyName(name)
	if shape.kind == rotationCopyNone || shape.base == "" {
		return false
	}
	for _, base := range caddyLogFamilyBases {
		if shape.base == base {
			return true
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

	// 可选 key/keys 收窄——缺省（nil）保持旧全量语义；指定时跳过
	// 未请求行的 DB/文件统计并只回这些行（任务监控弹框轮询不再放大全族统计）。
	requested := requestedLogKeys(c)
	want := func(key string) bool { return requested == nil || requested[key] }
	wantAny := func(keys ...string) bool {
		for _, key := range keys {
			if want(key) {
				return true
			}
		}
		return false
	}

	// 请求级目录枚举缓存：运行日志行与 caddy 聚合行的目录默认同为 /app/logs，
	// 此前各枚举一次（重复 ReadDir + 每文件重复 stat），且两次枚举之间若发生
	// 轮转，同一响应的两行会来自不同目录快照。成功与失败都缓存，失败返回
	// 空非 nil 切片（「nil=未提供」哨兵会让调用方重读，故障窗口退化为每个
	// 消费点一次 syscall）。
	type dirEntriesResult struct {
		entries []os.DirEntry
		ok      bool
	}
	dirEntries := map[string]dirEntriesResult{}
	readDir := func(dir string) []os.DirEntry {
		if cached, seen := dirEntries[dir]; seen {
			if !cached.ok {
				return []os.DirEntry{}
			}
			return cached.entries
		}
		entries, err := logStatsReadDir(dir)
		if err != nil {
			logStatsVolumeReadFailure("logstats-dir-"+dir, err)
			dirEntries[dir] = dirEntriesResult{ok: false}
			return []os.DirEntry{}
		}
		logStatsVolumeReadRecovered("logstats-dir-" + dir)
		dirEntries[dir] = dirEntriesResult{entries: entries, ok: true}
		return entries
	}
	// logFileDirStats 以「文件路径」为入口返回活跃/轮转体量（与 dirBytes 同
	// 口径），枚举复用本请求的目录缓存。
	logFileDirStats := func(path string) (int64, int64, int) {
		return dirBytesWithEntries(path, readDir(filepath.Dir(path)))
	}

	// （2026-09-06 裁定）已被 2026-09-15 裁定部分覆盖:指标历史固定保留
	// 最近 7 天(services/services.go cleanupHistory),不再复用「日志保留」
	// ConfigSource 类目清单不得再含指标历史。
	// 历史(用户裁定文案精简):可见文案短化——类目清单移 ConfigSource
	// (tooltip 展示),行内只留「每日清理 · 保留 N 个月」。
	//
	// 保留口径/事件上限同样按 want 门控——此前三处无条件
	// 求值（audit_retention_months 点查 + 安全事件策略两次点查），单行轮询也付
	// 3 次多余 SQLite 往返，与下方声明的门控不成立；安全事件两项
	// （摘要+行帽）收敛为一次策略读取（services.SecurityEventsRetentionSnapshot）。
	// 阈值按 want 门控——日志弹框只请求单行时不得读其它配置列。
	// 每列只读一次（此前任务循环逐任务重复读 task_log_size_mb）。
	var (
		auditLogLimit   *int64
		runtimeLogLimit *int64
		caddyLimit      *int64
		taskLogLimit    *int64
	)
	if want("security_events") {
		auditLogLimit = sizeLimitMB("audit_log_size_mb", db.DefaultAuditLogSizeMB)
	}
	if want("runtime") {
		runtimeLogLimit = sizeLimitMB("runtime_log_size_mb", db.DefaultRuntimeLogSizeMB)
	}
	if wantAny("caddy", "caddy_runtime", "caddy_tls", "caddy_server", "caddy_proxy", "rule_access") {
		caddyLimit = sizeLimitMB("caddy_log_size_mb", db.DefaultCaddyLogSizeMB)
	}
	wantsTaskRows := wantAny("certjob", "crs_update", "ip2region_update", "threat_update", "crawlerbot_update")
	if !wantsTaskRows && requested != nil {
		for key := range requested {
			if strings.HasPrefix(key, "task:") {
				wantsTaskRows = true
				break
			}
		}
	}
	if wantsTaskRows {
		taskLogLimit = sizeLimitMB("task_log_size_mb", db.DefaultTaskLogSizeMB)
	}

	infos := []LogStorageInfo{
		{Key: "audit", Name: "操作日志", KeepCount: 0, ConfigSource: "基础设置 · 日志保留（操作/运行/安全事件）"},
		{Key: "security_events", Name: "安全事件", KeepCount: 0, LimitBytes: auditLogLimit, ConfigSource: "基础设置 · 日志保留（操作/运行/安全事件）"},
		{Key: "certjob", Name: "证书任务日志", LimitBytes: taskLogLimit, KeepCount: logRotatedBackups, ConfigSource: "基础设置 · 任务日志大小"},
		{Key: "crs_update", Name: "CRS 更新日志", LimitBytes: taskLogLimit, KeepCount: 1, ConfigSource: "统一任务日志（tasks/crs.log）"},
		{Key: "ip2region_update", Name: "IP 库更新日志", LimitBytes: taskLogLimit, KeepCount: 1, ConfigSource: "统一任务日志（tasks/ip2region.log）"},
		{Key: "threat_update", Name: "威胁库更新日志", LimitBytes: taskLogLimit, KeepCount: 1, ConfigSource: "统一任务日志（tasks/threat.log）"},
		{Key: "crawlerbot_update", Name: "爬虫地址库更新日志", LimitBytes: taskLogLimit, KeepCount: 1, ConfigSource: "统一任务日志（tasks/crawlerbot-update.log）"},
		{Key: "runtime", Name: "运行日志", LimitBytes: runtimeLogLimit, KeepCount: 0, RetentionNote: "时间戳轮转，按保留期清理（份数随保留期）", ConfigSource: "基础设置 · 运行日志大小"},
		{Key: "caddy", Name: "Caddy 运行日志", LimitBytes: caddyLimit, KeepCount: logRotatedBackups, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "caddy_runtime", Name: "Caddy 运行时日志", LimitBytes: caddyLimit, KeepCount: logRotatedBackups, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "caddy_tls", Name: "Caddy TLS 日志", LimitBytes: caddyLimit, KeepCount: logRotatedBackups, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "caddy_server", Name: "Caddy HTTP 服务器日志", LimitBytes: caddyLimit, KeepCount: logRotatedBackups, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "caddy_proxy", Name: "Caddy 反向代理日志", LimitBytes: caddyLimit, KeepCount: logRotatedBackups, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "rule_access", Name: "规则访问日志", LimitBytes: caddyLimit, KeepCount: logRotatedBackups, ConfigSource: "Caddy 全局配置 · 日志大小"},
		// 原 coraza_audit 行删除——前端零消费方
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
	// 保留口径与事件上限只在所请求行内读取（各一次点查）。
	if info := byKey("audit"); info != nil && want("audit") {
		info.RetentionNote = "每日清理 · 保留 " + strconv.FormatInt(globalConfigInt("audit_retention_months", db.DefaultAuditRetentionMonths), 10) + " 个月"
	}
	if info := byKey("security_events"); info != nil && want("security_events") {
		// 安全事件行文案/行帽由 services 单源生成（显式
		// security_events_retention_days/row_cap 生效，不再复用审计月数文案）；
		// 其写入侧与审计日志同文件，大小限值随 audit_log_size_mb。
		note, rowCap := services.SecurityEventsRetentionSnapshot()
		info.RetentionNote = note
		limitRows := int64(rowCap)
		info.LimitRows = &limitRows
	}

	// DB 体量按库文件大小近似；行数供 UI 显示条目规模
	if want("audit") {
		if auditDB := db.AuditDB; auditDB != nil {
			if n, ok := cachedLogTableCount(auditDB, "logstats-audit-count", "SELECT COUNT(*) FROM audit_log"); ok {
				byKey("audit").Rows = &n
			} else if info := byKey("audit"); info != nil {
				// 与 security_events 行同口径：计数失败显式披露，避免消费方把
				// 「计数暂不可用」与「0 行」混为一谈（字段语义即如此）。
				info.RowsUnavailable = true
			}
		}
		if size, ok := logStatsFileSize(filepath.Join(dataDir, db.AuditDBFilename)); ok {
			byKey("audit").SizeBytes = size
		}
	}
	if want("security_events") {
		if metricsDB := db.MetricsDB; metricsDB != nil {
			if n, ok := cachedLogTableCount(metricsDB, "logstats-security-events-count", "SELECT COUNT(*) FROM security_events"); ok {
				byKey("security_events").Rows = &n
			} else if info := byKey("security_events"); info != nil {
				// 计数失败显式披露：此前响应只是缺席 rows，前端遂静默从
				// 「N / 上限 条」退回「字节 / 上限」，用户以为口径被改。
				info.RowsUnavailable = true
			}
		}
		if size, ok := logStatsFileSize(filepath.Join(dataDir, db.MetricsDBFilename)); ok {
			sz := size
			byKey("security_events").DBBytes = &sz
		}
		// SizeBytes=真实审计日志文件（2026-09-14 用户裁定）。B 形态起该文件只
		// 承载旧版本遗留与写侧兜底，**不再是**安全事件的主容量口径：主容量=
		// 库内行数/行帽（limit_rows+rows）+ 库容量（db_bytes），cache_* 另给出
		// IPC 失败后的待补采 spool（正常为 0）。保留 size_bytes 旧字段仅为
		// 向后兼容（旧前端/外部消费方仍在读）。
		auditActive, auditRotated, auditRotCount := logFileDirStats(resolvedWafAuditLogFile())
		if info := byKey("security_events"); info != nil {
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = auditActive, auditRotated, auditRotCount
		}
		// 待补采 spool（cache_*）：services 侧带 TTL 缓存与补采状态叠加的单源
		// 快照。Unavailable 时必须置 cache_unavailable——把「读不到」显示成
		// 「0 条」是这个指标最危险的误读（0 条=主路径全通）。
		spool := services.SecurityEventsSpoolSnapshot()
		if info := byKey("security_events"); info != nil {
			if spool.Unavailable {
				info.CacheUnavailable = true
			} else {
				entries, bytes, limitEntries, limitBytes := spool.Entries, spool.Bytes, spool.LimitEntries, spool.LimitBytes
				info.CacheEntries, info.CacheBytes = &entries, &bytes
				info.CacheLimitEntries, info.CacheLimitBytes = &limitEntries, &limitBytes
			}
		}
	}

	if want("runtime") {
		if info := byKey("runtime"); info != nil {
			rtA, rtR, rtC := logFileDirStats(runtimePath)
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = rtA, rtR, rtC
		}
	}
	// +:四文件与「caddy」聚合行共用一次目录枚举——聚合按
	// 基名归并（原实现每文件各一次 dirBytes、聚合行再扫一遍）。
	if want("caddy") || want("caddy_runtime") || want("caddy_tls") || want("caddy_server") || want("caddy_proxy") {
		caddyStats := aggregateDirStatsWithEntries(fixedLogsDir, readDir(fixedLogsDir), caddyLogFamilyMatch)
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
	// 目录取引擎实际装配的任务日志目录（taskengine.LogDir）——统计侧自行按
	// 运行日志目录推导会在「日志写入器打开失败」（runtimeLogFile 空 → 引擎回落
	// /app/logs）时读错目录恒 0B，而同响应内的逐任务行
	// （systemTaskLogPath→TaskLogPath）正确。引擎未装配（单测/嵌入式）时按同一
	// 回落规则派生。
	tasksDir := taskengine.LogDir()
	if tasksDir == "" {
		tasksDir = filepath.Join(filepath.Dir(runtimePath), "tasks")
	}
	// 同一 tasks 目录在一次全量请求里被四类已知行 + 逐任务行共享（request
	// 级 readDir 缓存），失败窗口不退化。
	taskFileBytes := func(id string) (int64, int64, int) {
		return dirBytesWithEntries(filepath.Join(tasksDir, id+".log"), readDir(tasksDir))
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
	// 轮转副本与归档份数均按本任务文件计算。批量路径解析复用同一个
	// systemTaskLogPathResolver，cert_jobs 只首批载入一次，避免 N+1。
	// 门控：只有请求里含 task:<id> 行（或无 keys 的全量请求）才枚举任务族——
	// 单行轮询（日志弹框只看某一行）此前仍全量 CollectSystemTasks（引擎
	// DescribeAll + cert_jobs 查询 + task_runs 统计），纯白付。
	wantsPerTaskRows := requested == nil
	if !wantsPerTaskRows {
		for key := range requested {
			if strings.HasPrefix(key, "task:") {
				wantsPerTaskRows = true
				break
			}
		}
	}
	var taskLogPath systemTaskLogPathResolver
	if wantsPerTaskRows {
		var taskRows []services.TaskInfo
		// 清单截断位由 /system/tasks 端点负责披露（任务监控页消费）；本端点
		// 不重复携带无人消费的同名字段（契约噪声与「采集白付」同源）。
		taskRows, _ = services.CollectSystemTasks()
		for _, task := range taskRows {
			key := "task:" + task.ID
			if !want(key) {
				continue
			}
			path, err := taskLogPath.resolve(task.ID)
			if err != nil {
				services.Logf("warn", "任务 %s 日志路径解析失败: %v", task.ID, err)
				continue
			}
			if path == "" {
				continue
			}
			keep := 1
			if strings.HasPrefix(task.ID, "cert-job:") {
				keep = logRotatedBackups
			}
			active, rotated, rotCount := dirBytesWithEntries(path, readDir(filepath.Dir(path)))
			infos = append(infos, LogStorageInfo{
				Key: key, Name: task.Name + "日志",
				SizeBytes: active, RotatedBytes: rotated, RotatedCount: rotCount,
				LimitBytes: taskLogLimit, KeepCount: keep,
				ConfigSource: "统一任务日志（" + filepath.Base(path) + "）",
			})
		}
	}
	ruleID := strings.TrimSpace(c.Query("caddy_id"))
	if ruleID != "" && (strings.ContainsAny(ruleID, "/\\") || ruleID == "." || ruleID == "..") {
		// 读侧不再要求「净化结果==原值」——写入端规则日志
		// 文件名改为可逆编码（合法字母表原样、其余字符 %hex），含点等 v2 导入
		// ID 的日志因此可读。这里只保留路径穿越形状的拒绝；文件名一律经
		// services.RuleLogFileComponent 生成，输出恒为安全字符集。
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的规则 ID"})
		return
	}
	if info := byKey("certjob"); info != nil && want("certjob") {
		// 读侧同源：与写入端 CertJobLogPath 同取 {任务日志目录}/certjobs
		// （曾读写死 /app/logs 根——惰性化后写入端已迁，不同源恒 0B）。
		certJobDir := services.CertJobLogDir()
		if ruleID != "" {
			cjA, cjR, cjC := logFileDirStats(services.CertJobLogPath(ruleID))
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = cjA, cjR, cjC
			info.Name = "证书任务日志 #" + ruleID
		} else {
			// 一次目录枚举归并（原逐文件 dirBytes = O(N²)）；
			// 归档份数与 .gz 归档同时计入（原丢弃 rotCount、.gz 冒充活跃）。
			var active, rotated int64
			var rotCount int
			for _, st := range aggregateDirStatsWithEntries(certJobDir, readDir(certJobDir), isCertJobLogName) {
				active += st.Active
				rotated += st.Rotated
				rotCount += st.RotCount
			}
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = active, rotated, rotCount
		}
	}
	if info := byKey("rule_access"); info != nil && want("rule_access") {
		if ruleID != "" {
			raA, raR, raC := logFileDirStats(filepath.Join(fixedLogsDir, "rules", services.RuleLogFileComponent(ruleID)+".log"))
			info.SizeBytes, info.RotatedBytes, info.RotatedCount = raA, raR, raC
			info.Name = "访问日志 #" + ruleID
		} else {
			var active, rotated int64
			var rotCount int
			for _, st := range aggregateDirStatsWithEntries(filepath.Join(fixedLogsDir, "rules"), readDir(filepath.Join(fixedLogsDir, "rules")), isRuleAccessLogName) {
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

// isCertJobLogName 证书任务日志文件名（含 .N 移位副本与 .gz/.zst 压缩归档）。
func isCertJobLogName(name string) bool {
	if !strings.HasPrefix(name, "certjob-") {
		return false
	}
	return isTaskLogFamilyName(name)
}

// isRuleAccessLogName 规则访问日志文件名（含 .N 移位副本与 .gz/.zst 压缩归档）。
func isRuleAccessLogName(name string) bool {
	return isTaskLogFamilyName(name)
}

// isTaskLogFamilyName 任务日志文件名族：活跃文件 base.log[.gz/.zst] 与全部轮转
// 副本形态（移位 .N[.gz/.zst]、时间戳、同秒碰撞后缀、timberjack）——压缩后缀
// 剥离与副本形态判定走单源（.N.gz 曾在此漏判而聚合少计）。
func isTaskLogFamilyName(name string) bool {
	if core, _ := taskengine.StripRotationCompressionSuffix(name); strings.HasSuffix(core, ".log") {
		return true
	}
	return isRotationCopyShape(name)
}

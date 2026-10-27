package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// ConfigFieldSections 配置字段 → 面板卡片段落映射（字段级审计归因用）。
// 新增 add() 字段（handlers/config_changes.go planConfigChanges）必须同步本表，
// 否则审计归因落「全局配置」；覆盖清点钉在 handlers/config_field_sections_test.go
// （同族漏点收敛，曾漏 github_token）。
var ConfigFieldSections = map[string]string{
	"acme_email":             "ACME配置",
	"cert_expiry_days":       "ACME配置",
	"cert_renewal_days":      "ACME配置",
	"cert_renewal_attempts":  "ACME配置",
	"default_ca_provider_id": "ACME配置",
	"dns_provider":           "ACME配置",

	"caddy_log_level":               "Caddy配置",
	"caddy_log_size_mb":             "Caddy配置",
	"request_body_max_size_mb":      "Caddy配置",
	"http_read_timeout":             "Caddy配置",
	"http_write_timeout":            "Caddy配置",
	"http_idle_timeout":             "Caddy配置",
	"upstream_keepalive_timeout":    "Caddy配置",
	"proxy_dial_timeout":            "Caddy配置",
	"proxy_response_header_timeout": "Caddy配置",
	"proxy_read_timeout":            "Caddy配置",
	"proxy_write_timeout":           "Caddy配置",
	"proxy_stream_timeout":          "Caddy配置",
	"proxy_flush_interval":          "Caddy配置",
	"proxy_stream_close_delay":      "Caddy配置",
	"server_tokens_hidden":          "Caddy配置",
	// v2.3.x 受信代理（CDN 真实 IP）：与 CDN/网络面同在 Caddy 配置卡片。
	"trusted_proxy_enabled":    "Caddy配置",
	"trusted_proxy_ranges":     "Caddy配置",
	"trusted_proxy_range_refs": "Caddy配置",
	"trusted_proxy_headers":    "Caddy配置",
	"trusted_proxy_strict":     "Caddy配置",
	"access_log_json":          "Caddy配置",
	"access_log_format":        "Caddy配置",

	"log_level":              "基础设置",
	"task_log_size_mb":       "基础设置",
	"audit_log_size_mb":      "基础设置",
	"runtime_log_size_mb":    "基础设置",
	"audit_retention_months": "基础设置",
	"server_map_lat":         "基础设置",
	"server_map_lon":         "基础设置",
	"jwt_expire_minutes":     "基础设置",
	"timezone":               "基础设置",
	"github_proxy_url":       "基础设置",
	// (2026-09-10 审计): 增补的两个安全开关漏同步 section 映射,审计
	// 归因曾落「全局配置」(实际在基础设置卡片)。
	// (2026-09-29 审计):同族漏点收敛——github_token 同批入表,审计归因
	// 曾落「全局配置」;全字段覆盖清点钉在 handlers/config_field_sections_test.go。
	"mfa_write_guard":     "基础设置",
	"mfa_lockout_enabled": "基础设置",
	"github_token":        "基础设置",

	// 威胁大屏视觉模式与安全事件保留（显式天/行帽）三字段
	// 漏同步 section 映射——字段级审计归因曾落「全局配置」（实际在基础设置卡片）。
	// 覆盖清点钉已改为源码扫描（handlers/config_field_sections_test.go 提取
	// planConfigChanges 的 add() 首参，与下表双向比对）。
	"threat_screen_mode":             "基础设置",
	"security_events_retention_days": "基础设置",
	"security_events_row_cap":        "基础设置",
	"threat_traffic_sample_n":        "基础设置",
}

func GetConfigSection(field string) string {
	if section, ok := ConfigFieldSections[field]; ok {
		return section
	}
	return "全局配置"
}

func GetConfigSourceSection(source string) string {
	switch source {
	case "basic":
		return "基础设置"
	case "cluster":
		return "集群管理"
	case "acme":
		return "ACME配置"
	case "caddy":
		return "Caddy配置"
	default:
		return "全局配置"
	}
}

// 操作日志词汇标准（系统标准，新老事件均须遵循）：操作标签 ≤4 词、事件对象
// ≤5 词。词制计数：中文字符各算 1 词，连续英文/数字串（API、Caddy、
// IP2Region 等缩写）整体算 1 词，空白不计。硬卡控在
// audit_vocabulary_test.go（新增超标字面量测试直接红），此处入口仅告警
// 不阻断，保持 best-effort 写入语义。
const (
	auditActionMaxWords   = 4
	auditResourceMaxWords = 5
)

func auditVocabWords(s string) int {
	words := 0
	inASCII := false
	for _, r := range s {
		switch {
		case r == ' ' || r == '\t':
			inASCII = false
		case r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'):
			if !inASCII {
				words++
				inASCII = true
			}
		default:
			words++
			inASCII = false
		}
	}
	return words
}

// auditDetailMaxBytes 是审计详情的落库上限。详情可携带对端文本（集群主节点
// 错误体、被攻陷主节点或明文链路 MITM 的响应），无界写入会膨胀审计库并让前端
// 单行渲染卡顿；4KB 覆盖正常业务文案（最长者为配置差异清单的聚合行）。
const auditDetailMaxBytes = 4 << 10

// sanitizeAuditDetail 是审计详情的单源净化：剥离控制字符（C0 与 DEL，含换行
// ——审计详情是单行文本，保留会让对端文本伪造「；结果：成功」之类段落）并按
// 4KB 上限截断到合法 UTF-8 边界。调用点覆盖全部 20+ 写入方，避免下一处遗漏
// 重演「同族两种处置」（此前 WAF 拉取路径单独截断 200B，集群切换/同步失败
// 路径原样落库）。
func sanitizeAuditDetail(detail string) string {
	if detail == "" {
		return detail
	}
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, detail)
	if len(cleaned) <= auditDetailMaxBytes {
		return cleaned
	}
	cut := auditDetailMaxBytes
	for cut > 0 && !utf8.ValidString(cleaned[:cut]) {
		cut--
	}
	return cleaned[:cut]
}

// auditIdentityMaxBytes 是审计身份列（username/action/resource/ip_address）的
// 落库上限。这些列不承载对端详情文本（详情走 detail 列），但会进入列表排版与
// 筛选：超长值截断到可展示长度即可，不得因该列异常丢事件（审计写入是
// best-effort）。
const auditIdentityMaxBytes = 256

// sanitizeAuditIdentity 净化审计身份列：剥控制字符（含换行——否则审计列表可被
// 排版成多行伪记录）并按 auditIdentityMaxBytes 截断到合法 UTF-8 边界。
// 与 detail 的单点净化同口径：此前只有 detail 净化，username 来自 users 表
// （导入备份/带外改库/未来自助注册均可带入控制字符），action/resource 是内部
// 词表字面量但仍按同口径纵深防御。
func sanitizeAuditIdentity(value string) string {
	if value == "" {
		return value
	}
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(cleaned) <= auditIdentityMaxBytes {
		return cleaned
	}
	cut := auditIdentityMaxBytes
	for cut > 0 && !utf8.ValidString(cleaned[:cut]) {
		cut--
	}
	return cleaned[:cut]
}

// beforeAuditLogExec 保留审计写入前注入缝，供关停交错回归测试使用。
var beforeAuditLogExec = func() {}

func RecordAuditLog(username, action, resource, detail, ipAddress string) {
	detail = sanitizeAuditDetail(detail)
	username = sanitizeAuditIdentity(username)
	action = sanitizeAuditIdentity(action)
	resource = sanitizeAuditIdentity(resource)
	ipAddress = sanitizeAuditIdentity(ipAddress)
	auditDB := db.AuditDB
	if auditDB == nil {
		Logf("warn", "audit log write skipped: audit database is not initialized")
		return
	}
	if aw, rw := auditVocabWords(action), auditVocabWords(resource); aw > auditActionMaxWords || rw > auditResourceMaxWords {
		Logf("info", "audit vocabulary over limit (action<=%d, resource<=%d): action=%q(%d) resource=%q(%d)", auditActionMaxWords, auditResourceMaxWords, action, aw, resource, rw)
	}
	beforeAuditLogExec()
	if _, err := auditDB.Exec("INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES (?, ?, ?, ?, ?)",
		username, action, resource, detail, ipAddress); err != nil {
		Logf("error", "audit log write failed: %v", err)
	}
}

func AppendAPIKeyAuditDetail(detail string, keyID int, keyName string) string {
	apiKeyPart := fmt.Sprintf("API密钥 %d（%s）", keyID, keyName)
	if detail == "" {
		return fmt.Sprintf("认证方式：API密钥；%s", apiKeyPart)
	}
	return fmt.Sprintf("%s；认证方式：API密钥；%s", detail, apiKeyPart)
}

// auditRetentionMonths 读取审计保留月数（audit_retention_months，默认 3）。
// 三消费点（CleanupAuditLogs/RuntimeLogCleanupOnce/taskLogsHousekeeping）
// 统一口径，返回 (月数, 错误)：
//
//   - 只有「口径已知」的错误形态才回退默认：ErrNoRows（全新库/配置行缺失
//     ——从未配置过，默认即用户口径）按默认 3 月继续，不返回错误。
//   - nil 库同样按「口径未知」返回错误，且不能回退默认：nil 覆盖两种生命
//     周期——启动前的脚手架形态，和关停后 db.Close() 置 nil 的形态。后者
//     发生在进程排空放弃、在途清理轮仍在跑时（关停预算耗尽后遗留 goroutine
//     随进程退出回收），按默认 3 月删除会把用户 12 月保留期内的应用日志副本
//     与任务日志不可逆删掉。调用方据此跳过本轮保留期删除（waf-audit 兜底与
//     规则日志孤儿清理在保留期门之前执行，不受影响）。
//   - 其他读错误（迁移窗口缺列、锁超时、库瞬断）返回 error：**不可逆删除不得
//     在口径未知时按更短默认执行**——用户配置 12 月保留时一次读失败会让
//     当日清理按 3 月永久删掉 9 个月审计证据。调用方据此跳过本轮删除并让
//     任务落 failed（下轮重试）。
//   - 越界值（<1）同回退默认（写侧 1-12 校验+启动钳位兜底，正常不可达）。
//
// log-cleanup 摘要行不再自行查库复算月数，改为复用
// RuntimeLogCleanupOnce 回填的 RuntimeCleanupResult.RetentionMonths——仍在
// 上述三消费点内，未新增第四份口径。
//
// ctx 贯穿本条首段读取：调用方都处在有界关停/导入排空预算内，取消已发出即
// 按 ctx 返回，不把「查询被主库写锁挡住」拖过预算。句柄取局部快照——nil
// 判定与查询必须针对同一个 *sql.DB，关停尾部 db.Close() 可能在两者之间把
// 包级 db.DB 置 nil。
func auditRetentionMonths(ctx context.Context) (int, error) {
	defaultMonths := db.DefaultAuditRetentionMonths
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	database := db.DB
	if database == nil {
		Logf("warn", "审计保留月数口径未知（数据库未初始化或已关闭），本轮跳过保留期删除")
		return 0, fmt.Errorf("保留月数口径未知：数据库未初始化或已关闭")
	}
	var months int
	if err := database.QueryRowContext(ctx, "SELECT COALESCE(audit_retention_months, ?) FROM global_config WHERE id=1", db.DefaultAuditRetentionMonths).Scan(&months); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 配置行缺失＝从未配置：默认值即用户口径，继续清理（仍留痕，
			// 与「读取失败不得静默」口径一致）。
			Logf("warn", "审计保留月数配置行缺失，按默认 %d 个月执行: %v", defaultMonths, err)
			return defaultMonths, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			// 取消打断查询：按取消原因返回，不记为「读取失败」（关停窗口
			// 不刷误导性 warn）。
			return 0, ctxErr
		}
		Logf("warn", "读取审计保留月数失败，本轮跳过保留期删除（不按默认 %d 个月删除证据）: %v", defaultMonths, err)
		return 0, fmt.Errorf("读取审计保留月数失败: %w", err)
	}
	if months < 1 {
		return defaultMonths, nil
	}
	return months, nil
}

// auditCleanupBatchSize 保留清理单批上限：分批 DELETE 避免长写锁阻塞
// 审计写入（单条巨型 DELETE 在百万行库上持锁数秒）。var 供测试缩批。
var auditCleanupBatchSize = 5000

// errAuditDBUnavailable 审计库未初始化或已关闭（关停期 db.Close() 置 nil）。
// 循环每批重读句柄并在 nil 时返回该错误：入口只判一次不足以防 nil 解引用
// panic——关停排空是**有界放弃**的，db.Close() 紧随其后把 AuditDB 置 nil，
// 大批积压的清理轮会在下一批撞上 nil *sql.DB。返回可见错误让任务落 failed
// 且摘要保留真实部分计数（已删批次不可逆）。
var errAuditDBUnavailable = errors.New("审计数据库未初始化")

// CleanupAuditLogs 按保留月数清理审计日志，返回删除条数（SPEC §6.5 摘要行数据源）。
// 失败必须上抛：audit-retention 任务体据此落 failed 终态，且失败轮不得写
// 「清理完成」（此前失败静默返回 0——任务监控全绿、摘要谎报完成）。
// 分批删除：每批至多 auditCleanupBatchSize 行循环至删净，批间释放写锁并
// 复检 ctx（删除按批幂等，中途取消语义无损——关停/取消可中断本轮，不让
// 日志清理轮拖过关停预算）。
func CleanupAuditLogs(ctx context.Context) (int, error) {
	retentionMonths, monthsErr := auditRetentionMonths(ctx)
	if monthsErr != nil {
		// 保留期口径未知时一条都不删：按更短默认删除是不可逆的证据损失。
		return 0, monthsErr
	}
	cutoff := time.Now().UTC().AddDate(0, -retentionMonths, 0).Format("2006-01-02 15:04:05")
	total := 0
	for {
		// 每批重读句柄（与指标孤儿清理同源）：nil 时返回可见错误，已删批次
		// 不可逆但计数如实。
		auditDB := db.AuditDB
		if auditDB == nil {
			Logf("warn", "audit log cleanup skipped: audit database is not initialized")
			return total, errAuditDBUnavailable
		}
		res, err := auditDB.ExecContext(ctx, "DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log WHERE created_at < ? LIMIT ?)", cutoff, auditCleanupBatchSize)
		if err != nil {
			Logf("warn", "audit log cleanup failed: %v", err)
			// 已删除批次不可逆——失败路径必须返回真实部分计数，摘要才能如实
			// 反映「已删除 N 条后中止」（与 security-events-retention 同口径）。
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("读取审计日志删除条数失败: %w", err)
		}
		total += int(n)
		// 批间复检 ctx：末批清空后同样以取消态收尾——否则任务取消/关停被
		// 当作清理完成（success），与「本轮只删掉了部分行」的事实不符。
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if int(n) < auditCleanupBatchSize {
			break
		}
	}
	return total, nil
}

// auditRetentionRound 一轮审计保留清理：审计日志分段 + 任务运行历史分段。
// 两段共用任务 ctx，且分段之间复检——本轮已被取消/关停打断时不得再启动
// 第二段不可逆删除（首段已删的行不可逆，但计数如实上报）。
func auditRetentionRound(ctx context.Context) (auditDeleted int, runsDeleted int64, err error) {
	auditDeleted, auditErr := CleanupAuditLogs(ctx)
	if ctxErr := ctx.Err(); ctxErr != nil {
		// 首段因同一取消提前返回时不再叠加同一条取消错误（摘要行只说一次）。
		if auditErr != nil && errors.Is(auditErr, ctxErr) {
			return auditDeleted, 0, auditErr
		}
		return auditDeleted, 0, errors.Join(auditErr, ctxErr)
	}
	runsDeleted, runsErr := taskengine.PurgeTaskRuns(ctx, 90)
	return auditDeleted, runsDeleted, errors.Join(auditErr, runsErr)
}

// FormatAuditAction 中间件侧通用审计的动作映射。仅保留 5 条 Generic
// 路由（auditpolicy.go 分类）中由中间件记录的 3 条 caddy/start|stop|restart——
// 其余全部 Explicit 路由的 handler 自行显式记录且被 HasExplicitAuditEvent 前置
// 短路，本函数对它们的映射运行时不可达（死代码，含映射不存在路由 /nodes/register
// 的历史遗留）；死映射的最大风险是「Explicit 清单漂移漏掉某路由时中间件恢复
// 映射记录 → 与 handler 显式记录叠加成双条」，故全部删除。
// 新增路由的审计分工：handler 显式记录 → 入 auditRoutePolicies 为 Explicit；
// 由中间件记录 → 入 Generic 并在本函数补映射 + TestAuditGenericRoutesExactlyOnce
// 登记表同步。契约绊线见 TestAuditExplicitRoutesMappingEmpty / TestAuditPolicyListsEqual。
func FormatAuditAction(path string) (action, resource, detail string) {
	switch {
	// /api/v1/config 为 Explicit（handler 记录，HasExplicitAuditEvent
	// 前置短路）；/config/reload 为 Generic 且由 handler（ReloadCaddy）显式记录，
	// 中间件经本函数的空映射跳过（不记录）——两者均无需映射 case，走兜底空返回。
	// 注意勿为 reload 补映射：Generic + handler 记录 + 非空映射 = 单次动作双条
	//（缺陷形态，TestAuditGenericRoutesExactlyOnce 钉住）。

	case strings.Contains(path, "/caddy/start"):
		return "启动", "Caddy服务", path
	case strings.Contains(path, "/caddy/stop"):
		return "停止", "Caddy服务", path
	case strings.Contains(path, "/caddy/restart"):
		return "重启", "Caddy服务", path
	}

	return "", "", ""
}

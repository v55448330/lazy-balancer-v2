package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// auditOptionRow 下拉选项的一行（值 + 频次）。
type auditOptionRow struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// auditOptionsPayload 是下拉选项响应的唯一构造点：正常/降级/故障三种状态
// 共用同一键集（usernames/actions/resources/partial），避免消费方按状态
// 切换解码分支。nil 值按空数组下发（JSON null 会让前端 spread 失败）。
func auditOptionsPayload(usernames, actions, resources []auditOptionRow, partial bool) map[string]interface{} {
	if usernames == nil {
		usernames = []auditOptionRow{}
	}
	if actions == nil {
		actions = []auditOptionRow{}
	}
	if resources == nil {
		resources = []auditOptionRow{}
	}
	return map[string]interface{}{
		"usernames": usernames,
		"actions":   actions,
		"resources": resources,
		"partial":   partial,
	}
}

// GetAuditLogOptions 返回筛选下拉的可选值：操作人/操作取自审计库去重
// auditOptionsCache:options 三条 GROUP BY 的进程内缓存(60s)——
// 下拉选项对实时性不敏感,深审计库每次筛选面板打开都做三趟全表 GROUP BY
// 是无谓放大;写侧不失效(60s 窗口内新动作延迟出现,可接受口径)。
// 读写并发加 sync.Mutex(与 helpers.go diskUsageCache 同型)——
// 此前读缓存/写缓存无锁,并发筛选面板打开可交错出撕裂读。
var auditOptionsCache struct {
	sync.Mutex
	expiresAt time.Time
	payload   map[string]interface{}
}

// resetAuditOptionsCacheForTest 仅供测试隔离。
func resetAuditOptionsCacheForTest() {
	auditOptionsCache.Lock()
	defer auditOptionsCache.Unlock()
	auditOptionsCache.expiresAt = time.Time{}
	auditOptionsCache.payload = nil
}

func (h *Handlers) GetAuditLogOptions(c *gin.Context) {
	// 审计库未装配时降级为空结果——同包日志统计
	// （GetLogStats）与审计写路径都有 nil 守卫，此处此前裸解引用会把生命周期
	// 边界形态变成 panic/500。降级形态与正常路径同键集（三列为空数组 +
	// partial=true），消费方无需按状态切换解码分支。
	if db.AuditDB == nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: auditOptionsPayload(nil, nil, nil, true)})
		return
	}
	// 缓存命中直返；并发 miss 经 single-flight 只跑一趟三条 GROUP BY（其余
	// 等待同一结果）——60s 边界或多人同时打开筛选面板不再以 3N 次全表聚合
	// 打到 SQLite。锁只保护缓存读写（double-check），查询在无锁状态执行。
	if payload, ok := loadAuditOptionsCache(time.Now()); ok {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: payload})
		return
	}
	// 聚合脱离首个请求的取消信号（首请求断开不应让同批等待者失败），保留
	// 总时长上限。
	value, _, _ := auditOptionsGroup.Do("audit-options", func() (any, error) {
		if payload, ok := loadAuditOptionsCache(time.Now()); ok {
			return payload, nil
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 10*time.Second)
		defer cancel()
		payload, fetchErr := auditOptionsFetch(ctx)
		// 任一 fetchDistinct 出错即跳过本轮缓存写入——空结果是故障形态,
		// 缓存它会让一次瞬态错误在 60s 窗口内持续喂空下拉。故障轮载荷已由
		// fetchAuditLogOptions 置 partial=true（与降级形态同键集），让
		// 「部分下拉」与「真空库」可区分。
		if fetchErr == nil {
			storeAuditOptionsCache(payload, time.Now())
		}
		return payload, nil
	})
	payload, _ := value.(map[string]interface{})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: payload})
}

// auditOptionsGroup 并发 miss 合并组：同一时刻只跑一趟下拉聚合。
var auditOptionsGroup singleflight.Group

// auditOptionsFetch 是下拉聚合的抓取入口（测试缝：计数/慢响应注入）。
var auditOptionsFetch = fetchAuditLogOptions

func loadAuditOptionsCache(now time.Time) (map[string]interface{}, bool) {
	auditOptionsCache.Lock()
	defer auditOptionsCache.Unlock()
	if auditOptionsCache.payload != nil && now.Before(auditOptionsCache.expiresAt) {
		return auditOptionsCache.payload, true
	}
	return nil, false
}

func storeAuditOptionsCache(payload map[string]interface{}, now time.Time) {
	auditOptionsCache.Lock()
	auditOptionsCache.payload = payload
	auditOptionsCache.expiresAt = now.Add(60 * time.Second)
	auditOptionsCache.Unlock()
}

// auditLogCountCacheTTL 审计列表 total（全表 COUNT(*)）的进程内缓存窗口：
// 审计库为百万行级（见 logstats 全表计数注释），每次翻页/筛选都付一次全表
// 计数；行数是展示与翻页锚点，5s 陈旧对用户不可感知。键=筛选条件签名——
// 不同筛选各自成桶，读失败不缓存（下一请求重试）。响应以 total_stale
// 披露「本次计数来自缓存」，消费方据此判断是否需要刷新核对。
var auditLogCountCacheTTL = 5 * time.Second

// auditLogCountCacheMaxEntries 计数缓存桶上限（任意筛选组合不得让缓存无界
// 增长）；越界逐出 at 最旧的一个桶，而非清空全表——清空会让紧接着的请求
// 全部退化回全表 COUNT(*)。
const auditLogCountCacheMaxEntries = 64

type auditLogCountEntry struct {
	total int64
	at    time.Time
}

var auditLogCounts struct {
	sync.Mutex
	entries map[string]auditLogCountEntry
}

// resetAuditLogCountCacheForTest 仅供测试隔离（跨用例的审计库交换后不得
// 读到上一夹具的计数）。
func resetAuditLogCountCacheForTest() {
	auditLogCounts.Lock()
	auditLogCounts.entries = nil
	auditLogCounts.Unlock()
}

func auditLogCountCacheKey(where string, args []interface{}) string {
	var b strings.Builder
	b.WriteString(where)
	for _, arg := range args {
		b.WriteString("\x1f")
		b.WriteString(fmt.Sprint(arg))
	}
	return b.String()
}

// cachedAuditLogTotal 返回当前筛选条件的 total；stale=true 表示来自缓存。
// 缓存桶上限 auditLogCountCacheMaxEntries，越界逐出 at 最旧的一个桶。
// 计数走请求 context：百万行 COUNT(*) 在客户端断开后不应继续跑完并占用
// SQLite 连接。
func cachedAuditLogTotal(ctx context.Context, database *sql.DB, where string, args []interface{}) (int64, bool, error) {
	key := auditLogCountCacheKey(where, args)
	now := time.Now()
	auditLogCounts.Lock()
	entry, ok := auditLogCounts.entries[key]
	auditLogCounts.Unlock()
	if ok && now.Sub(entry.at) < auditLogCountCacheTTL {
		return entry.total, true, nil
	}
	var total int64
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log"+where, args...).Scan(&total); err != nil {
		return 0, false, err
	}
	auditLogCounts.Lock()
	if auditLogCounts.entries == nil {
		auditLogCounts.entries = map[string]auditLogCountEntry{}
	}
	if len(auditLogCounts.entries) >= auditLogCountCacheMaxEntries {
		oldestKey, oldestAt := "", time.Time{}
		for k, v := range auditLogCounts.entries {
			if oldestKey == "" || v.at.Before(oldestAt) {
				oldestKey, oldestAt = k, v.at
			}
		}
		if oldestKey != "" {
			delete(auditLogCounts.entries, oldestKey)
		}
	}
	auditLogCounts.entries[key] = auditLogCountEntry{total: total, at: now}
	auditLogCounts.Unlock()
	return total, false, nil
}

// fetchAuditLogOptions 执行三条去重聚合（调用方保证同一时刻只跑一趟）。
// 返回载荷与降级形态同键集：partial 仅在本轮任一列查询/扫描/迭代失败时为
// true（故障轮载荷不得写入缓存，由调用方按 fetchErr 判定）。
func fetchAuditLogOptions(ctx context.Context) (map[string]interface{}, error) {
	fetchDistinct := func(column string, limit int) ([]auditOptionRow, error) {
		rows, err := db.AuditDB.QueryContext(ctx, `
			SELECT `+column+`, COUNT(*) AS cnt FROM audit_log
			WHERE `+column+` != ''
			GROUP BY `+column+`
			ORDER BY cnt DESC, `+column+`
			LIMIT ?`, limit)
		if err != nil {
			// 查询失败曾零日志（恒 200 空/部分下拉，运维无信号）——
			// 首错处 warn 留痕，响应携带 partial 标记。
			services.Logf("warn", "审计日志下拉选项（%s）查询失败: %v", column, err)
			return []auditOptionRow{}, err
		}
		defer rows.Close()
		out := []auditOptionRow{}
		var scanErr error
		for rows.Next() {
			var o auditOptionRow
			if err := rows.Scan(&o.Value, &o.Count); err != nil {
				// 单行 Scan 失败须留痕——静默丢行让下拉
				// 缺项零信号（主查询 500 口径在此分裂为静默）。
				services.Logf("warn", "审计日志下拉选项（%s）行扫描失败: %v", column, err)
				// Scan 失败也是故障轮——此前只 continue，fetchErr 不置位，
				// 缺项下拉被当作完整结果写进 60s 缓存（同文件门禁的
				// 遗漏分支）。保留首错用于缓存门判定。
				if scanErr == nil {
					scanErr = fmt.Errorf("审计日志下拉选项（%s）行扫描失败: %w", column, err)
				}
				continue
			}
			out = append(out, o)
		}
		// 迭代错误上抛 fetchErr——缓存门口径统一（查询失败
		// 与迭代失败同为故障轮，空/部分结果不得写 60s 缓存）。
		if err := rows.Err(); err != nil {
			services.Logf("warn", "审计日志下拉选项（%s）迭代失败: %v", column, err)
			return out, err
		}
		if scanErr != nil {
			return out, scanErr
		}
		return out, nil
	}
	var fetchErr error
	collect := func(column string, limit int) []auditOptionRow {
		rows, err := fetchDistinct(column, limit)
		if err != nil && fetchErr == nil {
			fetchErr = err
		}
		return rows
	}
	usernames := collect("COALESCE(username,'')", 100)
	actions := collect("action", 100)
	resources := collect("COALESCE(resource,'')", 50)
	return auditOptionsPayload(usernames, actions, resources, fetchErr != nil), fetchErr
}

// auditLogListPayload 是审计列表响应的唯一构造点：正常/降级两种状态共用
// 同一键集（list/total/total_stale/partial/page/page_size），消费方无需按
// 状态切换解码分支。list 的静态类型随调用方（降级为空切片、正常为条目
// 切片），键集与空值语义在此收口。
func auditLogListPayload(list any, total int64, totalStale, partial bool, page, pageSize int) map[string]interface{} {
	if list == nil {
		list = []any{}
	}
	return map[string]interface{}{
		"list":        list,
		"total":       total,
		"total_stale": totalStale,
		"partial":     partial,
		"page":        page,
		"page_size":   pageSize,
	}
}

// buildAuditLogFilters 组装列筛选 WHERE 子句。时间参数按配置时区解析后
// 换算为 UTC 与 created_at 比较；日期-only 输入自动补全天/日边界。
func buildAuditLogFilters(c *gin.Context, loc *time.Location) (string, []interface{}, bool) {
	// LIKE 值侧转义——用户输入中的 %/_/\ 是字面字符,不转义会被
	// 当通配符(搜「100%」命中 100abc);SQL 追加 ESCAPE '\' 声明转义符。
	like := func(column, value string) (string, interface{}) {
		return " AND " + column + " LIKE ? ESCAPE '\\'", "%" + escapeLikePattern(value) + "%"
	}
	var conds []string
	var args []interface{}
	if v := strings.TrimSpace(c.Query("username")); v != "" {
		c1, a1 := like("COALESCE(username,'')", v)
		conds = append(conds, c1)
		args = append(args, a1)
	}
	if v := strings.TrimSpace(c.Query("action")); v != "" {
		c1, a1 := like("action", v)
		conds = append(conds, c1)
		args = append(args, a1)
	}
	if v := strings.TrimSpace(c.Query("resource")); v != "" {
		c1, a1 := like("COALESCE(resource,'')", v)
		conds = append(conds, c1)
		args = append(args, a1)
	}
	if v := strings.TrimSpace(c.Query("ip")); v != "" {
		c1, a1 := like("COALESCE(ip_address,'')", v)
		conds = append(conds, c1)
		args = append(args, a1)
	}
	if v := strings.TrimSpace(c.Query("keyword")); v != "" {
		c1, a1 := like("COALESCE(detail,'')", v)
		conds = append(conds, c1)
		args = append(args, a1)
	}
	// 畸形时间筛选改 400：此前解析失败静默丢弃条件
	// 返回全量数据——用户以为在按时间过滤而实际没有。解析统一在此处做，
	// 失败即 400（aborted=true 让调用方短路）。
	parseBoundary := func(raw, endOfDay string) (time.Time, bool, bool) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return time.Time{}, false, false
		}
		if len(raw) == 10 { // YYYY-MM-DD → 起点取 00:00:00，终点取 23:59:59
			raw += " " + endOfDay
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", raw, loc)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "时间筛选格式无效，应为 YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS"})
			return time.Time{}, false, true
		}
		return t.UTC(), true, false
	}
	if startT, ok1, abort1 := parseBoundary(c.Query("start_time"), "00:00:00"); abort1 {
		return "", nil, true
	} else if ok1 {
		// (2026-09-10 审计):裸列比较替代 datetime(created_at) 包裹——包裹
		// 使 idx_audit_log_created 失效全表扫;created_at 为 SQLite 规范 UTC 文本
		// 与 datetime(?) 输出同格式,直接比较等价且可走索引。
		conds = append(conds, " AND created_at >= datetime(?)")
		args = append(args, startT.Format("2006-01-02 15:04:05"))
	}
	if endT, ok2, abort2 := parseBoundary(c.Query("end_time"), "23:59:59"); abort2 {
		return "", nil, true
	} else if ok2 {
		conds = append(conds, " AND created_at <= datetime(?)")
		args = append(args, endT.Format("2006-01-02 15:04:05"))
	}
	if len(conds) == 0 {
		return "", nil, false
	}
	return " WHERE 1=1" + strings.Join(conds, ""), args, false
}

// auditLogDeepPageLimit 审计列表深翻页上限（页码分页保留跳页能力，超限 400）。
const auditLogDeepPageLimit = 500

func (h *Handlers) GetAuditLogs(c *gin.Context) {
	// 分页参数统一解析（与安全事件/证书任务同口径）：非整数 400；<1 回默认；
	// page_size 超上限钳到 100（此前静默回默认 20——传 500 只拿到 20 条且无
	// 任何信号）。page 超阈值仍显式 400（深 OFFSET 退化，见下）。
	// 解析必须先于 nil 守卫：降级响应也按请求分页回显，否则 ?page=3&page_size=50
	// 在审计库未就绪时拿到第 1 页 20 条，按文档生成的分页器会跳回首页。
	page, ok := parsePaginationParam(c, "page", 1, math.MaxInt)
	if !ok {
		return
	}
	pageSize, ok := parsePaginationParam(c, "page_size", 20, 100)
	if !ok {
		return
	}
	// 深翻页折中：页码分页保留（可跳页、有总页数），但超过阈值显式 400 并给出
	// 筛选指引——OFFSET 深页在大审计库上是秒级全表扫描，静默 clamp 会让用户
	// 以为「翻到了第 501 页」却拿到错位结果。该 400 同时是 *pageSize 溢出的
	// 唯一防线（page ≤500 × page_size ≤100 → offset 恒安全）。
	// 必须在 nil 守卫之前：降级窗口不得比正常路径更宽松——审计库未就绪时
	// ?page=99999999 若回 200，按文档生成的分页器会显示不存在的页并算出越界
	// 偏移，同一参数在故障窗口内外的状态码分叉也无从排障。降级分支只回显
	// 合法页码。
	if page > auditLogDeepPageLimit {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf(
			"结果过多（超过 %d 页），请使用时间范围/用户/动作筛选缩小范围", auditLogDeepPageLimit)})
		return
	}
	// 与 GetAuditLogOptions 同口径的 nil 守卫。降级形态与正常路径同键集：
	// total_stale=true（计数不可信）+ partial=true，消费方无需按状态切换解码。
	if db.AuditDB == nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "审计库未就绪",
			Data: auditLogListPayload([]map[string]any{}, 0, true, true, page, pageSize)})
		return
	}
	offset := int64(page-1) * int64(pageSize)

	// 列筛选：操作人/操作/对象/IP 模糊匹配，keyword 搜详情，
	// 时间范围为配置时区的本地时间（created_at 按 UTC 存储，比较前换算）。
	loc := time.UTC
	var tzStr string
	// 时区读取失败/非法值的留痕走 services 状态转换单源（首报 warn、恢复
	// info）——此前两分支都直接 Logf("error")，带外写入非法时区后审计页每次
	// 轮询都记一条 error 淹没真实故障，且恢复无「已恢复」信号（与日志统计
	// 阈值读取同域口径分裂）。读失败与「值非法」用不同 key 区分。
	if err := db.DB.QueryRowContext(c.Request.Context(), "SELECT COALESCE(timezone,?) FROM global_config WHERE id=1", db.DefaultTimezone).Scan(&tzStr); err != nil {
		services.LogConfigReadFailure("audit-log-timezone", fmt.Errorf("审计日志筛选时区读取失败（按 UTC 继续）: %w", err))
	} else if l, lerr := time.LoadLocation(tzStr); lerr == nil {
		services.LogConfigReadRecovered("audit-log-timezone")
		services.LogConfigReadRecovered("audit-log-timezone-value")
		loc = l
	} else {
		services.LogConfigReadRecovered("audit-log-timezone")
		services.LogConfigReadFailure("audit-log-timezone-value", fmt.Errorf("审计日志筛选时区 %q 非法（按 UTC 继续）: %w", tzStr, lerr))
	}
	where, args, aborted := buildAuditLogFilters(c, loc)
	if aborted {
		return
	}

	// total 走 5s 进程缓存（键=筛选条件签名）：百万行审计库下每请求一次
	// 全表 COUNT(*) 是首屏固定成本，翻页/筛选反复支付；行数是展示与翻页
	// 锚点，短陈旧不可感知，响应以 total_stale 披露来源（不静默）。
	total, totalStale, err := cachedAuditLogTotal(c.Request.Context(), db.AuditDB, where, args)
	if err != nil {
		writeInternalError(c, http.StatusInternalServerError, "查询操作日志失败", fmt.Errorf("统计操作日志总数: %w", err))
		return
	}

	rows, err := db.AuditDB.QueryContext(c.Request.Context(), `
		SELECT id,
		       COALESCE(username, ''),
		       action,
		       COALESCE(resource,''),
		       COALESCE(detail,''),
		       COALESCE(ip_address,''),
		       created_at
		FROM audit_log`+where+`
		ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, pageSize, offset)...)
	if err != nil {
		writeInternalError(c, http.StatusInternalServerError, "查询操作日志失败", fmt.Errorf("查询操作日志明细: %w", err))
		return
	}
	defer rows.Close()

	type AuditLogEntry struct {
		ID          int    `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Action      string `json:"action"`
		Resource    string `json:"resource"`
		Detail      string `json:"detail"`
		IPAddress   string `json:"ip_address"`
		CreatedAt   string `json:"created_at"`
	}

	var logs []AuditLogEntry
	usernames := map[string]struct{}{}
	for rows.Next() {
		var e AuditLogEntry
		var createdAt time.Time
		if err := rows.Scan(&e.ID, &e.Username, &e.Action, &e.Resource, &e.Detail, &e.IPAddress, &createdAt); err != nil {
			// 与计数分支同口径：本端点在 business 组，任意登录用户可读，响应
			// 只回固定文案，扫描失败的表/列名与驱动错误只进运行日志。
			writeInternalError(c, http.StatusInternalServerError, "读取操作日志失败", fmt.Errorf("扫描操作日志行: %w", err))
			return
		}
		e.CreatedAt = createdAt.UTC().Format("2006-01-02 15:04:05")
		e.DisplayName = e.Username
		if e.Username != "" {
			usernames[e.Username] = struct{}{}
		}
		logs = append(logs, e)
	}
	if err := rows.Err(); err != nil {
		writeInternalError(c, http.StatusInternalServerError, "遍历操作日志失败", fmt.Errorf("遍历操作日志行: %w", err))
		return
	}
	if logs == nil {
		logs = []AuditLogEntry{}
	}
	// display_name 富化失败同样置 partial=true：列表已静默退化为 username，
	// 消费方必须能感知「部分降级」（与文档 partial 语义一致）。
	displayNameDegraded := false
	if len(usernames) > 0 {
		args := make([]interface{}, 0, len(usernames))
		placeholders := make([]string, 0, len(usernames))
		for name := range usernames {
			placeholders = append(placeholders, "?")
			args = append(args, name)
		}
		userRows, err := db.DB.QueryContext(c.Request.Context(), "SELECT username, COALESCE(NULLIF(TRIM(display_name), ''), username) FROM users WHERE username IN ("+strings.Join(placeholders, ",")+")", args...)
		if err != nil {
			displayNameDegraded = true
			services.Logf("error", "GetAuditLogs: failed to enrich usernames, using usernames: %v", err)
		} else {
			displayNames := map[string]string{}
			for userRows.Next() {
				var username, displayName string
				if err := userRows.Scan(&username, &displayName); err != nil {
					displayNameDegraded = true
					services.Logf("error", "GetAuditLogs: failed to scan username enrichment, using usernames: %v", err)
					break
				}
				displayNames[username] = displayName
			}
			if err := userRows.Err(); err != nil {
				displayNameDegraded = true
				services.Logf("error", "GetAuditLogs: failed to iterate username enrichment, using available names: %v", err)
			}
			if err := userRows.Close(); err != nil {
				displayNameDegraded = true
				services.Logf("error", "GetAuditLogs: failed to close username enrichment rows: %v", err)
			}
			for i := range logs {
				if displayName, ok := displayNames[logs[i].Username]; ok {
					logs[i].DisplayName = displayName
				}
			}
		}
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: auditLogListPayload(logs, total, totalStale, displayNameDegraded, page, pageSize)})
}

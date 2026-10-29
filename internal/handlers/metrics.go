package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// caddyMetricsHTTPClient 不设 Client.Timeout：抓取截止时间只由
// caddyMetricsFetchTimeout 施加的 request context 表达（单一截止时间）。
// 曾同时存在 10s 客户端超时与 15s 自身上限，客户端恒先触发，使「自身超时/
// 取消不写负缓存」的分支在真实 HTTP 路径永不可达，且 15s 调大调小都无效果。
var caddyMetricsHTTPClient = &http.Client{}

func fetchCaddyMetrics(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := caddyMetricsHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("Caddy 指标接口返回状态码 %d", resp.StatusCode)
	}
	// （2026-09-05 审计）：与 services.go collect 的同型——limit+1
	// 探测读取，超 16MB 显式报错（共用本函数的指标端点回 502），防止指标基数
	// 膨胀时的无界内存分配。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20+1))
	if err != nil {
		return nil, fmt.Errorf("读取 Caddy 指标响应失败: %w", err)
	}
	if len(body) > 16<<20 {
		return nil, fmt.Errorf("Caddy 指标响应超过 16MB 上限")
	}
	return body, nil
}

// caddyMetricsError 是采集类失败（指标源不可达/正文不可解析）的唯一写点：
// 6 个消费端点都在任意登录身份可读的组里，响应只回固定文案——底层错误
// （指标源 URL 与内网 IP:端口、Prometheus 正文片段与行号）只进运行日志。
func caddyMetricsError(c *gin.Context, err error) {
	writeInternalError(c, http.StatusBadGateway, "采集 Caddy 指标失败", err)
}

// metricsOverviewOrZero 返回当前总览；metricsService 未装配（&Handlers{} /
// NewHandlers(Dependencies{}) 形态的测试、嵌入或未来新进程入口）时返回零值。
// 与同文件对 db.MetricsDB==nil 的「未装配返回空数据 200」口径一致——直呼
// h.metricsService.GetOverview()（指针接收者）会 panic → gin Recovery 500。
func (h *Handlers) metricsOverviewOrZero() models.MetricsOverview {
	if h == nil || h.metricsService == nil {
		return models.MetricsOverview{}
	}
	return h.metricsService.GetOverview()
}

func (h *Handlers) GetMetricsOverview(c *gin.Context) {
	overview := h.metricsOverviewOrZero()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: overview})
}

// metricsDashboardOutcome 面板聚合结果：status=0 为成功；否则携带错误状态码
// 与文案（负缓存需保存完整失败响应形态，命中时与真实失败一致）。
type metricsDashboardOutcome struct {
	payload gin.H
	status  int
	message string
}

var (
	// metricsDashboardTTL 成功聚合缓存窗口（与 systemSampleTTL 同量级）。
	metricsDashboardTTL = 5 * time.Second
	// metricsDashboardNegativeTTL 失败负缓存窗口：失败短缓存——多页签/多客户端
	// 在同一失败窗口内不再串行重试击穿 Caddy，到期立即重试（自愈快）。
	metricsDashboardNegativeTTL = 2 * time.Second
	// metricsDashboardFetch 指标抓取入口（测试缝：计数/慢响应/失败注入）。
	metricsDashboardFetch = fetchCaddyMetrics
	// metricsDashboardGroup 并发请求合并：同一时刻只跑一趟聚合，其余等待同一
	// 结果（旧实现以全局锁串行整个聚合，且失败不缓存→并发请求逐个重试）。
	metricsDashboardGroup singleflight.Group
)

// metricsDashboardState 是包级缓存：键必须包含指标源 URL，否则同一进程中
// 不同 CaddyMetricsURL 的 Handlers 实例（测试并行/多租形态）会读到对方视角
// 的聚合结果。
var metricsDashboardState struct {
	sync.Mutex
	url       string
	outcome   metricsDashboardOutcome
	expiresAt time.Time
	valid     bool
}

// 指标抓取快照：规则/主机/Caddy/面板四个消费面读同一
// CaddyMetricsURL，每请求各拉一次最多 16MB Prometheus 文本并各自解析是纯放大。
// 快照按 URL 共享 TTL，并发 miss 合并为一趟，失败短负缓存（到期即重试）。
// 各端点仍各自解析（解析产物按端点形态不同），共享的是抓取字节。
var (
	caddyMetricsSnapshotTTL         = 5 * time.Second
	caddyMetricsSnapshotNegativeTTL = 2 * time.Second
	// caddyMetricsFetchTimeout 是共享抓取的自身上限。抓取脱离首个请求的取消
	// 信号（single-flight 的结果同时交给所有等待者，单个客户端断开不得让其余
	// 健康连接收到伪造的上游失败），因此必须有独立超时兜底。
	caddyMetricsFetchTimeout  = 15 * time.Second
	caddyMetricsSnapshotGroup singleflight.Group

	// metricsAggregationMargin 是面板聚合外层预算在抓取自身上限之外的固定
	// 余量：外层预算=caddyMetricsFetchTimeout+本值（单点派生，禁止再写一份
	// 独立字面量）——抓取满额超时后 DB 聚合段仍保有整个余量窗口。
	metricsAggregationMargin = 5 * time.Second
)

type caddyMetricsSnapshot struct {
	body      []byte
	err       error
	expiresAt time.Time
}

var caddyMetricsSnapshots struct {
	sync.Mutex
	entries map[string]caddyMetricsSnapshot
}

func readCaddyMetricsSnapshot(url string, now time.Time) ([]byte, error, bool) {
	caddyMetricsSnapshots.Lock()
	defer caddyMetricsSnapshots.Unlock()
	entry, ok := caddyMetricsSnapshots.entries[url]
	if !ok || !now.Before(entry.expiresAt) {
		return nil, nil, false
	}
	return entry.body, entry.err, true
}

func storeCaddyMetricsSnapshot(url string, body []byte, err error, now time.Time) {
	ttl := caddyMetricsSnapshotTTL
	if err != nil {
		ttl = caddyMetricsSnapshotNegativeTTL
	}
	if ttl <= 0 {
		return
	}
	caddyMetricsSnapshots.Lock()
	// 进程内只有一个指标源（h.cfg.CaddyMetricsURL）：整体替换实现单条目语义
	// ——管理员改地址后旧 URL 的条目（单条最多 16MB 正文）没有消费方却会
	// 常驻，按 URL 无界累积。并发改地址时两条短暂互斥由下一次抓取收敛。
	caddyMetricsSnapshots.entries = map[string]caddyMetricsSnapshot{
		url: {body: body, err: err, expiresAt: now.Add(ttl)},
	}
	caddyMetricsSnapshots.Unlock()
}

// caddyMetricsSnapshotDoBeforeForTest 是 single-flight 入口的测试接缝
// （仅测试注入；生产恒 nil）。用例据此建立「leader 已在抓取中 → waiter 已到达
// group.Do」的同步屏障，替代按墙钟猜调度顺序。
var caddyMetricsSnapshotDoBeforeForTest func()

// loadCaddyMetricsSnapshot 返回 Caddy 指标端点原文：TTL 内共享、并发合并。
// 抓取脱离首个请求的取消信号（context.WithoutCancel + 自有超时）——结果同时
// 交给所有等待者，leader 客户端断开不得让其余健康连接收到伪造的上游失败；
// 自身超时/取消错误不写负缓存（下一次健康请求立刻重抓），避免把一次瞬时
// 超时固化成同窗内的上游失败。
//
// cacheFailure 控制失败是否也短缓存：面板已有自己的负缓存窗口（其重试节奏
// 是产品语义的一部分，不能被更长的上游负缓存悄悄收窄），故面板传 false——
// 成功快照仍共享，失败每次都重新抓取。该策略在入口缓存检查与 single-flight
// 闭包内复核**两处**都生效：否则其他端点（true）刚写入的失败条目会让面板的
// 「重新抓取」在闭包内被静默吞掉。其余指标端点传 true（避免失败窗口内多客户端
// 反复击穿 Caddy）。
func loadCaddyMetricsSnapshot(ctx context.Context, url string, cacheFailure bool) ([]byte, error) {
	if body, err, ok := readCaddyMetricsSnapshot(url, time.Now()); ok && (err == nil || cacheFailure) {
		return body, err
	}
	type snapshotResult struct {
		body []byte
		err  error
	}
	// 测试缝（nil=生产直通）：在进入 single-flight 前触发，让并发用例能确定性
	// 等到「waiter 已到达 group.Do」再取消 leader——用 sleep 猜加入时序的错误
	// 实现（去掉 context.WithoutCancel）在慢机器上同样判绿。
	if hook := caddyMetricsSnapshotDoBeforeForTest; hook != nil {
		hook()
	}
	value, _, _ := caddyMetricsSnapshotGroup.Do(url, func() (any, error) {
		now := time.Now()
		if body, err, ok := readCaddyMetricsSnapshot(url, now); ok && (err == nil || cacheFailure) {
			return snapshotResult{body: body, err: err}, nil
		}
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), caddyMetricsFetchTimeout)
		defer cancel()
		body, err := metricsDashboardFetch(fetchCtx, url)
		// TTL 从抓取**完成**时刻起算：抓取耗时可能接近甚至超过 TTL（16MB 文本
		// 上限 + 15s 自有超时本就允许长抓取），以开始时刻为基准会让条目出生即
		// 过期——最需要共享的慢抓取场景反而每次重新拉取，三端点轮询叠加成
		// 「越慢越抓」。
		switch {
		case err == nil:
			storeCaddyMetricsSnapshot(url, body, nil, time.Now())
		// fetchCtx 是抓取唯一的截止时间来源（HTTP 客户端不设 Client.Timeout），
		// 因此「自身超时/取消」在此处真实可达：到期即不写负缓存。
		case cacheFailure && fetchCtx.Err() == nil:
			storeCaddyMetricsSnapshot(url, nil, err, time.Now())
		}
		return snapshotResult{body: body, err: err}, nil
	})
	result, _ := value.(snapshotResult)
	return result.body, result.err
}

// caddyMetricsSnapshot 读取当前配置的指标快照。未注入 cfg 的嵌入/测试
// 装配形态返回可解析的零值样本，而不是裸解引用 panic。
func (h *Handlers) caddyMetricsSnapshot(ctx context.Context, cacheFailure bool) ([]byte, error) {
	if h.cfg == nil {
		return []byte("caddy_http_requests_total 0\n"), nil
	}
	return loadCaddyMetricsSnapshot(ctx, h.cfg.CaddyMetricsURL, cacheFailure)
}

func (h *Handlers) GetMetricsDashboard(c *gin.Context) {
	outcome := h.metricsDashboardCached(c.Request.Context())
	if outcome.status != 0 {
		c.JSON(outcome.status, models.APIResponse{Code: outcome.status, Message: outcome.message})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: outcome.payload})
}

// metricsDashboardCached TTL 命中直返；未命中经 single-flight 合并并发后聚合，
// 成功写正缓存、失败写短负缓存（失败不长期缓存）。
func (h *Handlers) metricsDashboardCached(ctx context.Context) metricsDashboardOutcome {
	url := ""
	if h.cfg != nil {
		url = h.cfg.CaddyMetricsURL
	}
	if outcome, ok := loadMetricsDashboardCache(url, time.Now()); ok {
		return outcome
	}
	value, _, _ := metricsDashboardGroup.Do("dashboard:"+url, func() (any, error) {
		if outcome, ok := loadMetricsDashboardCache(url, time.Now()); ok {
			return outcome, nil
		}
		// 聚合脱离首个请求的取消信号（首请求断开不应让同批等待者失败），
		// 但保留总时长上限=抓取自身上限+固定余量：两份独立 15s 字面量曾互不
		// 约束——抓取吃光整个预算后，lb_rules/upstreams 聚合查询以毫秒级预算
		// 失败，被误报为「读取规则指标配置失败」（真实原因是抓取占满预算）。
		// 由 caddyMetricsFetchTimeout 派生：调整抓取上限时聚合预算随之。
		workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), caddyMetricsFetchTimeout+metricsAggregationMargin)
		defer cancel()
		outcome := h.buildMetricsDashboard(workCtx)
		storeMetricsDashboardOutcome(url, outcome, time.Now())
		return outcome, nil
	})
	outcome, _ := value.(metricsDashboardOutcome)
	return outcome
}

func loadMetricsDashboardCache(url string, now time.Time) (metricsDashboardOutcome, bool) {
	metricsDashboardState.Lock()
	defer metricsDashboardState.Unlock()
	if metricsDashboardState.valid && metricsDashboardState.url == url && now.Before(metricsDashboardState.expiresAt) {
		return metricsDashboardState.outcome, true
	}
	return metricsDashboardOutcome{}, false
}

func storeMetricsDashboardOutcome(url string, outcome metricsDashboardOutcome, now time.Time) {
	ttl := metricsDashboardTTL
	if outcome.status != 0 {
		ttl = metricsDashboardNegativeTTL
	}
	if ttl <= 0 {
		return
	}
	metricsDashboardState.Lock()
	metricsDashboardState.url = url
	metricsDashboardState.outcome = outcome
	metricsDashboardState.expiresAt = now.Add(ttl)
	metricsDashboardState.valid = true
	metricsDashboardState.Unlock()
}

func (h *Handlers) buildMetricsDashboard(ctx context.Context) metricsDashboardOutcome {
	body, err := h.caddyMetricsSnapshot(ctx, false)
	if err != nil {
		services.Logf("warn", "采集 Caddy 指标失败: %v", err)
		return metricsDashboardOutcome{status: http.StatusBadGateway, message: "采集 Caddy 指标失败"}
	}
	samples, err := parsePrometheusSamples(string(body))
	if err != nil {
		services.Logf("warn", "解析 Caddy 指标失败: %v", err)
		return metricsDashboardOutcome{status: http.StatusBadGateway, message: "采集 Caddy 指标失败"}
	}
	metricsIndex := buildPrometheusMetricsIndex(samples)

	type dashboardRule struct {
		id, domain, protocol string
		listenPort           int
		enableTLS, enabled   bool
	}
	database := db.DB
	if database == nil {
		return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则指标配置失败"}
	}
	ruleRows, err := database.QueryContext(ctx, `
		SELECT caddy_id, COALESCE(domain,''), listen_port, COALESCE(protocol,''), COALESCE(enable_tls,0), IIF(enabled IN ('1',1),1,0)
		FROM lb_rules ORDER BY caddy_id`)
	if err != nil {
		services.Logf("warn", "指标面板读取规则配置失败（查询 lb_rules）: %v", err)
		return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则指标配置失败"}
	}
	defer ruleRows.Close()
	rules := make([]dashboardRule, 0)
	for ruleRows.Next() {
		var rule dashboardRule
		if err := ruleRows.Scan(&rule.id, &rule.domain, &rule.listenPort, &rule.protocol, &rule.enableTLS, &rule.enabled); err != nil {
			services.Logf("warn", "指标面板读取规则配置失败（扫描 lb_rules 行）: %v", err)
			return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则指标配置失败"}
		}
		rules = append(rules, rule)
	}
	if err := ruleRows.Err(); err != nil {
		services.Logf("warn", "指标面板读取规则配置失败（迭代 lb_rules 行）: %v", err)
		return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则指标配置失败"}
	}

	upstreamRows, err := database.QueryContext(ctx, `
		SELECT rule_id, COALESCE(host,''), COALESCE(port,0), COALESCE(enabled,0)
		FROM upstreams u WHERE `+services.UpstreamEnabledSQLPredicate)
	if err != nil {
		services.Logf("warn", "指标面板读取规则上游失败（查询 upstreams）: %v", err)
		return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则上游失败"}
	}
	defer upstreamRows.Close()
	upstreamsByRule := make(map[string][]models.Upstream)
	for upstreamRows.Next() {
		var upstream models.Upstream
		if err := upstreamRows.Scan(&upstream.RuleID, &upstream.Host, &upstream.Port, &upstream.Enabled); err != nil {
			services.Logf("warn", "指标面板读取规则上游失败（扫描 upstreams 行）: %v", err)
			return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则上游失败"}
		}
		upstreamsByRule[upstream.RuleID] = append(upstreamsByRule[upstream.RuleID], upstream)
	}
	if err := upstreamRows.Err(); err != nil {
		services.Logf("warn", "指标面板读取规则上游失败（迭代 upstreams 行）: %v", err)
		return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则上游失败"}
	}

	// Block 标签+4xx 扣除(2026-09-15 用户裁定,方案 B):blocked 来自
	// lb_security_blocked_counter 插件(lazybalancer_security_blocked_total,
	// 与 status_4xx 同源同抓取零延迟);4xx 显示扣除安全拦截——不再双计。
	blockedByRule := metricsIndex.blockedByRule

	ruleMetrics := make(map[string]gin.H, len(rules))
	for _, rule := range rules {
		metrics := emptyRuleMetrics()
		if rule.enabled && rule.protocol == "tcp" {
			// TCP 口径=上游地址归集（caddy-l4 指标仅 upstream 标签，
			// 见 tcpRuleMetrics 注释）——多规则共享上游地址时为跨规则合计值，
			// Dashboard 请求数/处理中列 tooltip 已明示。
			metrics = metricsIndex.tcpRuleMetrics(upstreamsByRule[rule.id])
		} else if rule.enabled {
			metrics = metricsIndex.ruleMetrics(ruleMetricTarget{ruleID: rule.id, domain: rule.domain, listenPort: rule.listenPort, enableTLS: rule.enableTLS})
		}
		metrics["enabled"] = rule.enabled
		blocked := blockedByRule[rule.id]
		metrics["blocked"] = blocked
		// 4xx 扣除安全拦截(共享 deductBlockedFrom4xx）
		deductBlockedFrom4xx(metrics, blocked)
		ruleMetrics[rule.id] = metrics
	}
	payload := gin.H{
		"global":   metricsIndex.globalMetrics(),
		"hosts":    metricsIndex.hostMetrics(),
		"overview": h.metricsOverviewOrZero(),
		"rules":    ruleMetrics,
	}
	return metricsDashboardOutcome{payload: payload}
}

func (h *Handlers) GetRuleMetrics(c *gin.Context) {
	ruleID := c.Param("caddy_id")

	var rule models.LbRule
	database := db.DB
	if database == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库未初始化"})
		return
	}
	err := database.QueryRowContext(c.Request.Context(), `SELECT COALESCE(domain,''), listen_port, COALESCE(protocol,''), COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id = ?`, ruleID).Scan(
		&rule.Domain, &rule.ListenPort, &rule.Protocol, &rule.EnableTLS)
	// 错误分类走 dbQueryNotFound 单源（errors.Is 支持 %w 包装）——此前直接
	// 比较 sql.ErrNoRows 并与 500 共用「数据库错误」，包装过的 ErrNoRows 会被
	// 误判为服务故障，且响应形态与规则历史/证书任务等同族端点分裂。
	if dbQueryNotFound(c, err, "规则不存在", "GetRuleMetrics query rule") {
		return
	}

	body, err := h.caddyMetricsSnapshot(c.Request.Context(), true)
	if err != nil {
		caddyMetricsError(c, err)
		return
	}

	var metrics gin.H
	var parseErr error
	if rule.Protocol == "tcp" {
		upstreams, err := loadRuleUpstreams(c.Request.Context(), ruleID)
		if err != nil {
			writeInternalError(c, http.StatusInternalServerError, "读取规则上游失败", err)
			return
		}
		metrics, parseErr = parseTCPRuleMetricsFromPrometheus(string(body), upstreams)
		if parseErr == nil {
			// TCP 规则无 lazybalancer 计数(L4 无插件)——
			// blocked 恒 0,与 Dashboard 对该形态恒写 blocked 键对齐。
			// 本端点 TCP 指标同为上游地址口径（L4 指标仅 upstream
			// 标签）——共享上游地址的多规则返回相同合计值，非规则独占计数。
			metrics["blocked"] = int64(0)
		}
	} else {
		metrics, parseErr = parseRuleMetricsFromPrometheus(string(body), rule.Domain, rule.ListenPort, rule.EnableTLS, ruleID)
	}
	if parseErr != nil {
		caddyMetricsError(c, parseErr)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

// parseMetricsInterval 解析 interval 参数（"<n>h"/"<n>d"/"<n>m"，空/非法回退
// 1h；上限 168h/7d/10080m——保留期固定 7 天）为 SQLite
// datetime modifier 与窗口秒数。单一解析源——此前
// metricsIntervalModifier 与 metricsIntervalSeconds 两份手写解析靠注释维持
// 一致（分桶粒度=窗口秒数/720 必须对应 SQL modifier），收敛后编译期
// 保证。SQLite 没有 "1h" 语法，算术拼接得 NULL。
func parseMetricsInterval(interval string) (modifier string, seconds int64) {
	interval = strings.TrimSpace(strings.ToLower(interval))
	if interval == "" {
		return "-1 hours", 3600
	}
	unit := interval[len(interval)-1:]
	n := strings.TrimSuffix(interval, unit)
	value, err := strconv.Atoi(n)
	if err != nil {
		return "-1 hours", 3600
	}
	// Atoi 接受负数/零——"-5h"/"0d" 曾拼出非法或零长 SQL modifier
	// （"-−5 hours"）与负/零桶宽。非正值一律回退默认窗口（上限钳制不变）。
	if value <= 0 {
		return "-1 hours", 3600
	}
	switch unit {
	case "h":
		if value > 168 {
			value = 168 // F9:保留期固定 7 天——小时上限 7×24
		}
		return "-" + strconv.Itoa(value) + " hours", int64(value) * 3600
	case "d":
		if value > 7 {
			value = 7 // F9:天上限 7(原 30d 超窗静默空)
		}
		return "-" + strconv.Itoa(value) + " days", int64(value) * 86400
	case "m":
		if value > 10080 {
			value = 10080 // F9:分钟上限 7×24×60
		}
		return "-" + strconv.Itoa(value) + " minutes", int64(value) * 60
	default:
		return "-1 hours", 3600
	}
}

// metricsHistoryBuckets 是历史序列的桶数上限（两条历史端点共用：每桶取末行
// 样本，桶数恒 ≤720，与 GetMetricsHistory 的窗口函数范式一致）。
// 覆盖口径（与 bucketSecondsFor 的上取整配套）：窗口内 epoch 对齐桶数最多
// 720+1（窗口起点恰落桶界时多出一个部分桶），LIMIT 取最旧侧截断——序列覆盖
// 起点=窗口起点+≤1 个桶宽（1h=5s、6h=30s、24h=120s、7d=840s），不承诺逐字节
// 全窗覆盖。
const metricsHistoryBuckets = 720

// bucketSecondsFor 由窗口秒数派生桶宽（两个历史端点共用的单源派生）：
// 上取整保证 720×bucket ≥ 窗口。向下取整会静默丢弃最旧 window mod 720 秒
// （30m 窗口丢 360s=20%，且响应无覆盖起点披露）。覆盖残余：窗口起点恰对齐
// 桶界时窗口内桶数=720+1，LIMIT 720 截掉最旧的部分桶——覆盖起点=窗口起点
// +≤1 桶宽（见 metricsHistoryBuckets 注释）。
func bucketSecondsFor(windowSeconds int64) int64 {
	if windowSeconds <= 0 {
		return 1
	}
	bucket := (windowSeconds + int64(metricsHistoryBuckets) - 1) / int64(metricsHistoryBuckets)
	if bucket < 1 {
		bucket = 1
	}
	return bucket
}

// metricsHistoryRange 把规则历史端点的 range 参数解析为 (SQLite modifier,
// 桶宽秒数, 桶数)。桶宽由 parseMetricsInterval 的窗口秒数单源派生
// （窗口秒数/桶数）——7d 曾与 GetMetricsHistory 各写一份桶宽
// （900s vs 840s），同一时间窗在两个端点返回不同粒度的序列，前端叠图/对账
// 失真。支持集固定 1h/6h/24h/7d（缺省 24h），非法值回退默认。
func metricsHistoryRange(value string) (string, int, int) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "1h", "6h", "24h", "7d":
	default:
		normalized = "24h"
	}
	modifier, seconds := parseMetricsInterval(normalized)
	return modifier, int(bucketSecondsFor(seconds)), metricsHistoryBuckets
}

// metricHistoryRow 是两条历史端点共用的「每桶末行样本」行形状（timestamp
// 统一解析为 UTC）。Blocked 仅规则端点 SQL 返回（全局分支不查该列，保持 0）。
type metricHistoryRow struct {
	Timestamp time.Time
	Requests  int64
	Status2xx int64
	Status3xx int64
	Status4xx int64
	Status5xx int64
	Blocked   int64
	BytesIn   int64
	BytesOut  int64
}

// errMetricsHistoryTimestamp 标记「行时间戳解析失败」——两条历史端点对该
// 失败的固定文案与查询/扫描失败不同（解析历史指标时间失败 vs 读取…失败），
// 单源 helper 以哨兵区分，端点按 errors.Is 分派文案。
var errMetricsHistoryTimestamp = errors.New("历史指标时间戳解析失败")

// queryMetricsHistory 是两条历史端点共用的查询/扫描/时间解析单源（此前逐字
// 重复两份半——规则端点、全局分支各写一份 9/8 列 Scan 与同款解析，列清单与
// 错误分支的漂移无门禁可查）。端点只提供 SQL 片段与参数：是否 rule_id 过滤、
// 是否含 requests_blocked、全局分支先按 timestamp SUM；行采样语义（每桶末行、
// LIMIT 截断、升序输出）由 SQL 保证。
func queryMetricsHistory(ctx context.Context, metricsDB *sql.DB, query string, args []any, withBlocked bool) ([]metricHistoryRow, error) {
	rows, err := metricsDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]metricHistoryRow, 0)
	for rows.Next() {
		var r metricHistoryRow
		var ts string
		var scanErr error
		if withBlocked {
			scanErr = rows.Scan(&ts, &r.Requests, &r.Status2xx, &r.Status3xx, &r.Status4xx, &r.Status5xx, &r.Blocked, &r.BytesIn, &r.BytesOut)
		} else {
			scanErr = rows.Scan(&ts, &r.Requests, &r.Status2xx, &r.Status3xx, &r.Status4xx, &r.Status5xx, &r.BytesIn, &r.BytesOut)
		}
		if scanErr != nil {
			return nil, scanErr
		}
		parsed, err := time.ParseInLocation("2006-01-02 15:04:05", ts, time.UTC)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errMetricsHistoryTimestamp, err)
		}
		r.Timestamp = parsed
		out = append(out, r)
	}
	return out, rows.Err()
}

// respondMetricsHistoryError 两条历史端点共用的失败出口：时间戳解析失败与
// 读取失败的固定文案分派（两措辞此前逐分支手写，同族漂移由单源消除）。
func respondMetricsHistoryError(c *gin.Context, readMessage string, err error) {
	if errors.Is(err, errMetricsHistoryTimestamp) {
		writeInternalError(c, http.StatusInternalServerError, "解析历史指标时间失败", err)
		return
	}
	writeInternalError(c, http.StatusInternalServerError, readMessage, err)
}

// GetRuleMetricsHistory returns cumulative history rows for one HTTP rule
// within the requested range (1h/6h/24h/7d). TCP rules have no per-rule
// traffic counters from caddy-l4 and return an empty list with a note.
func (h *Handlers) GetRuleMetricsHistory(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	var protocol string
	database := db.DB
	if database == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库未初始化"})
		return
	}
	if err := database.QueryRowContext(c.Request.Context(), "SELECT COALESCE(protocol,'') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&protocol); dbQueryNotFound(c, err, "规则不存在", "GetRuleMetricsHistory query rule") {
		return
	}
	if protocol != "http" {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"protocol": protocol, "supported": false, "rows": []any{}}})
		return
	}
	modifier, bucketSeconds, bucketCount := metricsHistoryRange(c.DefaultQuery("range", "24h"))
	metricsDB := db.MetricsDB
	if metricsDB == nil {
		// MetricsDB 未装配（单测/嵌入形态）不得
		// nil-deref panic——对齐家族（GetIPEventCount/GetRuleStageStats）
		// 返回空数据 200。
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"protocol": protocol, "supported": true, "bucket_interval_seconds": bucketSeconds, "rows": []any{}}})
		return
	}
	historyRows, err := queryMetricsHistory(c.Request.Context(), metricsDB, `
		WITH ranked AS (
			SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ? AS bucket,
			       requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, requests_blocked, bytes_in, bytes_out,
			       ROW_NUMBER() OVER (
				   PARTITION BY CAST(strftime('%s', timestamp) AS INTEGER) / ?
				   ORDER BY timestamp DESC, id DESC
			   ) AS sample_rank
			FROM metrics_history
			WHERE rule_id = ? AND timestamp > datetime('now', ?)
		), recent AS (
			SELECT bucket, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, requests_blocked, bytes_in, bytes_out
			FROM ranked WHERE sample_rank = 1 ORDER BY bucket DESC LIMIT ?
		)
		SELECT datetime(bucket * ?, 'unixepoch'), requests_total, requests_2xx, requests_3xx,
		       requests_4xx, requests_5xx, requests_blocked, bytes_in, bytes_out
		FROM recent ORDER BY bucket
	`, []any{bucketSeconds, bucketSeconds, caddyID, modifier, bucketCount, bucketSeconds}, true)
	if err != nil {
		respondMetricsHistoryError(c, "读取历史指标失败", err)
		return
	}
	type row struct {
		Timestamp string `json:"timestamp"`
		Requests  int64  `json:"requests_total"`
		Status2xx int64  `json:"requests_2xx"`
		Status3xx int64  `json:"requests_3xx"`
		Status4xx int64  `json:"requests_4xx"`
		Status5xx int64  `json:"requests_5xx"`
		Blocked   int64  `json:"requests_blocked"`
		BytesIn   int64  `json:"bytes_in"`
		BytesOut  int64  `json:"bytes_out"`
	}
	result := make([]row, 0, len(historyRows))
	for _, r := range historyRows {
		// 统一口径：返回裸 UTC 字符串，由前端 formatDate 按配置时区转换
		// （与 /metrics/history 的 RFC3339 UTC 及其它列表端点一致）。
		result = append(result, row{
			Timestamp: r.Timestamp.UTC().Format("2006-01-02 15:04:05"),
			Requests:  r.Requests,
			Status2xx: r.Status2xx,
			Status3xx: r.Status3xx,
			Status4xx: r.Status4xx,
			Status5xx: r.Status5xx,
			Blocked:   r.Blocked,
			BytesIn:   r.BytesIn,
			BytesOut:  r.BytesOut,
		})
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"protocol": protocol, "supported": true, "bucket_interval_seconds": bucketSeconds, "rows": result}})
}

func (h *Handlers) GetMetricsHistory(c *gin.Context) {
	ruleID := c.Query("rule_id")
	rawInterval := c.DefaultQuery("interval", "1h")
	// modifier 与窗口秒数取自同一解析（parseMetricsInterval），
	// 杜绝双解析器漂移。
	interval, intervalSeconds := parseMetricsInterval(rawInterval)
	// 分桶上限——镜像 get_rule_metrics_history 的窗口
	// 函数范式（每桶取末行样本，桶数 ≤720）。此前无上限无分桶：默认配置
	// 7 天窗 30s 间隔可达 ~2 万行 ≈2.5MB 一次性返回（5s 间隔可达 12 万行）。
	// 桶宽上取整（单源 bucketSecondsFor）：窗口含分钟级取值时必须全覆盖，
	// 720 桶 × 向下取整桶宽会静默丢弃最旧一段。
	bucketSeconds := bucketSecondsFor(intervalSeconds)

	metricsDB := db.MetricsDB
	if metricsDB == nil {
		// 未装配形态返回空列表 `[]`（同
		// 空结果形态），不得 nil-deref panic。
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: []any{}})
		return
	}

	// 查询/扫描/时间解析经 queryMetricsHistory 单源；本端点只选分支（单规则
	// 过滤 vs 全站 per_ts SUM 聚合）与固定文案（读取指标历史失败）。
	type MetricRow struct {
		Timestamp     time.Time `json:"timestamp"`
		RequestsTotal int64     `json:"requests_total"`
		Status2xx     int64     `json:"status_2xx"`
		Status3xx     int64     `json:"status_3xx"`
		Status4xx     int64     `json:"status_4xx"`
		Status5xx     int64     `json:"status_5xx"`
		BytesIn       int64     `json:"bytes_in"`
		BytesOut      int64     `json:"bytes_out"`
	}
	query := `
		WITH ranked AS (
			SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ? AS bucket,
			       requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out,
			       ROW_NUMBER() OVER (
				   PARTITION BY CAST(strftime('%s', timestamp) AS INTEGER) / ?
				   ORDER BY timestamp DESC, id DESC
			   ) AS sample_rank
			FROM metrics_history
			WHERE rule_id = ? AND timestamp > datetime('now', ?)
		)
		SELECT datetime(bucket * ?, 'unixepoch'), requests_total, requests_2xx, requests_3xx,
		       requests_4xx, requests_5xx, bytes_in, bytes_out
		FROM (SELECT bucket, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out
		      FROM ranked WHERE sample_rank = 1 ORDER BY bucket DESC LIMIT ?) ORDER BY bucket`
	args := []any{bucketSeconds, bucketSeconds, ruleID, interval, bucketSeconds, metricsHistoryBuckets}
	if ruleID == "" {
		query = `
			WITH per_ts AS (
				SELECT timestamp, SUM(requests_total) AS requests_total, SUM(requests_2xx) AS requests_2xx,
				       SUM(requests_3xx) AS requests_3xx, SUM(requests_4xx) AS requests_4xx,
				       SUM(requests_5xx) AS requests_5xx, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out
				FROM metrics_history
				WHERE rule_id IS NULL AND timestamp > datetime('now', ?)
				GROUP BY timestamp
			), ranked AS (
				SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ? AS bucket,
				       requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out,
				       ROW_NUMBER() OVER (
					   PARTITION BY CAST(strftime('%s', timestamp) AS INTEGER) / ?
					   ORDER BY timestamp DESC
				   ) AS sample_rank
				FROM per_ts
			)
			SELECT datetime(bucket * ?, 'unixepoch'), requests_total, requests_2xx, requests_3xx,
			       requests_4xx, requests_5xx, bytes_in, bytes_out
			FROM (SELECT bucket, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out
			      FROM ranked WHERE sample_rank = 1 ORDER BY bucket DESC LIMIT ?) ORDER BY bucket`
		args = []any{interval, bucketSeconds, bucketSeconds, bucketSeconds, metricsHistoryBuckets}
	}

	historyRows, err := queryMetricsHistory(c.Request.Context(), metricsDB, query, args, false)
	if err != nil {
		// 查询失败是本端点最频繁的读库故障路径，必须与同端点其余三个失败
		// 分支（Scan/时间解析/rows.Err）共用固定文案 + 日志留痕。
		respondMetricsHistoryError(c, "读取指标历史失败", err)
		return
	}

	// 空结果必须是 []（同族列表端点与 OpenAPI 契约）——nil slice
	// 序列化为 null 会让客户端额外处理 null 形状。
	metrics := make([]MetricRow, 0, len(historyRows))
	for _, r := range historyRows {
		metrics = append(metrics, MetricRow{
			Timestamp:     r.Timestamp,
			RequestsTotal: r.Requests,
			Status2xx:     r.Status2xx,
			Status3xx:     r.Status3xx,
			Status4xx:     r.Status4xx,
			Status5xx:     r.Status5xx,
			BytesIn:       r.BytesIn,
			BytesOut:      r.BytesOut,
		})
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func (h *Handlers) GetCaddyMetrics(c *gin.Context) {
	body, err := h.caddyMetricsSnapshot(c.Request.Context(), true)
	if err != nil {
		caddyMetricsError(c, err)
		return
	}
	metrics, err := parsePrometheusMetrics(string(body))
	if err != nil {
		caddyMetricsError(c, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func (h *Handlers) GetHostMetrics(c *gin.Context) {
	body, err := h.caddyMetricsSnapshot(c.Request.Context(), true)
	if err != nil {
		caddyMetricsError(c, err)
		return
	}
	metrics, err := parseHostMetrics(string(body))
	if err != nil {
		caddyMetricsError(c, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func loadRuleUpstreams(ctx context.Context, ruleID string) ([]models.Upstream, error) {
	database := db.DB
	if database == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	rows, err := database.QueryContext(ctx, `
		SELECT COALESCE(id,0), COALESCE(rule_id,''), COALESCE(host,''), COALESCE(port,0), COALESCE(weight,0),
		       COALESCE(dynamic_dns,0), COALESCE(enabled,0), COALESCE(protocol,''),
		       COALESCE(max_connections,0)
		FROM upstreams u WHERE rule_id = ? AND `+services.UpstreamEnabledSQLPredicate+`
	`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var upstreams []models.Upstream
	for rows.Next() {
		var u models.Upstream
		if err := rows.Scan(&u.ID, &u.RuleID, &u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections); err != nil {
			return nil, err
		}
		upstreams = append(upstreams, u)
	}
	return upstreams, rows.Err()
}

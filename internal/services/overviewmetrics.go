package services

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rateLimit429CountMetric 是 Caddy 按 host/handler/code 暴露的请求时长直方图计数序列；
// 限流口径：仅按 code="429" 过滤、含上游自返 429，handler 标签不参与判定
// （见 parseRateLimit429CountsByServer 内联说明）。
const rateLimit429CountMetric = `caddy_http_request_duration_seconds_count{`

// overviewMetricsHTTPClient 与采集链共用 caddyMetricsScrapeTimeout：同一
// CaddyMetricsURL、同一 16MB 正文上限，超时预算必须一致（理由见该常量）。
// var 供测试注入桩 Transport。
var overviewMetricsHTTPClient = &http.Client{Timeout: caddyMetricsScrapeTimeout}

// overviewMetricsCacheTTL 概览指标抓取的进程内缓存窗口：仪表盘
// 三个调用点（限流卡片/单规则 stage-stats）各自抓取一次是重复放大面；
// 5s 窗口内同一 metricsURL 复用同一份解析结果。var 供测试缩短/复位。
var overviewMetricsCacheTTL = 5 * time.Second

// overviewMetricsCall 单飞（single-flight）在途调用：并发请求同一 URL 时
// 只抓一次，其余等待同一结果（失败一并传播，不缓存）。
type overviewMetricsCall struct {
	done   chan struct{}
	blocks []RateLimitHostBlocks
	// hostServer 是同一份抓取的 (host, server) 维度视图（同域多端口限流
	// chip 区分端口）。
	hostServer []RateLimitHostServerBlocks
	err        error
	// generation 是该抓取发起时的缓存代际：完成时若代际已变（期间
	// InvalidateOverviewMetricsCache 执行过，如 Caddy /load 成功），抓到的
	// 是重载前 registry 的计数——不得回填到新代际缓存，否则作废形同无效。
	generation uint64
}

var overviewMetricsCache struct {
	sync.Mutex
	entries    map[string]overviewMetricsCacheEntry
	inflight   map[string]*overviewMetricsCall
	generation uint64
}

type overviewMetricsCacheEntry struct {
	blocks     []RateLimitHostBlocks
	hostServer []RateLimitHostServerBlocks
	expiresAt  time.Time
}

// InvalidateOverviewMetricsCache 丢弃 /metrics 抓取缓存（生产写点：Caddy
// /load 成功）。任意成功重载都会重建 Caddy registry——限流 429 计数归零，
// 而 5s 缓存不感知会让限流卡片/单规则 stage-stats 在窗口内继续显示重载前的
// 累计值，与「计数据自最近一次重载以来累计」的声明口径矛盾。
func InvalidateOverviewMetricsCache() {
	overviewMetricsCache.Lock()
	defer overviewMetricsCache.Unlock()
	overviewMetricsCache.entries = nil
	overviewMetricsCache.inflight = nil
	// 代际自增：作废瞬间仍在途的抓取属于旧代际（抓的是重载前计数），
	// 完成时按代际不匹配丢弃，不得回填缓存。
	overviewMetricsCache.generation++
}

// resetOverviewMetricsCacheForTest 仅供测试隔离。
func resetOverviewMetricsCacheForTest() {
	overviewMetricsCache.Lock()
	defer overviewMetricsCache.Unlock()
	overviewMetricsCache.entries = nil
	overviewMetricsCache.inflight = nil
}

// ScrapeRateLimitBlocks 抓取 Caddy admin /metrics 并按站点聚合 429 限流拦截计数。
// 计数自最近一次 Caddy 配置重载以来累计（/load 重建 registry 即归零；进程重启
// 同），非按天口径。任何抓取/解析失败
// 都返回 error，由调用方决定降级策略，绝不静默返回空列表。
// 5s TTL 进程内缓存 + 同 URL 单飞——失败轮不写缓存（下一请求重试），
// 返回副本避免调用方改动共享切片。
// overviewMetricsWaiterHook 单飞等待方的测试观测缝（生产恒 nil）。
var overviewMetricsWaiterHook func()

func ScrapeRateLimitBlocks(metricsURL string) ([]RateLimitHostBlocks, error) {
	blocks, _, err := scrapeOverviewMetrics(metricsURL)
	return blocks, err
}

// ScrapeRateLimitBlocksByHostServer 与 ScrapeRateLimitBlocks 同源同缓存，但保留
// Caddy 的 server 标签（http_<port>）：同域名多端口部署下，按 host 求和会把各
// 端口的限流计数累加到每条规则的 chip 上（单规则口径被放大成多条之和）。
// 返回副本；排序=计数降序、host/server 升序。
func ScrapeRateLimitBlocksByHostServer(metricsURL string) ([]RateLimitHostServerBlocks, error) {
	_, byServer, err := scrapeOverviewMetrics(metricsURL)
	return byServer, err
}

// scrapeOverviewMetrics 抓取一次 /metrics 并产出两个维度视图（host 与
// host+server）：两个消费端点共享同一份 5s 缓存与单飞，不对 Caddy 放大抓取。
func scrapeOverviewMetrics(metricsURL string) ([]RateLimitHostBlocks, []RateLimitHostServerBlocks, error) {
	overviewMetricsCache.Lock()
	if entry, ok := overviewMetricsCache.entries[metricsURL]; ok && time.Now().Before(entry.expiresAt) {
		blocks := cloneRateLimitBlocks(entry.blocks)
		byServer := cloneRateLimitHostServerBlocks(entry.hostServer)
		overviewMetricsCache.Unlock()
		return blocks, byServer, nil
	}
	if call, ok := overviewMetricsCache.inflight[metricsURL]; ok {
		overviewMetricsCache.Unlock()
		// overviewMetricsWaiterHook 测试缝：等待方已确定进入单飞等待（生产恒
		// nil）。测试用它替代 `time.Sleep(50ms)` 猜等待方是否就位——sleep 在
		// 慢调度下会让等待方自行发起抓取（单飞未覆盖），用例反而变脆。
		if hook := overviewMetricsWaiterHook; hook != nil {
			hook()
		}
		<-call.done
		if call.err != nil {
			return nil, nil, call.err
		}
		return cloneRateLimitBlocks(call.blocks), cloneRateLimitHostServerBlocks(call.hostServer), nil
	}
	if overviewMetricsCache.inflight == nil {
		overviewMetricsCache.inflight = map[string]*overviewMetricsCall{}
	}
	call := &overviewMetricsCall{done: make(chan struct{}), generation: overviewMetricsCache.generation}
	overviewMetricsCache.inflight[metricsURL] = call
	overviewMetricsCache.Unlock()

	// 单飞清理必须 defer：抓取 panic（解析器越界等）时 inflight 条目残留会让
	// 同 URL 的后续请求全部永久阻塞在 <-call.done——一个坏响应把限流卡片钉死
	// 到进程重启。panic 照常向上传播（中间件恢复口径不变），等待方收到 error
	// 而非挂死。
	defer func() {
		if r := recover(); r != nil {
			overviewMetricsCache.Lock()
			call.err = fmt.Errorf("抓取限流指标 panic: %v", r)
			delete(overviewMetricsCache.inflight, metricsURL)
			overviewMetricsCache.Unlock()
			close(call.done)
			panic(r)
		}
	}()

	blocks, byServer, err := scrapeRateLimitBlocksUncached(metricsURL)

	overviewMetricsCache.Lock()
	call.blocks, call.hostServer, call.err = blocks, byServer, err
	delete(overviewMetricsCache.inflight, metricsURL)
	// 代际校验：作废（重载）后完成的旧代际抓取只回给本轮调用方，不入缓存
	// ——否则下一次请求在 TTL 内再次读到重载前的累计计数。
	if err == nil && overviewMetricsCache.generation == call.generation {
		if overviewMetricsCache.entries == nil {
			overviewMetricsCache.entries = map[string]overviewMetricsCacheEntry{}
		}
		overviewMetricsCache.entries[metricsURL] = overviewMetricsCacheEntry{
			blocks:     blocks,
			hostServer: byServer,
			expiresAt:  time.Now().Add(overviewMetricsCacheTTL),
		}
	}
	overviewMetricsCache.Unlock()
	close(call.done)
	if err != nil {
		return nil, nil, err
	}
	return cloneRateLimitBlocks(blocks), cloneRateLimitHostServerBlocks(byServer), nil
}

// cloneRateLimitBlocks 复制并按非 nil 空切片返回：JSON 序列化空结果为 []，
// 前端可直接读 hosts.length（nil 会编码成 null 导致渲染崩溃）。
func cloneRateLimitBlocks(src []RateLimitHostBlocks) []RateLimitHostBlocks {
	out := make([]RateLimitHostBlocks, len(src))
	copy(out, src)
	return out
}

// cloneRateLimitHostServerBlocks 同 cloneRateLimitBlocks（host+server 视图）。
func cloneRateLimitHostServerBlocks(src []RateLimitHostServerBlocks) []RateLimitHostServerBlocks {
	out := make([]RateLimitHostServerBlocks, len(src))
	copy(out, src)
	return out
}

// RateLimitHostBlocks 单个站点的限流拦截累计次数。
type RateLimitHostBlocks struct {
	Host  string  `json:"host"`
	Count float64 `json:"count"`
}

// RateLimitHostServerBlocks 单站点单监听端口的限流拦截累计次数。
// Server 是 Caddy 的 server 分组名（本系统恒为 http_<listen_port>）：同域名
// 多端口部署下按 host 求和会把各端口计数累加到每条规则上。
type RateLimitHostServerBlocks struct {
	Host   string  `json:"host"`
	Server string  `json:"server"`
	Count  float64 `json:"count"`
}

// rateLimitHostServerKey 是解析期的聚合键（未导出的中间形态）。
type rateLimitHostServerKey struct {
	host   string
	server string
}

// overviewMetricsReadLimit 是 Caddy /metrics 响应体的读取上限：指标基数异常膨胀
// 时防止大块内存分配拖垮仪表盘请求。
const overviewMetricsReadLimit = int64(16 << 20)

// scrapeRateLimitBlocksUncached 抓取 Caddy admin /metrics 并按站点聚合 429 限流
// 拦截计数（缓存/单飞外壳见 scrapeOverviewMetrics）。计数自最近一次 Caddy 配置
// 重载以来累计（/load 重建 registry 即归零；进程重启同），非按天口径。任何
// 抓取/解析失败都返回 error，由调用方决定降级策略，绝不静默返回空列表。
// 同一份响应解析出 host 与 host+server 两个视图（两个消费端点各取所需）。
func scrapeRateLimitBlocksUncached(metricsURL string) ([]RateLimitHostBlocks, []RateLimitHostServerBlocks, error) {
	resp, err := overviewMetricsHTTPClient.Get(metricsURL)
	if err != nil {
		return nil, nil, fmt.Errorf("采集 Caddy 限流指标失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, nil, fmt.Errorf("Caddy 指标接口返回状态码 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, overviewMetricsReadLimit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("读取 Caddy 指标响应失败: %w", err)
	}
	if int64(len(body)) > overviewMetricsReadLimit {
		return nil, nil, fmt.Errorf("Caddy 指标响应超过 %d 字节上限", overviewMetricsReadLimit)
	}
	byServer := parseRateLimit429CountsByServer(string(body))
	hostCounts := rateLimit429HostCounts(byServer)
	blocks := make([]RateLimitHostBlocks, 0, len(hostCounts))
	for host, count := range hostCounts {
		blocks = append(blocks, RateLimitHostBlocks{Host: host, Count: count})
	}
	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].Count != blocks[j].Count {
			return blocks[i].Count > blocks[j].Count
		}
		return blocks[i].Host < blocks[j].Host
	})
	serverBlocks := make([]RateLimitHostServerBlocks, 0, len(byServer))
	for key, count := range byServer {
		serverBlocks = append(serverBlocks, RateLimitHostServerBlocks{Host: key.host, Server: key.server, Count: count})
	}
	sort.Slice(serverBlocks, func(i, j int) bool {
		if serverBlocks[i].Count != serverBlocks[j].Count {
			return serverBlocks[i].Count > serverBlocks[j].Count
		}
		if serverBlocks[i].Host != serverBlocks[j].Host {
			return serverBlocks[i].Host < serverBlocks[j].Host
		}
		return serverBlocks[i].Server < serverBlocks[j].Server
	})
	return blocks, serverBlocks, nil
}

// NormalizeMetricsHost 统一 host 标签归一：Caddy metrics 的 host
// 标签是原文 r.Host（可能含 :8080 / [::1]:8443），而 lb_rules.domain 不带端口
// ——不归一会让带端口部署的规则限流计数恒 0。IPv6 方括号在比较域一并剥除。
func NormalizeMetricsHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if parsed, _, err := net.SplitHostPort(h); err == nil {
		h = parsed
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return h
}

// parseRateLimit429CountsByServer 从 Prometheus 文本中挑出
// caddy_http_request_duration_seconds_count{code="429",host=...} 序列并按
// (host, server) 聚合：server 是 Caddy 的监听端口分组名（本系统恒为
// http_<listen_port>），同域多端口部署下必须与 host 一起作为键——只按 host
// 求和会让每条规则的限流 chip 拿到同域全部端口的合计（各自被放大）。
// 站点级卡片按 host 求和（rateLimit429HostCounts）。
// 口径：仅按 code=429 过滤、含上游自返 429，handler 标签恒不命中（见下方内联
// 注释）；抓取失败由调用方返回 500。
// 注释行、其他指标、_bucket/_sum 序列、缺 host 标签或数值非法的行一律跳过。
func parseRateLimit429CountsByServer(body string) map[rateLimitHostServerKey]float64 {
	counts := map[rateLimitHostServerKey]float64{}
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		// geoip 透传路由与主/路径路由会为同一请求各注入一条
		// caddy_http_request_duration_seconds_count 序列（含 code="429"）——
		// 不跳过会让启用地域拦截的站点限流计数约 2 倍虚高，且与采集链/实时
		// 指标（同口径已剔除）互相矛盾。
		if IsGeoIPPassSeries(line) {
			continue
		}
		if !strings.HasPrefix(line, rateLimit429CountMetric) {
			continue
		}
		braceEnd := strings.LastIndexByte(line, '}')
		if braceEnd < 0 {
			continue
		}
		labels := parsePromLabelPairs(line[len(rateLimit429CountMetric):braceEnd])
		// 仅按 code=429 过滤：Caddy metrics 的 handler 标签取主路由链首处理器
		//（routes.go:174），注入后恒为 headers、错误路由响应亦继承主路由
		// 标签——handler="rate_limit" 永不命中。本栈限流拦截自 v2.2.3 起恒 429
		//（buildRateLimitErrorRoute），上游自返 429 无法区分、如实纳入计数
		//（卡片文案已标注口径）。
		if labels["code"] != "429" {
			continue
		}
		host := NormalizeMetricsHost(labels["host"])
		if host == "" {
			continue
		}
		fields := strings.Fields(line[braceEnd+1:])
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		counts[rateLimitHostServerKey{host: host, server: labels["server"]}] += value
	}
	return counts
}

// rateLimit429HostCounts 是站点级视图（host 求和），由 host+server 解析结果
// 聚合而来——过滤规则、归一、数值解析与站点聚合只有一份实现，抓取路径与
// 测试断言消费同一函数，避免未来只改一侧造成生产/断言静默分叉。
func rateLimit429HostCounts(byServer map[rateLimitHostServerKey]float64) map[string]float64 {
	counts := make(map[string]float64, len(byServer))
	for key, value := range byServer {
		counts[key.host] += value
	}
	return counts
}

// parsePromLabelPairs 解析 Prometheus 标签列表（key="value",...），容忍值内的
// 逗号；残缺片段直接丢弃。
// 转义按 exposition format 规范解码：`\\`→`\`、`\"`→`"`、
// `\n`→换行。规范未定义的转义（如 `\t`）原样保留（反斜杠+字符）——此前
// 实现直接吞掉反斜杠写下一字节，`\n` 被解析成字面 n（值失真），且静默丢字节。
func parsePromLabelPairs(s string) map[string]string {
	labels := map[string]string{}
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || eq+1 >= len(s) || s[eq+1] != '"' {
			return labels
		}
		key := s[:eq]
		s = s[eq+2:]
		var value strings.Builder
		i := 0
		for i < len(s) && s[i] != '"' {
			if s[i] == '\\' && i+1 < len(s) {
				switch s[i+1] {
				case '\\':
					value.WriteByte('\\')
				case '"':
					value.WriteByte('"')
				case 'n':
					value.WriteByte('\n')
				default:
					value.WriteByte('\\')
					value.WriteByte(s[i+1])
				}
				i += 2
				continue
			}
			value.WriteByte(s[i])
			i++
		}
		if i >= len(s) {
			return labels
		}
		labels[key] = value.String()
		s = s[i+1:]
		if comma := strings.IndexByte(s, ','); comma >= 0 {
			s = s[comma+1:]
		} else {
			return labels
		}
	}
	return labels
}

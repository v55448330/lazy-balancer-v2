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
// （见 parseRateLimit429Counts 内联说明）。
const rateLimit429CountMetric = `caddy_http_request_duration_seconds_count{`

var overviewMetricsHTTPClient = &http.Client{Timeout: 5 * time.Second}

// overviewMetricsCacheTTL 概览指标抓取的进程内缓存窗口（U08-F06）：仪表盘
// 三个调用点（限流卡片/单规则 stage-stats）各自抓取一次是重复放大面；
// 5s 窗口内同一 metricsURL 复用同一份解析结果。var 供测试缩短/复位。
var overviewMetricsCacheTTL = 5 * time.Second

// overviewMetricsCall 单飞（single-flight）在途调用：并发请求同一 URL 时
// 只抓一次，其余等待同一结果（失败一并传播，不缓存）。
type overviewMetricsCall struct {
	done   chan struct{}
	blocks []RateLimitHostBlocks
	err    error
}

var overviewMetricsCache struct {
	sync.Mutex
	entries  map[string]overviewMetricsCacheEntry
	inflight map[string]*overviewMetricsCall
}

type overviewMetricsCacheEntry struct {
	blocks    []RateLimitHostBlocks
	expiresAt time.Time
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
// U08-F06：5s TTL 进程内缓存 + 同 URL 单飞——失败轮不写缓存（下一请求重试），
// 返回副本避免调用方改动共享切片。
func ScrapeRateLimitBlocks(metricsURL string) ([]RateLimitHostBlocks, error) {
	overviewMetricsCache.Lock()
	if entry, ok := overviewMetricsCache.entries[metricsURL]; ok && time.Now().Before(entry.expiresAt) {
		blocks := cloneRateLimitBlocks(entry.blocks)
		overviewMetricsCache.Unlock()
		return blocks, nil
	}
	if call, ok := overviewMetricsCache.inflight[metricsURL]; ok {
		overviewMetricsCache.Unlock()
		<-call.done
		if call.err != nil {
			return nil, call.err
		}
		return cloneRateLimitBlocks(call.blocks), nil
	}
	if overviewMetricsCache.inflight == nil {
		overviewMetricsCache.inflight = map[string]*overviewMetricsCall{}
	}
	call := &overviewMetricsCall{done: make(chan struct{})}
	overviewMetricsCache.inflight[metricsURL] = call
	overviewMetricsCache.Unlock()

	blocks, err := scrapeRateLimitBlocksUncached(metricsURL)

	overviewMetricsCache.Lock()
	call.blocks, call.err = blocks, err
	delete(overviewMetricsCache.inflight, metricsURL)
	if err == nil {
		if overviewMetricsCache.entries == nil {
			overviewMetricsCache.entries = map[string]overviewMetricsCacheEntry{}
		}
		overviewMetricsCache.entries[metricsURL] = overviewMetricsCacheEntry{
			blocks:    blocks,
			expiresAt: time.Now().Add(overviewMetricsCacheTTL),
		}
	}
	overviewMetricsCache.Unlock()
	close(call.done)
	if err != nil {
		return nil, err
	}
	return cloneRateLimitBlocks(blocks), nil
}

// cloneRateLimitBlocks 复制并按非 nil 空切片返回：JSON 序列化空结果为 []，
// 前端可直接读 hosts.length（nil 会编码成 null 导致渲染崩溃）。
func cloneRateLimitBlocks(src []RateLimitHostBlocks) []RateLimitHostBlocks {
	out := make([]RateLimitHostBlocks, len(src))
	copy(out, src)
	return out
}

// scrapeRateLimitBlocksUncached 实际抓取与解析（缓存/单飞外壳见
// ScrapeRateLimitBlocks）。

// RateLimitHostBlocks 单个站点的限流拦截累计次数。
type RateLimitHostBlocks struct {
	Host  string  `json:"host"`
	Count float64 `json:"count"`
}

// overviewMetricsReadLimit 是 Caddy /metrics 响应体的读取上限：指标基数异常膨胀
// 时防止大块内存分配拖垮仪表盘请求（R34 H）。
const overviewMetricsReadLimit = int64(16 << 20)

// scrapeRateLimitBlocksUncached 抓取 Caddy admin /metrics 并按站点聚合 429 限流
// 拦截计数（缓存/单飞外壳见 ScrapeRateLimitBlocks）。计数自最近一次 Caddy 配置
// 重载以来累计（/load 重建 registry 即归零；进程重启同），非按天口径。任何
// 抓取/解析失败都返回 error，由调用方决定降级策略，绝不静默返回空列表。
func scrapeRateLimitBlocksUncached(metricsURL string) ([]RateLimitHostBlocks, error) {
	resp, err := overviewMetricsHTTPClient.Get(metricsURL)
	if err != nil {
		return nil, fmt.Errorf("采集 Caddy 限流指标失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("Caddy 指标接口返回状态码 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, overviewMetricsReadLimit+1))
	if err != nil {
		return nil, fmt.Errorf("读取 Caddy 指标响应失败: %w", err)
	}
	if int64(len(body)) > overviewMetricsReadLimit {
		return nil, fmt.Errorf("Caddy 指标响应超过 %d 字节上限", overviewMetricsReadLimit)
	}
	counts := parseRateLimit429Counts(string(body))
	blocks := make([]RateLimitHostBlocks, 0, len(counts))
	for host, count := range counts {
		blocks = append(blocks, RateLimitHostBlocks{Host: host, Count: count})
	}
	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].Count != blocks[j].Count {
			return blocks[i].Count > blocks[j].Count
		}
		return blocks[i].Host < blocks[j].Host
	})
	return blocks, nil
}

// parseRateLimit429Counts 从 Prometheus 文本中挑出
// caddy_http_request_duration_seconds_count{code="429",host=...} 序列并按 host
// 累加（同一 host 的不同 method/server 序列求和）。口径：仅按 code=429 过滤、
// 含上游自返 429，handler 标签恒不命中（见下方内联注释）；抓取失败由调用方
// 返回 500。
// 注释行、其他指标、_bucket/_sum 序列、缺 host 标签或数值非法的行一律跳过。
// NormalizeMetricsHost 统一 host 标签归一（L03-09）：Caddy metrics 的 host
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

func parseRateLimit429Counts(body string) map[string]float64 {
	counts := map[string]float64{}
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, rateLimit429CountMetric) {
			continue
		}
		braceEnd := strings.LastIndexByte(line, '}')
		if braceEnd < 0 {
			continue
		}
		labels := parsePromLabelPairs(line[len(rateLimit429CountMetric):braceEnd])
		// 仅按 code=429 过滤：Caddy metrics 的 handler 标签取主路由链首处理器
		//（routes.go:174），F3 注入后恒为 headers、错误路由响应亦继承主路由
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
		counts[host] += value
	}
	return counts
}

// parsePromLabelPairs 解析 Prometheus 标签列表（key="value",...），
// 容忍值内的转义引号与逗号；残缺片段直接丢弃。
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
				i++
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

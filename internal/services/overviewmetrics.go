package services

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// rateLimit429CountMetric 是 Caddy 按 host/handler/code 暴露的请求时长直方图计数序列；
// 限流拦截产生的 HTTP 429 会落在 handler="rate_limit" 的 _count 序列上。
const rateLimit429CountMetric = `caddy_http_request_duration_seconds_count{`

var overviewMetricsHTTPClient = &http.Client{Timeout: 5 * time.Second}

// RateLimitHostBlocks 单个站点的限流拦截累计次数。
type RateLimitHostBlocks struct {
	Host  string  `json:"host"`
	Count float64 `json:"count"`
}

// ScrapeRateLimitBlocks 抓取 Caddy admin /metrics 并按站点聚合 429 限流拦截计数。
// 计数自 Caddy 进程启动以来累计（重启归零），非按天口径。任何抓取/解析失败
// 都返回 error，由调用方决定降级策略，绝不静默返回空列表。
func ScrapeRateLimitBlocks(metricsURL string) ([]RateLimitHostBlocks, error) {
	resp, err := overviewMetricsHTTPClient.Get(metricsURL)
	if err != nil {
		return nil, fmt.Errorf("采集 Caddy 限流指标失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("Caddy 指标接口返回状态码 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 Caddy 指标响应失败: %w", err)
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
// caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host=...}
// 序列并按 host 累加（同一 host 的不同 method/server 序列求和）。
// 注释行、其他指标、_bucket/_sum 序列、缺 host 标签或数值非法的行一律跳过。
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
		if labels["code"] != "429" || labels["handler"] != "rate_limit" {
			continue
		}
		host := labels["host"]
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

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// cidrTokenRE / cidrTokenV6RE 通用 CIDR/裸 IP 提取（JSON/HTML 通用）。
var (
	cidrTokenRE   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)
	cidrTokenV6RE = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?:/\d{1,3})?\b`)
)

// parseCrawlerCIDRs 从任意 JSON/HTML 文本提取 CIDR 与裸 IP 并去重。
// U02-F01（第 78 轮）：JSON 源优先按结构解析 ipv4Prefix/ipv6Prefix（Google
// common-crawlers.json 携带大量 ipv6Prefix，旧纯 IPv4 词法把 IPv6 全丢弃）；
// 通用词法同时补 IPv6（冒号十六进制 + 可选 /len）；统一 netip 校验，裸 IP
// 归一 /32（IPv4）/ /128（IPv6），非法 token（版本号等）跳过。
func parseCrawlerCIDRs(body string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 64)
	add := func(tok string) {
		prefix, ok := normalizeCrawlerPrefixToken(strings.Trim(tok, " \t\r\n,;\"')"))
		if !ok {
			return
		}
		if _, dup := seen[prefix]; dup {
			return
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	// 1) 结构化字段（JSON 对象/数组递归；ipv4Prefix/ipv6Prefix 大小写不敏感）。
	var parsed any
	if json.Unmarshal([]byte(body), &parsed) == nil {
		collectCrawlerPrefixFields(parsed, add)
	}
	// 2) 通用词法（HTML/纯文本/未结构化 JSON）。
	for _, tok := range cidrTokenRE.FindAllString(body, -1) {
		add(tok)
	}
	for _, tok := range cidrTokenV6RE.FindAllString(body, -1) {
		add(tok)
	}
	return out
}

// collectCrawlerPrefixFields 递归收集 JSON 中的 ipv4Prefix/ipv6Prefix 字符串值。
func collectCrawlerPrefixFields(v any, add func(string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if sv, ok := val.(string); ok && (strings.EqualFold(k, "ipv4Prefix") || strings.EqualFold(k, "ipv6Prefix")) {
				add(sv)
				continue
			}
			collectCrawlerPrefixFields(val, add)
		}
	case []any:
		for _, item := range t {
			collectCrawlerPrefixFields(item, add)
		}
	}
}

// normalizeCrawlerPrefixToken 统一 CIDR/裸 IP 归一（掩码对齐、裸 IP 补长度）。
func normalizeCrawlerPrefixToken(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	if p, err := netip.ParsePrefix(tok); err == nil {
		return p.Masked().String(), true
	}
	addr, err := netip.ParseAddr(tok)
	if err != nil {
		return "", false
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits).String(), true
}

// crawlerFetchBody 下载源文本（ctx 取消可断；body 上限 16MB）。
func crawlerFetchBody(ctx context.Context, src crawlerSource) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "lazy-balancer-v2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// U02-F02：与 threatupdate 同口径——Content-Length 超限提前失败；读取
	// cap+1 后显式拒绝截断文本（旧实现把截断内容当合法文本返回，可能残留
	// 部分 CIDR 而「看似成功」，覆盖上次快照）。
	const crawlerBodyCap = 16 << 20
	if resp.ContentLength > crawlerBodyCap {
		return "", fmt.Errorf("响应体 %d 字节超过上限 %d", resp.ContentLength, crawlerBodyCap)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, crawlerBodyCap+1))
	if err != nil {
		return "", err
	}
	if len(body) > crawlerBodyCap {
		return "", fmt.Errorf("响应体超过上限 %d 字节，已拒绝（保留上次快照）", crawlerBodyCap)
	}
	return string(body), nil
}

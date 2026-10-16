package services

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"time"
)

// cidrTokenRE 通用 CIDR/裸 IP 提取（JSON/HTML 通用；裸 IP 归一 /32）。
var cidrTokenRE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)

// parseCrawlerCIDRs 从任意 JSON/HTML 文本提取 CIDR 与裸 IP（归一 /32）并去重。
// 裸 IP 解析失败（非合法 IP）跳过；超界掩码（>/32 或非数字）跳过。
func parseCrawlerCIDRs(body string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, tok := range cidrTokenRE.FindAllString(body, -1) {
		// 排除非 IP 数字串（如版本号 1.2.3.4.5）
		if _, err := netip.ParsePrefix(tok); err != nil {
			if _, aerr := netip.ParseAddr(tok); aerr == nil {
				tok += "/32"
			} else {
				continue
			}
		}
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	return out
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20+1))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

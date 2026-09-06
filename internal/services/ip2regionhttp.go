package services

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
)

var ip2RegionHTTPClient = &http.Client{Timeout: 60 * time.Second}

// ip2RegionDownloadClient 无 Client.Timeout——大文件下载仅由 ctx 15min 兜底，
// 避免 Client.Timeout 60s 短路读 body（50KB/s × 11MB ≈ 220s 必死）。
// tag 查询继续用 ip2RegionHTTPClient（轻请求需快速失败）。
var ip2RegionDownloadClient = &http.Client{}

// ip2RegionRepoSlug 是 ip2region 的 GitHub 仓库标识：直连 API 与代理
// releases/latest 共用。
const ip2RegionRepoSlug = "lionsoul2014/ip2region"

// ip2RegionLatestReleaseAPIURL 是 ip2region 最新版本的 GitHub API 直连地址；
// var 以便测试指向 httptest 服务（R57）。
var ip2RegionLatestReleaseAPIURL = "https://api.github.com/repos/lionsoul2014/ip2region/releases/latest"

// defaultFetchIP2RegionLatestTag 查询 ip2region 最新版本：先直连
// api.github.com（快路径不变），仅在 403 限流与传输类失败（Do() 错误、5xx、
// 读体中断）时经 GitHub 加速代理（github_proxy_url 白名单）回退查询
// releases/latest 页面；其余 4xx 与 tag 解析失败不重试。两路均失败时错误同时
// 点名两个尝试过的 URL（R57，口径同 defaultFetchCRSLatestTag）。
func defaultFetchIP2RegionLatestTag(ctx context.Context) (string, error) {
	tag, err, transport := fetchGitHubLatestTagFromAPI(ctx, ip2RegionHTTPClient, ip2RegionLatestReleaseAPIURL)
	if err == nil {
		return tag, nil
	}
	if !transport {
		return "", fmt.Errorf("查询 ip2region 最新版本: %w", err)
	}
	proxyTag, proxyErr := fetchGitHubLatestTagViaProxy(ctx, ip2RegionRepoSlug)
	if proxyErr != nil {
		return "", fmt.Errorf("查询 ip2region 最新版本: 直连 %s 失败: %v；经代理 %s 重试仍失败: %v",
			ip2RegionLatestReleaseAPIURL, err, ghProxied(gitHubReleasesLatestURL(ip2RegionRepoSlug)), proxyErr)
	}
	return proxyTag, nil
}

// ip2RegionXDBSourceURL 是 ip2region xdb 的真实来源 URL（含版本 tag，作为完整
// 性基线的键）：下载函数与安装校验后的记录调用共用，避免 URL 构造分叉。
func ip2RegionXDBSourceURL(tag string) string {
	return ghProxied("https://raw.githubusercontent.com/lionsoul2014/ip2region/" + tag + "/data/ip2region_v4.xdb")
}

// ip2RegionXDBDownloadSizeCap 是 xdb 下载的单设上限（100MB，>9× 合法 v4.xdb
// 约 11MB）：此前与 CRS tarball 共用 2GB 上限，而安装校验经 NewV4Config 的
// BufferCache 在构造期全量读入内存（binding 库 config.go LoadContent）——
// ~2GB 的恶意/损坏响应体会在校验阶段分配等量堆，小内存容器被 OOM kill 整个
// admin 进程（R64 B-F1）。100MB 内的损坏文件仅使探针搜索失败、拒绝安装。
const ip2RegionXDBDownloadSizeCap = int64(100 << 20)

// defaultDownloadIP2RegionXDB downloads the ip2region v4 xdb to destPath.
func defaultDownloadIP2RegionXDB(ctx context.Context, tag, destPath string, progress downloadProgressFunc) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		ip2RegionXDBSourceURL(tag), nil)
	if err != nil {
		return err
	}
	resp, err := ip2RegionDownloadClient.Do(req)
	if err != nil {
		return fmt.Errorf("下载 ip2region xdb: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 ip2region xdb: GitHub 返回 %d", resp.StatusCode)
	}
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	copyErr := writeRuleSetDownload(out, resp, ip2RegionXDBDownloadSizeCap, progress)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

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
// var 以便测试指向 httptest 服务。
var ip2RegionLatestReleaseAPIURL = "https://api.github.com/repos/lionsoul2014/ip2region/releases/latest"

// defaultFetchIP2RegionLatestTag 查询 ip2region 最新版本：先直连
// api.github.com（快路径不变），仅在 403 限流与传输类失败（Do() 错误、5xx、
// 读体中断）时经 GitHub 加速代理（github_proxy_url 白名单）回退查询
// releases/latest 页面；其余 4xx 与 tag 解析失败不重试。两路均失败时错误同时
// 点名两个尝试过的 URL（口径同 defaultFetchCRSLatestTag）。
func defaultFetchIP2RegionLatestTag(ctx context.Context) (string, error) {
	return fetchLatestGitHubTag(ctx, ip2RegionHTTPClient, ip2RegionLatestReleaseAPIURL, ip2RegionRepoSlug, "ip2region")
}

// ip2RegionXDBSourceURL 是 ip2region xdb 的真实来源 URL（含版本 tag，作为完整
// 性基线的键）：下载函数与安装校验后的记录调用共用，避免 URL 构造分叉。
func ip2RegionXDBSourceURL(tag string) string {
	return ip2RegionXDBSourceURLFor("v4", tag)
}

// ip2RegionXDBSourceURLFor 按数据族（v4/v6）构造来源 URL：两族文件同仓库
// 同 tag 发布（data/ip2region_v4.xdb 与 data/ip2region_v6.xdb），单次版本
// 检查同时覆盖两源。
func ip2RegionXDBSourceURLFor(family, tag string) string {
	return ghProxied(ip2RegionXDBOriginURLFor(family, tag))
}

// ip2RegionXDBOriginURLFor 裸 GitHub 源站 URL（不含代理前缀）——完整性基线
// 的键口径：代理是传输层(白名单可切换),内容校验应钉源站。
func ip2RegionXDBOriginURLFor(family, tag string) string {
	return "https://raw.githubusercontent.com/lionsoul2014/ip2region/" + tag + "/data/ip2region_" + family + ".xdb"
}

// ip2RegionXDBBaselineKey 是完整性基线的键:裸 GitHub URL 不含
// 代理前缀——代理是传输层(白名单可切换),内容校验应钉源站。
func ip2RegionXDBBaselineKey(tag string) string {
	return ip2RegionXDBOriginURLFor("v4", tag)
}

// ip2RegionXDBDownloadSizeCap 是 xdb 下载的单设上限（100MB，>9× 合法 v4.xdb
// 约 11MB）：此前与 CRS tarball 共用 2GB 上限，而安装校验经 NewV4Config 的
// BufferCache 在构造期全量读入内存（binding 库 config.go LoadContent）——
// ~2GB 的恶意/损坏响应体会在校验阶段分配等量堆，小内存容器被 OOM kill 整个
// admin 进程。100MB 内的损坏文件仅使探针搜索失败、拒绝安装。
const ip2RegionXDBDownloadSizeCap = int64(100 << 20)

// ip2RegionDownloadSync 是落盘同步的测试缝（生产恒为 (*os.File).Sync）：
// Sync 失败分支是掉电持久性门，无法用真实文件注入（只能靠磁盘故障），
// 经缝覆盖「同步失败不得把 staging 文件当成功」。
var ip2RegionDownloadSync = func(f *os.File) error { return f.Sync() }

// defaultDownloadIP2RegionXDB downloads the ip2region v4 xdb to destPath.
func defaultDownloadIP2RegionXDB(ctx context.Context, tag, destPath string, progress downloadProgressFunc) error {
	return defaultDownloadIP2RegionXDBFamily(ctx, "v4", tag, destPath, progress)
}

// defaultDownloadIP2RegionXDBV6 是 v6 数据源的下载缝（与 v4 同一实现，仅
// 来源 URL 与族名不同；测试各自重定向）。
func defaultDownloadIP2RegionXDBV6(ctx context.Context, tag, destPath string, progress downloadProgressFunc) error {
	return defaultDownloadIP2RegionXDBFamily(ctx, "v6", tag, destPath, progress)
}

// defaultDownloadIP2RegionXDBFamily 按数据族下载 xdb 到 destPath：错误文案
// 带族名，安装前结构自检门按族布局判定（见 checkIP2RegionXDBStructure）。
func defaultDownloadIP2RegionXDBFamily(ctx context.Context, family, tag, destPath string, progress downloadProgressFunc) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		ip2RegionXDBSourceURLFor(family, tag), nil)
	if err != nil {
		return err
	}
	resp, err := ip2RegionDownloadClient.Do(req)
	if err != nil {
		return fmt.Errorf("下载 ip2region %s xdb: %w", family, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 ip2region %s xdb: GitHub 返回 %d", family, resp.StatusCode)
	}
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	copyErr := writeRuleSetDownload(out, resp, ip2RegionXDBDownloadSizeCap, progress)
	// 落盘持久化屏障：staging 文件随后被 rename 进 live 路径，掉电窗口内
	// 未 fsync 的页缓存会留下半截 live 库（与 writeFileAtomicSynced 同口径，
	// 先 Sync 再 Close）。
	var syncErr error
	if copyErr == nil {
		syncErr = ip2RegionDownloadSync(out)
	}
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return fmt.Errorf("ip2region %s xdb 落盘同步失败: %w", family, syncErr)
	}
	if closeErr != nil {
		return closeErr
	}
	// Content-Length 回读比对：声明长度的响应被中间层截断时落盘字节数
	// 与声明值不一致，直接拒收；chunked 无声明长度，由安装前的结构自检
	// 门兜底（见 validateIP2RegionXDB / validateIP2RegionV6XDB）。
	if resp.ContentLength >= 0 {
		fi, serr := os.Stat(destPath)
		if serr != nil {
			return fmt.Errorf("ip2region %s xdb 落盘回读失败: %w", family, serr)
		}
		if fi.Size() != resp.ContentLength {
			return fmt.Errorf("ip2region %s xdb 落盘字节 %d 与响应声明长度 %d 不一致（疑似截断）", family, fi.Size(), resp.ContentLength)
		}
	}
	return nil
}

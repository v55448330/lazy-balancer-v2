package services

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var crsHTTPClient = &http.Client{Timeout: 30 * time.Second}

// ruleSetDownloadSizeCap 是 CRS/ip2region 下载的最大字节数（2GB）：代理在超时
// 窗口内可无限流式灌入，无界 io.Copy 会写爆数据卷 staging 目录（R34 A）。
const ruleSetDownloadSizeCap = int64(2 << 30)

// downloadProgressFunc 是下载进度回调：written 为已落盘字节数，total 为预期总
// 字节数（未知时为 0）。下载函数在收到响应头后先以 (0, total) 触发一次开始
// 信号，随后由计数 reader 在流式拷贝中持续回调（R57）。
type downloadProgressFunc func(written, total int64)

// writeRuleSetDownload 将响应体限界写入目标文件：Content-Length 超上限先拒绝
// 落盘，流式拷贝超上限即报错中止（R34 A）。progress 非 nil 时先发出 (0, total)
// 开始信号，再经计数 reader 持续上报进度（R57）。
func writeRuleSetDownload(out *os.File, resp *http.Response, cap int64, progress downloadProgressFunc) error {
	if resp.ContentLength > cap {
		return fmt.Errorf("下载声明 Content-Length=%d 超过大小上限 %d 字节", resp.ContentLength, cap)
	}
	total := resp.ContentLength
	if total < 0 {
		total = 0 // chunked 或未知长度
	}
	var src io.Reader = io.LimitReader(resp.Body, cap+1)
	if progress != nil {
		progress(0, total)
		src = &downloadProgressReader{r: src, total: total, progress: progress}
	}
	n, err := io.Copy(out, src)
	if err != nil {
		return err
	}
	if n > cap {
		return fmt.Errorf("下载超过大小上限 %d 字节，已中止", cap)
	}
	return nil
}

// downloadProgressReader 是计数 reader：每次成功读取后累加并回调进度（R57）。
type downloadProgressReader struct {
	r        io.Reader
	written  int64
	total    int64
	progress downloadProgressFunc
}

func (r *downloadProgressReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.written += int64(n)
		r.progress(r.written, r.total)
	}
	return n, err
}

// newDownloadProgressLogger 返回节流进度闭包（R57）：首次回调（下载函数的
// (0, total) 开始信号）写「开始下载」行，携带完整来源 URL，Content-Length
// 已知时附预计大小；此后 total 已知按每 10% 阈值、未知按每 5MB 写一条「下载
// 进度」行。logLine 由调用方接到各自的更新日志 writer。
func newDownloadProgressLogger(sourceURL string, logLine func(message string)) downloadProgressFunc {
	const unknownTotalStepBytes = int64(5 << 20)
	started := false
	var lastStep int64
	return func(written, total int64) {
		if !started {
			started = true
			if total > 0 {
				logLine(fmt.Sprintf("开始下载: %s (预计 %s)", sourceURL, formatDownloadBytes(total)))
			} else {
				logLine("开始下载: " + sourceURL)
			}
		}
		var step int64
		if total > 0 {
			step = written * 10 / total
			if step > 10 {
				step = 10
			}
		} else {
			step = written / unknownTotalStepBytes
		}
		if step <= lastStep {
			return
		}
		lastStep = step
		if total > 0 {
			logLine(fmt.Sprintf("下载进度: %s/%s (%d%%)", formatDownloadBytes(written), formatDownloadBytes(total), step*10))
		} else {
			logLine(fmt.Sprintf("下载进度: %s", formatDownloadBytes(written)))
		}
	}
}

// logDownloadCompletion 写下载完成行：落盘总字节 + 耗时秒（R57）。
func logDownloadCompletion(logLine func(message string), destPath string, startedAt time.Time) {
	var size int64
	if info, err := os.Stat(destPath); err == nil {
		size = info.Size()
	}
	logLine(fmt.Sprintf("下载完成: 共 %s，耗时 %.1f 秒", formatDownloadBytes(size), time.Since(startedAt).Seconds()))
}

// formatDownloadBytes 以 1024 进制格式化字节数（如 12.3 MB）。
func formatDownloadBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ghFastProxy prefixes GitHub downloads through https://ghfast.top/ — direct
// GitHub file access is unreliable from the deployment network. The proxy
// supports raw.githubusercontent.com and github.com archive paths but NOT
// codeload.github.com or api.github.com (verified 403), so the CRS tarball
// uses the equivalent archive URL and the latest-tag check falls back to the
// proxied releases/latest redirect (R57). var（而非 const）以便测试指向
// httptest 代理。
var ghFastProxy = "https://ghfast.top/"

func ghProxied(rawURL string) string {
	return ghFastProxy + rawURL
}

// crsTarballSourceURL 是 CRS 发布包的真实来源 URL（含版本 tag，作为完整性基线
// 的键）：下载函数与安装校验后的记录调用共用，避免 URL 构造分叉。
func crsTarballSourceURL(tag string) string {
	return ghProxied("https://github.com/coreruleset/coreruleset/archive/refs/tags/" + tag + ".tar.gz")
}

// crsRepoSlug 是 CRS 的 GitHub 仓库标识：直连 API 与代理 releases/latest 共用。
const crsRepoSlug = "coreruleset/coreruleset"

// crsLatestReleaseAPIURL 是 CRS 最新版本的 GitHub API 直连地址；var 以便测试
// 指向 httptest 服务（R57）。
var crsLatestReleaseAPIURL = "https://api.github.com/repos/coreruleset/coreruleset/releases/latest"

// defaultFetchCRSLatestTag 查询 CRS 最新版本：先直连 api.github.com（快路径不
// 变），仅在传输类失败（Do() 错误、5xx、读体中断）时经 ghfast 代理回退查询
// （api.github.com 不可代理，verified 403）；4xx 与 tag 解析失败不重试。两路
// 均失败时错误同时点名两个尝试过的 URL（R57）。
func defaultFetchCRSLatestTag(ctx context.Context) (string, error) {
	tag, err, transport := fetchGitHubLatestTagFromAPI(ctx, crsHTTPClient, crsLatestReleaseAPIURL)
	if err == nil {
		return tag, nil
	}
	if !transport {
		return "", fmt.Errorf("查询 CRS 最新版本: %w", err)
	}
	proxyTag, proxyErr := fetchGitHubLatestTagViaProxy(ctx, crsRepoSlug)
	if proxyErr != nil {
		return "", fmt.Errorf("查询 CRS 最新版本: 直连 %s 失败: %v；经代理 %s 重试仍失败: %v",
			crsLatestReleaseAPIURL, err, ghProxied(gitHubReleasesLatestURL(crsRepoSlug)), proxyErr)
	}
	return proxyTag, nil
}

func defaultDownloadCRSTarball(ctx context.Context, tag, destPath string, progress downloadProgressFunc) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		crsTarballSourceURL(tag), nil)
	if err != nil {
		return err
	}
	resp, err := crsHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub 下载返回 %d", resp.StatusCode)
	}
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	copyErr := writeRuleSetDownload(out, resp, ruleSetDownloadSizeCap, progress)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

// gitHubReleasesLatestURL 是仓库 releases/latest 页面地址：GitHub 会 302 跳转
// 到 /releases/tag/{最新 tag}，经 ghfast 代理即可绕过 api.github.com 不可代理
// 的限制查询最新版本（R57）。
func gitHubReleasesLatestURL(repoSlug string) string {
	return "https://github.com/" + repoSlug + "/releases/latest"
}

// ghLatestTagBodyLimit 限定代理直接返回页面（200 无跳转）时扫描的 HTML 字节数。
const ghLatestTagBodyLimit = int64(1 << 20)

var ghLatestTagInBodyRegexp = regexp.MustCompile(`/releases/tag/([^"'/]+)`)

// fetchGitHubLatestTagViaProxy 经 ghfast 代理查询 repoSlug 的最新 release tag
// （R57）：GET 代理后的 releases/latest，用 CheckRedirect 捕获首个 Location
// （302 → /releases/tag/{tag}）而不跟随；代理直接返回 200 页面（无跳转）时改
// 从响应体（≤1MB）正则提取首个 /releases/tag/ 出现。
func fetchGitHubLatestTagViaProxy(ctx context.Context, repoSlug string) (string, error) {
	proxiedURL := ghProxied(gitHubReleasesLatestURL(repoSlug))
	var location string
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			location = req.URL.String()
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxiedURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("代理查询最新版本 %s: %w", proxiedURL, err)
	}
	defer resp.Body.Close()
	if location != "" {
		return parseGitHubTagFromLocation(location)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("代理查询最新版本 %s: 返回 %d", proxiedURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ghLatestTagBodyLimit))
	if err != nil {
		return "", fmt.Errorf("读取代理响应 %s: %w", proxiedURL, err)
	}
	if m := ghLatestTagInBodyRegexp.FindSubmatch(body); m != nil {
		return string(m[1]), nil
	}
	return "", fmt.Errorf("代理响应 %s 未包含 /releases/tag/ 跳转", proxiedURL)
}

// parseGitHubTagFromLocation 从 releases/latest 的跳转地址解析 tag（容忍尾部
// 的 query/fragment）。
func parseGitHubTagFromLocation(location string) (string, error) {
	const marker = "/releases/tag/"
	idx := strings.LastIndex(location, marker)
	if idx < 0 {
		return "", fmt.Errorf("跳转地址 %q 不含 %s", location, marker)
	}
	tag := location[idx+len(marker):]
	if i := strings.IndexAny(tag, "?#"); i >= 0 {
		tag = tag[:i]
	}
	if tag == "" {
		return "", fmt.Errorf("跳转地址 %q 未携带 tag", location)
	}
	return tag, nil
}

// fetchGitHubLatestTagFromAPI 直连 GitHub releases/latest API 解析 tag_name。
// transport 报告失败是否为网络/传输类（Do() 错误、5xx、响应体读取中断）——
// 只有这类失败值得经 ghfast 代理重试；4xx（含限流 403）与 tag 解析失败不重
// 试（R57：代理对 api.github.com 同样 403，重试只会放大延迟）。
func fetchGitHubLatestTagFromAPI(ctx context.Context, client *http.Client, apiURL string) (string, error, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err, false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err, true
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub 返回 %d", resp.StatusCode), resp.StatusCode >= http.StatusInternalServerError
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("读取 GitHub 响应: %w", err), true
	}
	tag, err := parseGitHubLatestTag(body)
	return tag, err, false
}

package services

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var crsHTTPClient = &http.Client{Timeout: 30 * time.Second}

// ruleSetDownloadSizeCap 是 CRS/ip2region 下载的最大字节数（2GB）：代理在超时
// 窗口内可无限流式灌入，无界 io.Copy 会写爆数据卷 staging 目录（R34 A）。
const ruleSetDownloadSizeCap = int64(2 << 30)

// writeRuleSetDownload 将响应体限界写入目标文件：Content-Length 超上限先拒绝
// 落盘，流式拷贝超上限即报错中止（R34 A）。
func writeRuleSetDownload(out *os.File, resp *http.Response, cap int64) error {
	if resp.ContentLength > cap {
		return fmt.Errorf("下载声明 Content-Length=%d 超过大小上限 %d 字节", resp.ContentLength, cap)
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, cap+1))
	if err != nil {
		return err
	}
	if n > cap {
		return fmt.Errorf("下载超过大小上限 %d 字节，已中止", cap)
	}
	return nil
}

// ghFastProxy prefixes GitHub downloads through https://ghfast.top/ — direct
// GitHub file access is unreliable from the deployment network. The proxy
// supports raw.githubusercontent.com and github.com archive paths but NOT
// codeload.github.com or api.github.com (verified 403), so the CRS tarball
// uses the equivalent archive URL and release metadata stays direct.
const ghFastProxy = "https://ghfast.top/"

func ghProxied(rawURL string) string {
	return ghFastProxy + rawURL
}

// crsTarballSourceURL 是 CRS 发布包的真实来源 URL（含版本 tag，作为完整性基线
// 的键）：下载函数与安装校验后的记录调用共用，避免 URL 构造分叉。
func crsTarballSourceURL(tag string) string {
	return ghProxied("https://github.com/coreruleset/coreruleset/archive/refs/tags/" + tag + ".tar.gz")
}

func defaultFetchCRSLatestTag(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/coreruleset/coreruleset/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := crsHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("查询 CRS 最新版本: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("查询 CRS 最新版本: GitHub 返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("读取 GitHub 响应: %w", err)
	}
	return parseGitHubLatestTag(body)
}

func defaultDownloadCRSTarball(ctx context.Context, tag, destPath string) error {
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
	copyErr := writeRuleSetDownload(out, resp, ruleSetDownloadSizeCap)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

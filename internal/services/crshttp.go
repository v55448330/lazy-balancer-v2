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
	_, copyErr := io.Copy(out, resp.Body)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

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
		"https://codeload.github.com/coreruleset/coreruleset/tar.gz/refs/tags/"+tag, nil)
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
	return closeErr
}

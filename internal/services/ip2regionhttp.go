package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var ip2RegionHTTPClient = &http.Client{Timeout: 60 * time.Second}

func defaultFetchIP2RegionLatestCommit(ctx context.Context) (string, error) {
	tag, commit, err := defaultFetchIP2RegionLatestTag(ctx)
	if err != nil {
		return "", err
	}
	if commit == "" {
		return tag, nil
	}
	return commit, nil
}

func defaultFetchIP2RegionLatestTag(ctx context.Context) (tag, commit string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/lionsoul2014/ip2region/releases/latest", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := ip2RegionHTTPClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("查询 ip2region 最新版本: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("查询 ip2region 最新版本: GitHub 返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("读取 GitHub 响应: %w", err)
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return "", "", fmt.Errorf("解析 GitHub releases 响应: %w", err)
	}
	if release.TagName == "" {
		return "", "", errors.New("GitHub releases 响应缺少 tag_name")
	}
	return release.TagName, "", nil
}

// defaultDownloadIP2RegionXDB downloads the ip2region v4 xdb to destPath.
func defaultDownloadIP2RegionXDB(ctx context.Context, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb", nil)
	if err != nil {
		return err
	}
	resp, err := ip2RegionHTTPClient.Do(req)
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
	_, copyErr := io.Copy(out, resp.Body)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// parseGitHubCommitSHA extracts the sha of the first commit from a GitHub
// commits list response.
func parseGitHubCommitSHA(body []byte) (string, error) {
	var payload []struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("解析 GitHub 响应失败: %w", err)
	}
	if len(payload) == 0 || payload[0].SHA == "" {
		return "", errors.New("GitHub 响应缺少 commit sha")
	}
	return payload[0].SHA, nil
}

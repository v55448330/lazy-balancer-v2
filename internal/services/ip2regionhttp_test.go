package services

// R57: ip2region 最新版本查询的代理回退 + 下载 URL/进度日志测试。

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// withIP2RegionLatestAPIURL 将 ip2region 直连 API 地址指向测试服务并在结束后还原。
func withIP2RegionLatestAPIURL(t *testing.T, url string) {
	t.Helper()
	old := ip2RegionLatestReleaseAPIURL
	ip2RegionLatestReleaseAPIURL = url
	t.Cleanup(func() { ip2RegionLatestReleaseAPIURL = old })
}

func TestFetchIP2RegionLatestTag_directSuccessSkipsProxy(t *testing.T) {
	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyHits++ }))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.github+json")
		fmt.Fprint(w, `{"tag_name":"v3.99.0"}`)
	}))
	defer api.Close()
	withIP2RegionLatestAPIURL(t, api.URL)

	tag, err := defaultFetchIP2RegionLatestTag(context.Background())
	if err != nil {
		t.Fatalf("defaultFetchIP2RegionLatestTag()=%v, want success", err)
	}
	if tag != "v3.99.0" {
		t.Fatalf("tag=%q, want v3.99.0", tag)
	}
	if proxyHits != 0 {
		t.Fatalf("proxy hits=%d, want 0 (direct success must not call the proxy)", proxyHits)
	}
}

func TestFetchIP2RegionLatestTag_transportErrorFallsBackToProxyRedirect(t *testing.T) {
	// Given 直连传输类失败 + 代理 302 跳转到 /releases/tag/{tag}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/lionsoul2014/ip2region/releases/tag/v3.99.0", http.StatusFound)
	}))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")
	withIP2RegionLatestAPIURL(t, deadServerURL(t))

	tag, err := defaultFetchIP2RegionLatestTag(context.Background())
	if err != nil {
		t.Fatalf("defaultFetchIP2RegionLatestTag()=%v, want proxied fallback success", err)
	}
	if tag != "v3.99.0" {
		t.Fatalf("tag=%q, want v3.99.0 parsed from the redirect Location", tag)
	}
}

func TestFetchIP2RegionLatestTag_bothFailErrorNamesBothURLs(t *testing.T) {
	// Given 直连传输类失败 + 代理也失败（502）
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "proxy down", http.StatusBadGateway)
	}))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")
	withIP2RegionLatestAPIURL(t, deadServerURL(t))

	_, err := defaultFetchIP2RegionLatestTag(context.Background())
	if err == nil {
		t.Fatal("err=nil, want both attempts to fail")
	}
	if !strings.Contains(err.Error(), ip2RegionLatestReleaseAPIURL) {
		t.Fatalf("error must name the direct API URL %q: %v", ip2RegionLatestReleaseAPIURL, err)
	}
	proxiedLatest := ghProxied(gitHubReleasesLatestURL(ip2RegionRepoSlug))
	if !strings.Contains(err.Error(), proxiedLatest) {
		t.Fatalf("error must name the proxied URL %q: %v", proxiedLatest, err)
	}
}

func TestIP2RegionDownloadXDBLogged_startAndCompletionLines(t *testing.T) {
	// Given 内存下载服务：显式 Content-Length + 分块 flush 模拟流式到达
	body := bytes.Repeat([]byte("i"), 8*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		const chunks = 4
		chunk := len(body) / chunks
		for i := 0; i < chunks; i++ {
			start := i * chunk
			end := start + chunk
			if i == chunks-1 {
				end = len(body)
			}
			if _, err := w.Write(body[start:end]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()
	withGHFastProxy(t, srv.URL+"/")

	m := newTestIP2RegionManager(t)
	dest := filepath.Join(t.TempDir(), "ip2region_v4.xdb")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// When 带日志的下载跑完
	if err := m.downloadXDBLogged(ctx, "v9.9.9", dest); err != nil {
		t.Fatalf("downloadXDBLogged()=%v", err)
	}

	// Then 文件完整落盘
	if info, err := os.Stat(dest); err != nil || info.Size() != int64(len(body)) {
		t.Fatalf("downloaded file size=%d,%v, want %d", info.Size(), err, len(body))
	}

	// And 更新日志包含：开始行（完整代理 URL+预计大小）与完成行（字节+耗时）
	data, err := os.ReadFile(IP2RegionUpdateLogPath())
	if err != nil {
		t.Fatal(err)
	}
	logContent := string(data)
	wantURL := ghProxied("https://raw.githubusercontent.com/lionsoul2014/ip2region/v9.9.9/data/ip2region_v4.xdb")
	if !strings.Contains(logContent, "开始下载: "+wantURL) {
		t.Fatalf("log missing start line with the full proxied URL:\n%s", logContent)
	}
	if !strings.Contains(logContent, "预计 8.0 KB") {
		t.Fatalf("log missing expected size:\n%s", logContent)
	}
	if !strings.Contains(logContent, "下载完成: 共 8.0 KB") {
		t.Fatalf("log missing completion line with byte count:\n%s", logContent)
	}
	if !strings.Contains(logContent, "耗时") {
		t.Fatalf("log missing elapsed seconds:\n%s", logContent)
	}
	if !strings.Contains(logContent, string(IP2RegionStatusDownloading)) {
		t.Fatalf("log lines must use the downloading stage:\n%s", logContent)
	}
}

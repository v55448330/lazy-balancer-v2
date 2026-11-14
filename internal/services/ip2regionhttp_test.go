package services

// ip2region 最新版本查询的代理回退 + 下载 URL/进度日志测试。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"lazy-balancer-v2/internal/taskengine"
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
	// Given 内存下载服务：显式 + 分块 flush 模拟流式到达
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

	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })
	m := newTestIP2RegionManager(t)
	dest := filepath.Join(t.TempDir(), "ip2region_v4.xdb")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// When 带日志的下载跑完
	if err := m.downloadXDBLogged(ctx, "v9.9.9", dest); err != nil {
		t.Fatalf("downloadXDBLogged()=%v", err)
	}

	// Then 文件完整落盘
	// 分开断言：err != nil 时 info 为 nil，旧写法在 Fatalf 实参里再解引用
	// info.Size() 直接 panic，掩盖「下载未落盘」的真实原因。
	info, statErr := os.Stat(dest)
	if statErr != nil {
		t.Fatalf("下载文件未落盘: %v", statErr)
	}
	if info.Size() != int64(len(body)) {
		t.Fatalf("downloaded file size=%d, want %d", info.Size(), len(body))
	}

	// And 更新日志包含：开始行（完整代理 URL+预计大小）与完成行（字节+耗时）
	data, err := os.ReadFile(taskengine.TaskLogPath("ip2region"))
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

// ---- 下载完整性门（Content-Length 回读 / 落盘同步）----

// 合成响应经包内共享 roundTripFunc 注入 http.Client.Transport（不经网络）。

// 中间层截断：响应声明 Content-Length 大于实际可读字节时不得把 staging 文件
// 当成功（安装段会 rename 它进 live 路径）。
func TestDownloadIP2RegionXDB_rejectsTruncatedBodyAgainstDeclaredLength(t *testing.T) {
	oldClient := ip2RegionDownloadClient
	ip2RegionDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(strings.NewReader("short-body")),
			ContentLength: 1024,
			Header:        make(http.Header),
		}, nil
	})}
	t.Cleanup(func() { ip2RegionDownloadClient = oldClient })
	oldSync := ip2RegionDownloadSync
	ip2RegionDownloadSync = func(f *os.File) error { return f.Sync() }
	t.Cleanup(func() { ip2RegionDownloadSync = oldSync })

	dest := filepath.Join(t.TempDir(), "ip2region_v4.xdb")
	err := defaultDownloadIP2RegionXDB(context.Background(), "v9.9.9", dest, nil)
	if err == nil {
		t.Fatal("声明长度与实际字节不一致必须拒收（截断文件不得当成功）")
	}
	if !strings.Contains(err.Error(), "疑似截断") {
		t.Fatalf("错误须点名截断形态: %v", err)
	}
	if info, serr := os.Stat(dest); serr != nil || info.Size() != int64(len("short-body")) {
		t.Fatalf("部分落盘内容=%v,%v（staging 内容保持原样供上层清理）", info, serr)
	}
}

// 落盘同步失败（掉电持久性门）必须上抛，不得把未 fsync 的 staging 文件当成功。
func TestDownloadIP2RegionXDB_rejectsSyncFailure(t *testing.T) {
	oldClient := ip2RegionDownloadClient
	ip2RegionDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := "xdb-payload"
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Header:        make(http.Header),
		}, nil
	})}
	t.Cleanup(func() { ip2RegionDownloadClient = oldClient })
	oldSync := ip2RegionDownloadSync
	ip2RegionDownloadSync = func(*os.File) error { return errors.New("injected sync failure") }
	t.Cleanup(func() { ip2RegionDownloadSync = oldSync })

	dest := filepath.Join(t.TempDir(), "ip2region_v4.xdb")
	err := defaultDownloadIP2RegionXDB(context.Background(), "v9.9.9", dest, nil)
	if err == nil || !strings.Contains(err.Error(), "落盘同步失败") {
		t.Fatalf("同步失败必须上抛落盘同步错误, got %v", err)
	}
}

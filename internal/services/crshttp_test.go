package services

// GitHub 最新版本查询的代理回退 + 下载 URL/进度日志测试。

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// withGHFastProxy 将 ghFastProxy 指向测试代理并在测试结束后还原。
func withGHFastProxy(t *testing.T, base string) {
	t.Helper()
	old := ghFastProxy
	ghFastProxy = base
	t.Cleanup(func() { ghFastProxy = old })
}

// deadServerURL 返回一个必然连接失败（传输类错误）的 URL：先建后关，端口拒连。
func deadServerURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	return url
}

// withCRSLatestAPIURL 将 CRS 直连 API 地址指向测试服务并在结束后还原。
func withCRSLatestAPIURL(t *testing.T, url string) {
	t.Helper()
	old := crsLatestReleaseAPIURL
	crsLatestReleaseAPIURL = url
	t.Cleanup(func() { crsLatestReleaseAPIURL = old })
}

func TestFetchCRSLatestTag_directSuccessSkipsProxy(t *testing.T) {
	// Given 直连 API 成功 + 一个会计数的代理
	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyHits++ }))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.github+json")
		fmt.Fprint(w, `{"tag_name":"v4.99.0"}`)
	}))
	defer api.Close()
	withCRSLatestAPIURL(t, api.URL)

	// When 查询最新版本
	tag, err := defaultFetchCRSLatestTag(context.Background())

	// Then 直连成功即返回，代理不被调用（快路径不变）
	if err != nil {
		t.Fatalf("defaultFetchCRSLatestTag()=%v, want success", err)
	}
	if tag != "v4.99.0" {
		t.Fatalf("tag=%q, want v4.99.0", tag)
	}
	if proxyHits != 0 {
		t.Fatalf("proxy hits=%d, want 0 (direct success must not call the proxy)", proxyHits)
	}
}

func TestFetchCRSLatestTag_direct403FallsBackToProxy(t *testing.T) {
	// Given 直连 api.github.com 返回 403（未认证限流 60 次/小时/IP）：
	// 代理走 releases/latest 页面（非 api.github.com），可绕过限流。
	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits++
		w.Header().Set("Location", "https://github.com/coreruleset/coreruleset/releases/tag/v4.14.0")
		w.WriteHeader(http.StatusFound)
	}))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	defer api.Close()
	withCRSLatestAPIURL(t, api.URL)

	// When 查询最新版本
	tag, err := defaultFetchCRSLatestTag(context.Background())

	// Then 代理回退成功提取 tag
	if err != nil {
		t.Fatalf("err=%v, want proxy fallback to succeed past 403 rate limit", err)
	}
	if tag != "v4.14.0" {
		t.Fatalf("tag=%q, want v4.14.0", tag)
	}
	if proxyHits == 0 {
		t.Fatal("proxy hits=0, want 403 to trigger proxy fallback")
	}
}

func TestFetchCRSLatestTag_emptyTagDoesNotFallBack(t *testing.T) {
	// Given 直连 200 但响应缺少 tag_name（非传输类失败）
	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyHits++ }))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{}`)
	}))
	defer api.Close()
	withCRSLatestAPIURL(t, api.URL)

	// When 查询最新版本
	_, err := defaultFetchCRSLatestTag(context.Background())

	// Then 直接失败，不走代理回退
	if err == nil {
		t.Fatal("err=nil, want missing tag_name to fail without proxy fallback")
	}
	if proxyHits != 0 {
		t.Fatalf("proxy hits=%d, want 0 (parse failures must not fall back to the proxy)", proxyHits)
	}
}

func TestFetchCRSLatestTag_transportErrorFallsBackToProxyRedirect(t *testing.T) {
	// Given 直连传输类失败（连接被拒）+ 代理 302 跳转到 /releases/tag/{tag}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/coreruleset/coreruleset/releases/tag/v4.99.0", http.StatusFound)
	}))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")
	withCRSLatestAPIURL(t, deadServerURL(t))

	// When 查询最新版本
	tag, err := defaultFetchCRSLatestTag(context.Background())

	// Then 代理回退从 Location 解析出 tag
	if err != nil {
		t.Fatalf("defaultFetchCRSLatestTag()=%v, want proxied fallback success", err)
	}
	if tag != "v4.99.0" {
		t.Fatalf("tag=%q, want v4.99.0 parsed from the redirect Location", tag)
	}
}

func TestFetchCRSLatestTag_proxyServesPageDirectlyParsesBody(t *testing.T) {
	// Given 直连传输类失败 + 代理不跳转、直接 200 返回页面
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/coreruleset/coreruleset/releases/tag/v4.28.0" data-direction="south">v4.28.0</a></body></html>`)
	}))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")
	withCRSLatestAPIURL(t, deadServerURL(t))

	// When 查询最新版本
	tag, err := defaultFetchCRSLatestTag(context.Background())

	// Then 从响应体正则解析出 tag
	if err != nil {
		t.Fatalf("defaultFetchCRSLatestTag()=%v, want body-regexp parse success", err)
	}
	if tag != "v4.28.0" {
		t.Fatalf("tag=%q, want v4.28.0 parsed from the HTML body", tag)
	}
}

func TestFetchCRSLatestTag_bothFailErrorNamesBothURLs(t *testing.T) {
	// Given 直连传输类失败 + 代理也失败（502）
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "proxy down", http.StatusBadGateway)
	}))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")
	withCRSLatestAPIURL(t, deadServerURL(t))

	// When 查询最新版本
	_, err := defaultFetchCRSLatestTag(context.Background())

	// Then 错误同时点名直连与代理两个尝试过的 URL
	if err == nil {
		t.Fatal("err=nil, want both attempts to fail")
	}
	if !strings.Contains(err.Error(), crsLatestReleaseAPIURL) {
		t.Fatalf("error must name the direct API URL %q: %v", crsLatestReleaseAPIURL, err)
	}
	proxiedLatest := ghProxied(gitHubReleasesLatestURL(crsRepoSlug))
	if !strings.Contains(err.Error(), proxiedLatest) {
		t.Fatalf("error must name the proxied URL %q: %v", proxiedLatest, err)
	}
}

func TestParseGitHubTagFromLocation(t *testing.T) {
	tag, err := parseGitHubTagFromLocation("https://github.com/coreruleset/coreruleset/releases/tag/v4.28.0")
	if err != nil || tag != "v4.28.0" {
		t.Fatalf("parseGitHubTagFromLocation()=(%q,%v), want v4.28.0", tag, err)
	}
	// 尾部 query/fragment 被容忍
	tag, err = parseGitHubTagFromLocation("https://github.com/o/r/releases/tag/v1.2.3?from=redirect")
	if err != nil || tag != "v1.2.3" {
		t.Fatalf("parseGitHubTagFromLocation()=(%q,%v), want v1.2.3", tag, err)
	}
	// 无 marker 报错
	if _, err := parseGitHubTagFromLocation("https://github.com/o/r/releases"); err == nil {
		t.Fatal("err=nil, want error for a Location without /releases/tag/")
	}
}

func TestDownloadProgressLogger_knownTotalTenPercentSteps(t *testing.T) {
	// Given 总量已知的下载：开始信号 + 每 10% 一次读取
	var lines []string
	progress := newDownloadProgressLogger("https://ghfast.top/https://github.com/example/repo/archive.tar.gz", func(message string) {
		lines = append(lines, message)
	})
	const total = int64(10 << 20)
	progress(0, total) // 下载函数的开始信号
	for written := int64(1 << 20); written <= total; written += 1 << 20 {
		progress(written, total)
	}

	// Then 开始行携带完整 URL 与预计大小，随后恰好 10 条 10% 步进进度行
	if len(lines) != 11 {
		t.Fatalf("lines=%d, want 11 (start + 10 progress)", len(lines))
	}
	if !strings.Contains(lines[0], "开始下载: https://ghfast.top/https://github.com/example/repo/archive.tar.gz") {
		t.Fatalf("start line missing the full source URL: %q", lines[0])
	}
	if !strings.Contains(lines[0], "预计 10.0 MB") {
		t.Fatalf("start line missing the expected size: %q", lines[0])
	}
	for i, want := range []string{"(10%)", "(20%)", "(30%)", "(40%)", "(50%)", "(60%)", "(70%)", "(80%)", "(90%)", "(100%)"} {
		if !strings.Contains(lines[i+1], want) {
			t.Fatalf("progress line %d=%q, want %s", i+1, lines[i+1], want)
		}
	}
	if !strings.Contains(lines[5], "5.0 MB/10.0 MB (50%)") {
		t.Fatalf("50%% line=%q, want 5.0 MB/10.0 MB (50%%)", lines[5])
	}
}

func TestDownloadProgressLogger_unknownTotalFiveMBSteps(t *testing.T) {
	// Given 总量未知（chunked）：开始信号 + 每 1MB 一次读取
	var lines []string
	progress := newDownloadProgressLogger("https://example.com/file", func(message string) {
		lines = append(lines, message)
	})
	progress(0, 0)
	for written := int64(1 << 20); written <= 12<<20; written += 1 << 20 {
		progress(written, 0)
	}

	// Then 开始行无预计大小，进度行每 5MB 一条
	if len(lines) != 3 {
		t.Fatalf("lines=%d, want 3 (start + 5MB + 10MB): %v", len(lines), lines)
	}
	if lines[0] != "开始下载: https://example.com/file" {
		t.Fatalf("start line=%q, want plain URL without expected size", lines[0])
	}
	if !strings.Contains(lines[1], "下载进度: 5.0 MB") {
		t.Fatalf("second line=%q, want 5.0 MB step", lines[1])
	}
	if !strings.Contains(lines[2], "下载进度: 10.0 MB") {
		t.Fatalf("third line=%q, want 10.0 MB step", lines[2])
	}
}

// chunkedReader 按固定块大小吐出数据，模拟流式到达。
type chunkedReader struct {
	data  []byte
	chunk int
	pos   int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	end := r.pos + r.chunk
	if end > len(r.data) {
		end = len(r.data)
	}
	n := copy(p, r.data[r.pos:end])
	r.pos += n
	return n, nil
}

func TestDownloadProgressReader_callbacksViaWriteRuleSetDownload(t *testing.T) {
	// Given 总量已知的合成响应，经计数 reader 落盘
	const total = int64(4096)
	body := bytes.Repeat([]byte("z"), int(total))
	resp := &http.Response{
		ContentLength: total,
		Body:          io.NopCloser(&chunkedReader{data: body, chunk: 1024}),
	}
	out, err := os.OpenFile(filepath.Join(t.TempDir(), "download"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	var calls [][2]int64
	if err := writeRuleSetDownload(out, resp, ruleSetDownloadSizeCap, func(written, gotTotal int64) {
		calls = append(calls, [2]int64{written, gotTotal})
	}); err != nil {
		t.Fatalf("writeRuleSetDownload()=%v", err)
	}

	// Then 首次回调是 (0, total) 开始信号，末次是 (total, total)
	if len(calls) == 0 {
		t.Fatal("no progress callbacks")
	}
	if calls[0] != [2]int64{0, total} {
		t.Fatalf("first callback=%v, want start signal (0, %d)", calls[0], total)
	}
	if last := calls[len(calls)-1]; last != [2]int64{total, total} {
		t.Fatalf("last callback=%v, want (%d, %d)", last, total, total)
	}
	for _, c := range calls {
		if c[1] != total {
			t.Fatalf("callback %v carries wrong total, want %d", c, total)
		}
	}
}

func TestCRSDownloadTarballLogged_startProgressCompletionLines(t *testing.T) {
	// Given 内存下载服务：显式 + 分 10 块 flush 模拟流式到达
	body := bytes.Repeat([]byte("c"), 64*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		const chunks = 10
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
	m := newTestCRSManager(t)
	dest := filepath.Join(t.TempDir(), "crs.tar.gz")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// When 带日志的下载跑完
	if err := m.downloadTarballLogged(ctx, "v9.9.9", dest); err != nil {
		t.Fatalf("downloadTarballLogged()=%v", err)
	}

	// Then 文件完整落盘
	if info, err := os.Stat(dest); err != nil || info.Size() != int64(len(body)) {
		t.Fatalf("downloaded file size=%d,%v, want %d", info.Size(), err, len(body))
	}

	// And 更新日志包含：开始行（完整代理 URL+预计大小）、进度行、完成行（字节+耗时）
	// （更新日志=任务日志 tasks/crs.log 唯一数据源）
	data, err := os.ReadFile(taskengine.TaskLogPath("crs"))
	if err != nil {
		t.Fatal(err)
	}
	logContent := string(data)
	wantURL := ghProxied("https://github.com/coreruleset/coreruleset/archive/refs/tags/v9.9.9.tar.gz")
	if !strings.Contains(logContent, "开始下载: "+wantURL) {
		t.Fatalf("log missing start line with the full proxied URL:\n%s", logContent)
	}
	if !strings.Contains(logContent, "预计 64.0 KB") {
		t.Fatalf("log missing expected size:\n%s", logContent)
	}
	if !strings.Contains(logContent, "下载进度:") {
		t.Fatalf("log missing progress lines:\n%s", logContent)
	}
	if !strings.Contains(logContent, "下载完成: 共 64.0 KB") {
		t.Fatalf("log missing completion line with byte count:\n%s", logContent)
	}
	if !strings.Contains(logContent, "耗时") {
		t.Fatalf("log missing elapsed seconds:\n%s", logContent)
	}
	if !strings.Contains(logContent, string(CRSStatusDownloading)) {
		t.Fatalf("log lines must use the downloading stage:\n%s", logContent)
	}
}

// gitHubAPIToken 读库失败（非 ErrNoRows）此前静默
// 降级无令牌——与同文件 getGitHubProxyURL「读库故障记日志留痕」口径分裂。
// 补 warn 后降级可见；行缺失（ErrNoRows）属正常「未配置」不告警。
func TestGitHubAPIToken_readFailureLogsWarn(t *testing.T) {
	// Given：global_config 表被改名——读取必失败（非 ErrNoRows 形态）
	_, database := newClusterTestService(t)
	if _, err := database.Exec("ALTER TABLE global_config RENAME TO global_config_secc2_bak"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := database.Exec("ALTER TABLE global_config_secc2_bak RENAME TO global_config"); err != nil {
			t.Errorf("restore global_config: %v", err)
		}
	})
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When：读取失败降级为空令牌
	if tok := gitHubAPIToken(); tok != "" {
		t.Fatalf("token=%q, want empty on read failure", tok)
	}

	// Then：warn 级留痕（对齐 getGitHubProxyURL 口径）
	if !strings.Contains(buf.String(), "WARNING:") || !strings.Contains(buf.String(), "GitHub API 令牌") {
		t.Fatalf("读库失败须 warn 留痕, log:\n%s", buf.String())
	}
}

// 401（令牌失效）与 5xx（传输/服务端故障）都必须经代理 releases/latest 回退；
// 404/400 等确定性 4xx 不回退（重试只会放大延迟）。
func TestFetchCRSLatestTag_apiFailureFallbackMatrix(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		wantFallback bool
	}{
		{"401_unauthorized_falls_back", http.StatusUnauthorized, true},
		{"500_server_error_falls_back", http.StatusInternalServerError, true},
		{"404_not_found_no_fallback", http.StatusNotFound, false},
		{"400_bad_request_no_fallback", http.StatusBadRequest, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxyHits := 0
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				proxyHits++
				w.Header().Set("Location", "https://github.com/coreruleset/coreruleset/releases/tag/v4.14.0")
				w.WriteHeader(http.StatusFound)
			}))
			defer proxy.Close()
			withGHFastProxy(t, proxy.URL+"/")

			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "failure", tc.status)
			}))
			defer api.Close()
			withCRSLatestAPIURL(t, api.URL)

			tag, err := defaultFetchCRSLatestTag(context.Background())
			if tc.wantFallback {
				if err != nil || tag != "v4.14.0" {
					t.Fatalf("status %d 必须回退代理: tag=%q err=%v", tc.status, tag, err)
				}
				if proxyHits == 0 {
					t.Fatalf("status %d 未触发代理回退", tc.status)
				}
				return
			}
			if err == nil {
				t.Fatalf("status %d 不得回退代理（err=nil）", tc.status)
			}
			if proxyHits != 0 {
				t.Fatalf("status %d 不得请求代理, hits=%d", tc.status, proxyHits)
			}
		})
	}
}

// GitHub API 令牌仅随 api.github.com 直连发送：代理收到 5xx 后的回退请求
// 必须不带 Authorization（第三方代理不可见凭据）。
func TestFetchCRSLatestTag_tokenNeverSentToProxy(t *testing.T) {
	initServicesDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET github_token='ghp_secret_token' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	proxyAuth := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyAuth <- r.Header.Get("Authorization")
		w.Header().Set("Location", "https://github.com/coreruleset/coreruleset/releases/tag/v4.20.0")
		w.WriteHeader(http.StatusFound)
	}))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")

	apiAuth := make(chan string, 1)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiAuth <- r.Header.Get("Authorization")
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer api.Close()
	withCRSLatestAPIURL(t, api.URL)

	tag, err := defaultFetchCRSLatestTag(context.Background())
	if err != nil || tag != "v4.20.0" {
		t.Fatalf("500 回退应成功: tag=%q err=%v", tag, err)
	}
	if got := <-apiAuth; got != "Bearer ghp_secret_token" {
		t.Fatalf("直连 API Authorization=%q, want Bearer 令牌", got)
	}
	if got := <-proxyAuth; got != "" {
		t.Fatalf("代理请求携带 Authorization=%q——令牌不得发往第三方代理", got)
	}
}

// 下载失败（Content-Length 超限 / io.Copy 中断）不得在 dest 留下 0 字节或半截
// 工件：该函数是 seam（测试/复用方传任意 dest），下一次「跳过下载」的调用会把
// 残件当成品消费（TOFU 完整性基线与解包都基于错误字节）。生产 dest 在 staging
// 内由 defer 清理，故此处只补 seam 形态。
func TestDefaultDownloadCRSTarball_removesPartialArtifactOnFailure(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "crs.tar.gz")
	oldClient := crsDownloadClient
	crsDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			ContentLength: ruleSetDownloadSizeCap + 1,
			Body:          io.NopCloser(strings.NewReader("partial")),
			Header:        http.Header{},
		}, nil
	})}
	t.Cleanup(func() { crsDownloadClient = oldClient })

	if err := defaultDownloadCRSTarball(context.Background(), "v4.99.0", dest, nil); err == nil {
		t.Fatal("Content-Length 超限必须失败")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("失败下载留下的工件未清理: stat err=%v", err)
	}
}

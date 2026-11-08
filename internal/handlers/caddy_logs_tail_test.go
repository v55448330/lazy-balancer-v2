package handlers

// GetCaddyLogs 尾窗「无换行/残段」行为与 GetAppLogs
// 统一口径（抽享 tailLogWindow）——修复前 GetCaddyLogs 在窗口内无
// '\n' 时返回整段原始中段（只收敛了 system.go，漏扫点）
// 单行 JSON 巨行（大请求头/大 body 访问日志可达 >128KB）时输出为巨行中段，
// 首字节切在多字节 rune 中间时带无效字节，JSON 编码后以 U+FFFD 污染。
// 统一口径：起点非零丢弃首行残段；窗口内无 '\n'（整窗为同一巨行中段）输出为空。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// tailLogWindow 形状钉：起点 0 原样 / 行中段含换行丢弃首行残段 / 行中段无换行
// 整窗为空 / 起点恰为行首（前一字节 '\n'）首行完整保留。
func TestTailLogWindow_shapes(t *testing.T) {
	if got := tailLogWindow(nil, []byte("abc\ndef"), 0); string(got) != "abc\ndef" {
		t.Fatalf("startOffset=0 应原样返回, got %q", got)
	}

	fragmentWindow := []byte("残段abc\n完整行\n")
	fragmentFull := append([]byte("PREVROW"), fragmentWindow...)
	if got := tailLogWindow(bytes.NewReader(fragmentFull), fragmentWindow, int64(len("PREVROW"))); string(got) != "完整行\n" {
		t.Fatalf("行中段应丢弃首行残段, got %q", got)
	}

	giantWindow := []byte("巨行中段无换行")
	giantFull := append([]byte("PREVROW"), giantWindow...)
	if got := tailLogWindow(bytes.NewReader(giantFull), giantWindow, int64(len("PREVROW"))); got != nil {
		t.Fatalf("行中段无换行应返回空（整窗为同一巨行中段）, got %q", got)
	}

	lineStartWindow := []byte("完整行\n完整行2\n")
	lineStartFull := append([]byte("PREVROW\n"), lineStartWindow...)
	if got := tailLogWindow(bytes.NewReader(lineStartFull), lineStartWindow, int64(len("PREVROW\n"))); string(got) != string(lineStartWindow) {
		t.Fatalf("起点恰为行首时应完整保留首行, got %q want %q", got, lineStartWindow)
	}

	// 读不到前一个字节（窗口起点超出 src 长度）时保守丢弃首行残段。
	if got := tailLogWindow(bytes.NewReader([]byte("短")), fragmentWindow, 100); string(got) != "完整行\n" {
		t.Fatalf("无法判定边界时应保守丢弃首行, got %q", got)
	}
}

// 以 \n 结尾的窗口按真实行数切片：行终止符产生的尾部空元素
// 不计行数，超限窗口必须显示满 500 条真实行（与 GetAppLogs 同形状）。
func TestGetCaddyLogs_maxLinesCountsRealLines(t *testing.T) {
	// Given：505 行且以 \n 结尾的运行日志
	h := newBackupTestHandlers(t)
	logPath := filepath.Join(t.TempDir(), "caddy.log")
	var builder strings.Builder
	for i := 1; i <= 505; i++ {
		fmt.Fprintf(&builder, "line-%d\n", i)
	}
	if err := os.WriteFile(logPath, []byte(builder.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{"runtime": logPath}
	t.Cleanup(func() { caddyLogPaths = oldPaths })

	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=runtime", nil))

	// Then：恰好保留最后 500 条真实行（line-6…line-505）
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(envelope.Data.Content, "\n")
	if len(lines) != 500 || lines[0] != "line-6" || lines[499] != "line-505" {
		t.Fatalf("以 \\n 结尾的 505 行应保留最后 500 条真实行（line-6…line-505），实得 %d 个元素，首 %q 尾 %q", len(lines), lines[0], lines[len(lines)-1])
	}
}

// GetCaddyLogs 巨行形状：单条 >128KB 无换行日志，窗口整体落在行中段 → 内容为空。
func TestGetCaddyLogs_tailWindowGiantLineReturnsEmpty(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	logPath := filepath.Join(t.TempDir(), "caddy.log")
	if err := os.WriteFile(logPath, []byte(strings.Repeat("a", 200*1024)), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{"runtime": logPath}
	t.Cleanup(func() { caddyLogPaths = oldPaths })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=runtime", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if envelope.Data.Content != "" {
		t.Fatalf("巨行中段应输出为空（与 GetAppLogs 同口径）, got %d 字节（首 64 字符: %q）",
			len(envelope.Data.Content), logContentPreview(envelope.Data.Content, 64))
	}
}

// GetCaddyLogs 残段形状（镜像夹具）：起点恰落在「中」（3 字节）的
// 第 2 字节——首行残段整体丢弃，输出恰为后续完整行，零 U+FFFD 污染。
func TestGetCaddyLogs_tailWindowDropsFirstLineFragment(t *testing.T) {
	// Given
	const maxBytes = 128 * 1024
	pad := strings.Repeat("a", 100) + "\n"               // 101 字节
	boundaryRune := "中"                                  // 占字节 101/102/103
	restOfBoundaryLine := strings.Repeat("c", 50) + "\n" // 边界行残余部分
	targetTotal := len(pad) + 1 + maxBytes               // startOffset=102=「中」第 2 字节
	fillerLen := targetTotal - len(pad) - len(boundaryRune) - len(restOfBoundaryLine)
	var fb strings.Builder
	longLine := strings.Repeat("d", 299) + "\n" // 300 字节长行,行数 <<500
	for fb.Len()+len(longLine) <= fillerLen {
		fb.WriteString(longLine)
	}
	if remaining := fillerLen - fb.Len(); remaining > 0 {
		fb.WriteString(strings.Repeat("e", remaining-1) + "\n")
	}
	filler := fb.String()
	if fillerLen <= 0 || len(filler) != fillerLen {
		t.Fatalf("夹具构造错误: fillerLen=%d len(filler)=%d", fillerLen, len(filler))
	}
	h := newBackupTestHandlers(t)
	logPath := filepath.Join(t.TempDir(), "caddy.log")
	if err := os.WriteFile(logPath, []byte(pad+boundaryRune+restOfBoundaryLine+filler), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{"runtime": logPath}
	t.Cleanup(func() { caddyLogPaths = oldPaths })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=runtime", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.Contains(envelope.Data.Content, string(rune(0xFFFD))) {
		t.Fatalf("输出含 U+FFFD 替换符——窗口起点切断多字节 rune,残段污染首行（首 64 字符: %q）", logContentPreview(envelope.Data.Content, 64))
	}
	if envelope.Data.Content != filler {
		t.Fatalf("输出须恰好为截断后的完整行内容: 长度=%d, want %d（首行残段整体丢弃）", len(envelope.Data.Content), len(filler))
	}
}

// logContentPreview 截取日志内容预览：断言失败消息里直接
// content[:64] 会在内容不足 64 字节（含空串）时 panic，掩盖真实诊断。
func logContentPreview(content string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(content)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return string(runes)
}

func TestLogContentPreview_shortContentDoesNotPanic(t *testing.T) {
	if got := logContentPreview("short", 64); got != "short" {
		t.Fatalf("preview=%q, want short", got)
	}
	if got := logContentPreview("", 64); got != "" {
		t.Fatalf("preview=%q, want empty", got)
	}
	if got := logContentPreview("abcdef", 3); got != "abc…" {
		t.Fatalf("preview=%q, want abc…", got)
	}
}

// GetCaddyLogs 先 os.Stat 得 size 再
// Seek(size-128KB) 后 io.ReadAll(f) 无 LimitReader——Stat 与 Read 之间日志
// 增长时本次返回可超 128KB 上限（certjobs.readLogTailFile 同族已用
// io.LimitReader）。测试钩子在 Stat 之后追加 200KB，钉住读取严格受窗口约束。
func TestGetCaddyLogs_capsWindowReadAt128KB(t *testing.T) {
	h := newBackupTestHandlers(t)
	logPath := filepath.Join(t.TempDir(), "caddy.log")
	line := strings.Repeat("a", 1023) + "\n" // 1024 字节/行
	writeLines := func(n int) {
		t.Helper()
		var builder strings.Builder
		for builder.Len() < n {
			builder.WriteString(line)
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatalf("open log: %v", err)
		}
		if _, err := f.WriteString(builder.String()); err != nil {
			f.Close()
			t.Fatalf("append log: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close log: %v", err)
		}
	}
	writeLines(300 * 1024)
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{"runtime": logPath}
	t.Cleanup(func() { caddyLogPaths = oldPaths })
	oldHook := caddyLogsStatHook
	// Stat 与读取之间的增长窗口：追加 200KB（轮转滞后/高流量形态）。
	caddyLogsStatHook = func() { writeLines(200 * 1024) }
	t.Cleanup(func() { caddyLogsStatHook = oldHook })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=runtime", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(envelope.Data.Content) > 128*1024 {
		t.Fatalf("content=%d 字节, want ≤128KB（Stat/Read 窗口增长必须受 LimitReader 约束）", len(envelope.Data.Content))
	}
	if envelope.Data.Content == "" {
		t.Fatal("content 为空——夹具日志应命中完整行窗口")
	}
}

// 未知日志类型必须 fail-visible：此前静默回落到 runtime 日志，排障者会
// 误读另一族日志（runtime/tls/server/proxy 内容完全不同），且响应无任何信号。
// 文案的可选值必须由**当前**路径表派生：注入一张与生产表不同的路径表后，
// 400 仍列出生产四类型即证明文案消费的是包初始化快照而非查表本身。
func TestGetCaddyLogs_unknownTypeRejectedWithValidValues(t *testing.T) {
	h := newBackupTestHandlers(t)
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{
		"runtime": filepath.Join(t.TempDir(), "caddy.log"),
		"audit":   filepath.Join(t.TempDir(), "caddy-audit.log"),
	}
	t.Cleanup(func() { caddyLogPaths = oldPaths })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=tls", nil))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"tls", "runtime", "audit"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body=%s, want 点名未知类型与当前可选值 %q", body, want)
		}
	}
	for _, stale := range []string{"server", "proxy"} {
		if strings.Contains(body, stale) {
			t.Fatalf("body=%s, 不得列出当前路径表之外的 %q（文案须由活路径表派生）", body, stale)
		}
	}
}

// GetCaddyLogs 行首形状：startOffset 恰落在行首（前一字节为 '\n'）时窗口首行
// 是完整行，不得按「残段」丢弃——此前一律丢到首个 '\n' 之后，每 avgLineLen
// 分之一概率让尾读面板少显示一行（极端形态整窗只有该行时显示「无日志」）。
func TestGetCaddyLogs_tailWindowKeepsFirstLineAtLineStart(t *testing.T) {
	// Given：文件总长 = 行首偏移 + 窗口上限，窗口起点恰在 '\n' 之后
	const maxBytes = 128 * 1024
	const firstLine = "FIRST-LINE-KEPT"
	pad := strings.Repeat("h", 200) + "\n" // 201 字节，末字节为 '\n'
	fillerLen := maxBytes - len(firstLine) - 1
	if fillerLen <= 0 {
		t.Fatalf("夹具构造错误: fillerLen=%d", fillerLen)
	}
	filler := strings.Repeat("w", fillerLen) // 单行无换行，行数远小于 500
	content := pad + firstLine + "\n" + filler

	h := newBackupTestHandlers(t)
	logPath := filepath.Join(t.TempDir(), "caddy.log")
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	if size := int64(len(content)); size-int64(len(pad)) != maxBytes {
		t.Fatalf("夹具构造错误: 窗口起点偏移=%d, want %d", size-maxBytes, len(pad))
	}
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{"runtime": logPath}
	t.Cleanup(func() { caddyLogPaths = oldPaths })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=runtime", nil))

	// Then：起点在行首时首行完整保留
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(envelope.Data.Content, firstLine) {
		t.Fatalf("起点在行首时首行被丢弃（窗口首 %q）, content 前 64 字符: %q",
			firstLine, logContentPreview(envelope.Data.Content, 64))
	}
}

package handlers

// LBH-B-U1（第 69 轮 P3）：GetCaddyLogs 尾窗「无换行/残段」行为与 GetAppLogs
// 统一 SYSB44-3 口径（抽享 tailLogWindow）——修复前 GetCaddyLogs 在窗口内无
// '\n' 时返回整段原始中段（第 44 轮只收敛了 system.go，R-12 漏扫点）：
// 单行 JSON 巨行（大请求头/大 body 访问日志可达 >128KB）时输出为巨行中段，
// 首字节切在多字节 rune 中间时带无效字节，JSON 编码后以 U+FFFD 污染。
// 统一口径：起点非零丢弃首行残段；窗口内无 '\n'（整窗为同一巨行中段）输出为空。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// tailLogWindow 三形状钉：起点 0 原样 / 含换行丢弃首行残段 / 无换行整窗为空。
func TestTailLogWindow_shapes(t *testing.T) {
	if got := tailLogWindow([]byte("abc\ndef"), 0); string(got) != "abc\ndef" {
		t.Fatalf("startOffset=0 应原样返回, got %q", got)
	}
	if got := tailLogWindow([]byte("残段abc\n完整行\n"), 100); string(got) != "完整行\n" {
		t.Fatalf("含换行应丢弃首行残段, got %q", got)
	}
	if got := tailLogWindow([]byte("巨行中段无换行"), 100); got != nil {
		t.Fatalf("无换行应返回空（整窗为同一巨行中段）, got %q", got)
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
			len(envelope.Data.Content), envelope.Data.Content[:64])
	}
}

// GetCaddyLogs 残段形状（镜像 SYSB44-3 夹具）：起点恰落在「中」（3 字节）的
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
		t.Fatalf("输出含 U+FFFD 替换符——窗口起点切断多字节 rune,残段污染首行（首 64 字符: %q）", envelope.Data.Content[:64])
	}
	if envelope.Data.Content != filler {
		t.Fatalf("输出须恰好为截断后的完整行内容: 长度=%d, want %d（首行残段整体丢弃）", len(envelope.Data.Content), len(filler))
	}
}

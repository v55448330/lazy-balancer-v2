package caddygeoip

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// F62-30(第 62 轮审计):写侧三文件此前零测试——补并发追加/空 ID 短路/目录
// 惰性创建的行为钉。

// Given: 并发 50 goroutine 各追加一行
// When: AppendSecurityTiming
// Then: 互斥锁保证 50 行完整落盘(无交错/丢行)
func TestAppendSecurityTiming_concurrentAppend(t *testing.T) {
	dir := t.TempDir()
	orig := securityTimingLogPath
	securityTimingLogPath = filepath.Join(dir, "timing.log")
	defer restoreSecurityTimingPath(orig) // PLUG-U2：关闭旧 fd 再置 nil（原泄漏）

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			AppendSecurityTiming(strings.Repeat("a", 8), int64(n))
		}(i)
	}
	wg.Wait()
	if securityTimingFd != nil {
		_ = securityTimingFd.Sync()
	}
	data, err := os.ReadFile(securityTimingLogPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 50 {
		t.Errorf("lines=%d; want 50 (mutex must serialize appends)", len(lines))
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "aaaaaaaa ") {
			t.Errorf("malformed line: %q", l)
		}
	}
}

// Given: 空 ID
// When: AppendSecurityTiming
// Then: 短路(不建文件)
func TestAppendSecurityTiming_emptyIdShortCircuit(t *testing.T) {
	dir := t.TempDir()
	orig := securityTimingLogPath
	securityTimingLogPath = filepath.Join(dir, "timing.log")
	defer restoreSecurityTimingPath(orig) // PLUG-U2：关闭旧 fd 再置 nil（原泄漏）

	AppendSecurityTiming("", 100)

	if _, err := os.Stat(securityTimingLogPath); !os.IsNotExist(err) {
		t.Error("empty ID must short-circuit without creating file")
	}
}

// Given: 目录不存在
// When: AppendSecurityTiming
// Then: MkdirAll 兜底后正常写入
func TestAppendSecurityTiming_mkdirFallback(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "timing.log")
	orig := securityTimingLogPath
	securityTimingLogPath = nested
	defer restoreSecurityTimingPath(orig) // PLUG-U2：关闭旧 fd 再置 nil（原泄漏）

	AppendSecurityTiming("testid01", 42)

	data, err := os.ReadFile(nested)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "testid01 42" {
		t.Errorf("content=%q; want %q", data, "testid01 42")
	}
}

// Given: 正常调用
// When: securityTimingID
// Then: 16 字符 hex(8 字节;F62-29 扩容后)
func TestSecurityTimingID_length(t *testing.T) {
	id := securityTimingID()
	if len(id) != 16 {
		t.Errorf("len=%d; want 16 (8 bytes hex)", len(id))
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			t.Errorf("non-hex char %q in %q", c, id)
		}
	}
}

// restoreSecurityTimingPath 还原侧车路径并关闭旧 fd（PLUG-U2 第 69 轮 P5：
// 此前重置直接置 nil，每个相关测试泄漏一个 fd 句柄）。
func restoreSecurityTimingPath(orig string) {
	if securityTimingFd != nil {
		_ = securityTimingFd.Close()
		securityTimingFd = nil
	}
	securityTimingLogPath = orig
}

// PLUG-R1（第 69 轮 P4）：security_timing_pre/end 两 ServeHTTP 逐字重复收敛为
// recordSecurityTiming helper——钉 helper 契约：合法头对写一行「<id><suffix> <us>」，
// 缺头对零写入（静默降级语义不变）。
func TestRecordSecurityTiming_writesSuffixedLine(t *testing.T) {
	// Given 临时侧车路径 + 携带关联头对的请求（起始时间 12345µs 前）
	dir := t.TempDir()
	orig := securityTimingLogPath
	securityTimingLogPath = filepath.Join(dir, "timing.log")
	defer restoreSecurityTimingPath(orig)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, "abcdef0123456789")
	req.Header.Set(securityTimingStartHeader, strconv.FormatInt(time.Now().UnixNano()-12345000, 10))

	// When
	recordSecurityTiming(req, ":pre")

	// Then：恰好一行 <id>:pre <us>，耗时为正整数
	if securityTimingFd != nil {
		_ = securityTimingFd.Sync()
	}
	data, err := os.ReadFile(securityTimingLogPath)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 || parts[0] != "abcdef0123456789:pre" {
		t.Fatalf("line=%q, want %q", line, "abcdef0123456789:pre <us>")
	}
	if us, perr := strconv.ParseInt(parts[1], 10, 64); perr != nil || us <= 0 {
		t.Fatalf("duration=%q, want positive integer µs", parts[1])
	}

	// And 畸形形状：缺头对的请求零写入
	recordSecurityTiming(httptest.NewRequest(http.MethodGet, "/", nil), ":end")
	dataAfter, err := os.ReadFile(securityTimingLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(dataAfter) != string(data) {
		t.Fatalf("missing headers must write nothing: before=%q after=%q", data, dataAfter)
	}
}

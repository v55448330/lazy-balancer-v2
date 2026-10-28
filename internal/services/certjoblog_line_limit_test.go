package services

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestCertJobFileLogger_truncatesLinesBeforeRotation(t *testing.T) {
	const maxLineBytes = 4096
	useCertJobLogTestEnv(t, maxLineBytes+1)
	logger := NewCertJobFileLogger("lb_long_line")

	logger.Log("cleanup_warning", strings.Repeat("界", 2000)+strings.Repeat("x", 2000))
	logger.Log("stage", "short message")

	base := CertJobLogPath("lb_long_line")
	for generation, path := range []string{base, base + ".1"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read generation %d: %v", generation, err)
		}
		if int64(len(data)) > maxLineBytes+1 {
			t.Fatalf("generation %d size=%d, want at most one truncated line plus newline", generation, len(data))
		}
		line := strings.TrimSuffix(string(data), "\n")
		if !utf8.ValidString(line) {
			t.Fatalf("generation %d contains invalid UTF-8 after truncation", generation)
		}
		if len(line) > maxLineBytes {
			t.Fatalf("generation %d line bytes=%d, want <= %d", generation, len(line), maxLineBytes)
		}
		if strings.Contains(line, "\n") {
			t.Fatalf("generation %d contains multiple lines: %q", generation, line)
		}
	}

	rotated, err := os.ReadFile(base + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rotated), "行已截断") {
		t.Fatalf("long line lacks an explicit truncation marker: %q", rotated)
	}
	current, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(current), "short message") || strings.Contains(string(current), "行已截断") {
		t.Fatalf("short line changed unexpectedly: %q", current)
	}
	if got := len(strings.Split(strings.TrimSpace(string(current)), "\n")); got != 1 {
		t.Fatalf("current line count=%d, want 1 (%s)", got, fmt.Sprint(string(current)))
	}
}

// Given 证书签发错误串携带 CR、LF 与一段形似日志前缀的载荷。
// When 写入证书任务日志。
// Then 每次写日志仍只产出一行（换行被替换），载荷不得伪造出带时间戳前缀的
// 独立行。
func TestCertJobFileLoggerKeepsOneLinePerEntry(t *testing.T) {
	useCertJobLogTestEnv(t, 1<<20)
	logger := NewCertJobFileLogger("lb_newline")

	const forged = "[INFO] forged - injected"
	logger.Log("cleanup", "签发失败: "+forged+"\n继续\r\n结束\r")
	logger.Log("stage", "第二条")

	data, err := os.ReadFile(CertJobLogPath("lb_newline"))
	if err != nil {
		t.Fatalf("read cert job log: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("两次写日志应各占恰好一行，got %d 行: %q", len(lines), data)
	}
	if strings.ContainsAny(string(data), "\r") {
		t.Fatalf("CR 未归一: %q", data)
	}
	for i, line := range lines {
		if len(line) < len("2006/01/02 15:04:05") {
			t.Fatalf("第 %d 行过短，缺少前缀: %q", i+1, line)
		}
		if _, err := time.Parse("2006/01/02 15:04:05", line[:19]); err != nil {
			t.Fatalf("第 %d 行缺少统一时间戳前缀（伪造行）: %q", i+1, line)
		}
	}
	if !strings.Contains(lines[0], forged) {
		t.Fatalf("载荷正文被丢弃，只应替换换行符: %q", lines[0])
	}
}

package services

import (
	"fmt"
	"os"
	"strings"
	"testing"
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

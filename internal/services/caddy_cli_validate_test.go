package services

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestCaddyCLIValidateTimeoutMatchesInteractiveSaveBudget(t *testing.T) {
	if caddyCLIValidateTimeout <= 0 || caddyCLIValidateTimeout > 20*time.Second {
		t.Fatalf("CLI validation timeout=%s, want positive and no more than 20s", caddyCLIValidateTimeout)
	}
}

func TestExecCaddyValidate_classifiesSuccessRejectAndUnavailable(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "caddy")
	writeScript := func(body string) {
		t.Helper()
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("success", func(t *testing.T) {
		writeScript("#!/bin/sh\nexit 0\n")
		t.Setenv("PATH", dir)
		if err := execCaddyValidate([]byte(`{"apps":{}}`)); err != nil {
			t.Fatalf("validate success: %v", err)
		}
	})

	t.Run("reject", func(t *testing.T) {
		writeScript("#!/bin/sh\necho 'provision failed' >&2\nexit 1\n")
		t.Setenv("PATH", dir)
		err := execCaddyValidate([]byte(`{"apps":{}}`))
		if err == nil || errors.Is(err, ErrCLIValidatorUnavailable) || !strings.Contains(err.Error(), "拒绝配置") || !strings.Contains(err.Error(), "provision failed") {
			t.Fatalf("validate reject error=%v, want rejected with stderr", err)
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		err := execCaddyValidate([]byte(`{"apps":{}}`))
		if !errors.Is(err, ErrCLIValidatorUnavailable) {
			t.Fatalf("missing caddy error=%v, want ErrCLIValidatorUnavailable", err)
		}
	})

	// 阻塞形态：exec 直到超时被杀必须归为「校验器不可用」，不得被误判成
	// 「配置被拒」——前者调用方记日志放行（事务应用仍是最终门控），后者回滚
	// 用户写入。用可控 shell 脚本 sleep 模拟，超时注入毫秒级。
	t.Run("timeout is unavailable not rejected", func(t *testing.T) {
		// exec 让 shell 被 sleep 替换：超时 kill 直接命中进程本身，不必等
		// 子进程关闭继承的 stdout/stderr 管道（生产 caddy 不派生进程）。
		writeScript("#!/bin/sh\nexec sleep 10\n")
		// PATH 需同时含 caddy 桩（dir，优先）与系统命令（脚本内的 sleep）。
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		prev := caddyCLIValidateTimeout
		caddyCLIValidateTimeout = 200 * time.Millisecond
		t.Cleanup(func() { caddyCLIValidateTimeout = prev })

		err := execCaddyValidate([]byte(`{"apps":{}}`))
		if !errors.Is(err, ErrCLIValidatorUnavailable) {
			t.Fatalf("timeout error=%v, want ErrCLIValidatorUnavailable", err)
		}
		if err != nil && strings.Contains(err.Error(), "拒绝配置") {
			t.Fatalf("timeout 被误分类为配置被拒: %v", err)
		}
	})

	// 非零退出但输出为空：仍是「配置被拒」（退出码是唯一判据），error 不得
	// 为空/不得 panic，也不得因空输出退化成校验器不可用。
	t.Run("nonzero exit with empty output is rejected", func(t *testing.T) {
		writeScript("#!/bin/sh\nexit 1\n")
		t.Setenv("PATH", dir)

		err := execCaddyValidate([]byte(`{"apps":{}}`))
		if err == nil {
			t.Fatal("nonzero exit must not be treated as success")
		}
		if errors.Is(err, ErrCLIValidatorUnavailable) {
			t.Fatalf("nonzero exit misclassified as unavailable: %v", err)
		}
		if !strings.Contains(err.Error(), "拒绝配置") {
			t.Fatalf("nonzero exit error=%v, want 拒绝配置", err)
		}
	})
}

// 错误详情必须先按字节上限截断、再回退到合法 UTF-8
// 边界——先归一再按固定字节位硬切会把切口落在多字节字符中间（JSON 响应变成
// U+FFFD 乱码残片）。同时收集侧有界：异常巨量输出不得无界驻留内存。
func TestCaddyValidateDetail_truncatesBytesBeforeUTF8Normalization(t *testing.T) {
	// Given：切口恰落在多字节字符中间（1023 字节 ASCII + "中" 三字节）
	output := append(bytes.Repeat([]byte("a"), caddyErrorBodyMaxBytes-1), []byte("中")...)

	// When
	detail := boundedValidateDetail(output)

	// Then：带合法 UTF-8，且尾部半截 rune 被回退而非保留
	if !utf8.Valid(detail) {
		t.Fatalf("detail 含非法 UTF-8 字节: %q", detail)
	}
	if len(detail) > caddyErrorBodyMaxBytes {
		t.Fatalf("detail 长度 %d 超过上限 %d", len(detail), caddyErrorBodyMaxBytes)
	}
	if string(detail) != string(bytes.Repeat([]byte("a"), caddyErrorBodyMaxBytes-1)) {
		t.Fatalf("detail 尾部残留=%q, want 仅 ASCII 前缀（半个 rune 必须回退）", detail[len(detail)-8:])
	}
}

func TestCaddyValidateOutputCap_boundsCollectedOutput(t *testing.T) {
	// Given：上限 8 字节的收集器
	buf := &cappedOutputBuffer{limit: 8}

	// When：写入 16 字节（模拟异常巨量输出的分块）
	n, err := buf.Write([]byte("0123456789abcdef"))

	// Then：对子进程如实报告全额消费，缓冲区只保留上限内容
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 16 {
		t.Fatalf("Write 返回 %d, want 16（短写会让子进程误判）", n)
	}
	if got := buf.buf.String(); got != "01234567" {
		t.Fatalf("收集内容=%q, want 前 8 字节", got)
	}
}

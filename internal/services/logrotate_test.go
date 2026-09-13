package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeLogCleanup_stops_when_context_is_canceled(t *testing.T) {
	// Given
	ctx, cancel := context.WithCancel(context.Background())
	done := StartRuntimeLogCleanupContext(ctx, filepath.Join(t.TempDir(), "runtime.log"))

	// When
	cancel()
	<-done

	// Then
	select {
	case <-done:
	default:
		t.Fatal("runtime log cleanup did not stop")
	}
}

func TestRotatingFileWriter_Write_returns_rotation_reopen_error(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "runtime.log")
	writer, err := NewRotatingFileWriter(path)
	if err != nil {
		t.Fatalf("create rotating writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	runtimeLogSizeMB.Store(0)
	t.Cleanup(func() { runtimeLogSizeMB.Store(100) })
	writer.path = filepath.Join(path, "missing", "runtime.log")

	// When
	n, err := writer.Write([]byte("entry"))

	// Then
	if err == nil || n != 0 {
		t.Fatalf("rotation failure write n=%d err=%v, want no write and an error", n, err)
	}
	if !strings.Contains(err.Error(), "rotate log file") || strings.Contains(err.Error(), "file already closed") {
		t.Fatalf("write error=%q, want reopen failure", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("original log file disappeared: %v", statErr)
	}
}

// SECLB23-P3-1(第 23 轮审计):LogFileEnabled 恒 true 的用户裁定意图在裸二进制
// 部署落空——open() 不建父目录,/app/logs 不存在时恒回退 stdout。必须 MkdirAll。
func TestNewRotatingFileWriter_createsParentDirs(t *testing.T) {
	// Given: 不存在的嵌套父目录(模拟裸二进制无 /app/logs)
	path := filepath.Join(t.TempDir(), "app", "logs", "lazy-balancer.log")

	// When
	w, err := NewRotatingFileWriter(path)
	if err != nil {
		t.Fatalf("NewRotatingFileWriter with missing parent dirs: %v", err)
	}
	defer w.Close()

	// Then: 文件可写(父目录已建)
	if _, err := w.Write([]byte("test\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("log file not created: %v", err)
	}
}

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

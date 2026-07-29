package services

import (
	"context"
	"path/filepath"
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

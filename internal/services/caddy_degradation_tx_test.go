package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestApplyConfigFromTx_degradationDoesNotBlockOnOpenWriteTx(t *testing.T) {
	_, database := newClusterTestService(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	done := make(chan error, 1)
	go func() {
		done <- service.applyConfigLockedOpt(map[string]interface{}{
			caddyConfigDegradationKey: "受信代理渲染降级",
		}, true, false)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("degraded transactional apply: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transactional apply must not write caddy_apply_error on a second connection while tx holds the write lock")
	}
}

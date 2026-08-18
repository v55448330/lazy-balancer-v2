package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
)

func TestSyncService_Report_rejection_message_includes_response_body(t *testing.T) {
	// Given：主节点上报端点返回 403 并携带正文说明
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte("invalid token"))
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))

	// When
	err := service.Report(context.Background())

	// Then：错误信息附带状态码与正文摘要
	if err == nil {
		t.Fatal("report unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "主节点拒绝状态上报: 403") || !strings.Contains(err.Error(), "body=invalid token") {
		t.Fatalf("report error=%q, want status code plus body summary", err)
	}
}

func TestSyncService_Report_rejection_body_capped_to_200_chars(t *testing.T) {
	// Given：主节点返回超长正文，审计信息必须截断
	_, database := newClusterTestService(t)
	longBody := strings.Repeat("x", 600)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(longBody))
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))

	// When
	err := service.Report(context.Background())

	// Then
	if err == nil {
		t.Fatal("report unexpectedly succeeded")
	}
	prefix := "主节点拒绝状态上报: 401 body="
	if got := len(err.Error()) - len(prefix); got != 200 {
		t.Fatalf("body summary length=%d, want 200", got)
	}
}

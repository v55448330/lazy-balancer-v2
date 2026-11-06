package handlers

import (
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/services"
)

// TCP 拦截提示品牌注入（2026-11-06 用户裁定）：branding.json 未配置
// （空 app_name）→ 注入空串（services 侧回退裁定默认文案 Lazy Balancer v2，
// 而非 handlers 层填充的 "Lazy Balancer"）；显式配置原样透传。
func TestSyncDefaultLandingText_tcpNoticeBrandInjection(t *testing.T) {
	t.Cleanup(func() { services.SetTCPBlockNoticeBrand("") })
	dir := t.TempDir()
	write := func(content string) {
		if err := os.WriteFile(filepath.Join(dir, "branding.json"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(`{"app_name":"","footer_text":"","landing_text":"","version":""}`)
	if _, err := SyncDefaultLandingText(dir); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := services.TCPBlockNoticeBrand(); got != "" {
		t.Fatalf("未配置 app_name 注入 = %q, want 空串（回退裁定默认文案）", got)
	}

	write(`{"app_name":"甲板面板","footer_text":"","landing_text":"","version":""}`)
	if _, err := SyncDefaultLandingText(dir); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := services.TCPBlockNoticeBrand(); got != "甲板面板" {
		t.Fatalf("显式配置注入 = %q, want 原样透传", got)
	}
}

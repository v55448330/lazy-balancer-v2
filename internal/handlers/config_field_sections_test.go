package handlers

// U8-P4-1（Round 62 审计）：ConfigFieldSections 必须覆盖 config_changes.go
// planConfigChanges 全部 add() 字段，否则字段级审计归因落「全局配置」
// （github_token 曾漏——R72 同批字段，SYS-2 同族漏点）。
// 字段清单为 config_changes.go add() 首参的硬编码镜像（R-8 验证源直取；
// 两侧同步责任由本测试与 ConfigFieldSections 注释双向钉住）。

import (
	"testing"

	"lazy-balancer-v2/internal/services"
)

// configChangeFieldTokens planConfigChanges 全部 add() 首参（令牌），
// 顺序与 config_changes.go 调用顺序一致。
var configChangeFieldTokens = []string{
	"acme_email",
	"dns_provider",
	"dns_credentials",
	"cert_expiry_days",
	"default_ca_provider_id",
	"cert_renewal_days",
	"cert_renewal_attempts",
	"log_level",
	"timezone",
	"github_proxy_url",
	"github_token",
	"audit_retention_months",
	"server_map_lat",
	"server_map_lon",
	"jwt_expire_minutes",
	"mfa_write_guard",
	"mfa_lockout_enabled",
	"trusted_proxy_enabled",
	"trusted_proxy_ranges",
	"trusted_proxy_range_refs",
	"trusted_proxy_headers",
	"trusted_proxy_strict",
	"task_log_size_mb",
	"audit_log_size_mb",
	"runtime_log_size_mb",
	"caddy_log_level",
	"caddy_log_size_mb",
	"request_body_max_size_mb",
	"http_read_timeout",
	"http_write_timeout",
	"http_idle_timeout",
	"upstream_keepalive_timeout",
	"proxy_dial_timeout",
	"proxy_response_header_timeout",
	"proxy_read_timeout",
	"proxy_write_timeout",
	"proxy_stream_timeout",
	"proxy_flush_interval",
	"proxy_stream_close_delay",
	"server_tokens_hidden",
	"access_log_json",
	"access_log_format",
}

func TestConfigFieldSections_coverAllConfigChangeFields(t *testing.T) {
	for _, field := range configChangeFieldTokens {
		section, ok := services.ConfigFieldSections[field]
		if !ok {
			t.Errorf("ConfigFieldSections missing add() field %q: audit attribution falls back to 全局配置", field)
			continue
		}
		if section == "" {
			t.Errorf("ConfigFieldSections[%q] has empty section", field)
		}
	}
}

func TestConfigFieldSections_recentDriftKeysPinned(t *testing.T) {
	// 近两轮漂移键显式钉死（U8-P4-1 + SYS-2），防止镜像清单漏列时静默通过。
	pinned := map[string]string{
		"github_token":        "基础设置",
		"mfa_write_guard":     "基础设置",
		"mfa_lockout_enabled": "基础设置",
	}
	for field, want := range pinned {
		if got := services.ConfigFieldSections[field]; got != want {
			t.Fatalf("ConfigFieldSections[%q]=%q, want %q", field, got, want)
		}
	}
}

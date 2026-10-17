package services

import (
	"encoding/json"
	"strings"
	"testing"
)

// F73 修复：全局请求体大小必须贯通到渲染——此前 SingleRuleConfig 构造块漏填
// GlobalRequestBodyMaxSizeMB（填了 keepalive/server_tokens 两个兄弟却漏了本字段），
// resolveRuleOverrides 恒读 0 → 兜底 128，用户设置的非默认值从未生效。
func TestGenerateCaddyConfig_globalRequestBodyMaxSizeReachesRender(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_rb_global", false)
	if _, err := database.Exec("UPDATE global_config SET request_body_max_size_mb=64 WHERE id=1"); err != nil {
		t.Fatalf("seed global: %v", err)
	}
	cfg := generateCaddyConfigFromStore(database)
	raw, _ := json.Marshal(cfg)
	s := strings.ReplaceAll(string(raw), " ", "")
	if strings.Contains(s, `"max_size":134217728`) {
		t.Fatalf("渲染出兜底 128MiB——全局 64 未贯通（构造块漏填 GlobalRequestBodyMaxSizeMB）")
	}
	if !strings.Contains(s, `"max_size":67108864`) {
		t.Fatalf("渲染缺少全局 64MiB（67108864）")
	}
}

// 规则级覆盖优先级回归：规则级 32 优先于全局 64。
func TestGenerateCaddyConfig_ruleLevelRequestBodyOverridesGlobal(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_rb_rule", false)
	if _, err := database.Exec("UPDATE global_config SET request_body_max_size_mb=64 WHERE id=1"); err != nil {
		t.Fatalf("seed global: %v", err)
	}
	if _, err := database.Exec("UPDATE lb_rules SET request_body_max_size_mb=32 WHERE caddy_id='lb_rb_rule'"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	cfg := generateCaddyConfigFromStore(database)
	raw, _ := json.Marshal(cfg)
	s := strings.ReplaceAll(string(raw), " ", "")
	if strings.Contains(s, `"max_size":67108864`) {
		t.Fatalf("规则级 32 应优先于全局 64，渲染却含 64MiB")
	}
	if !strings.Contains(s, `"max_size":33554432`) {
		t.Fatalf("渲染缺少规则级 32MiB（33554432）")
	}
}

// F73 全量值贯通核查（用户质询后的系统性补验）：全部全局 Caddy 配置项设非默认
// 哨兵值 → 渲染 → 逐项断言渲染值=设置值。历史上只验默认值形状导致 request_body
// 全局断裂漏检多年——本测试以非默认形态钉住全部全局→渲染链。
func TestGenerateCaddyConfig_allGlobalOverridesReachRender(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb贯通", false)
	seedGenerationRule(t, database, "lb_global_probe", false)
	database.Exec("UPDATE lb_rules SET protocol='http' WHERE caddy_id='lb_global_probe'")
	sentinel := map[string]any{
		"request_body_max_size_mb": 64, "http_read_timeout": 33, "http_write_timeout": 44,
		"http_idle_timeout": 55, "upstream_keepalive_timeout": 66,
		"proxy_dial_timeout": 11, "proxy_response_header_timeout": 22, "proxy_read_timeout": 77,
		"proxy_write_timeout": 88, "proxy_stream_timeout": 99, "proxy_flush_interval": -1,
		"proxy_stream_close_delay": 7,
	}
	for col, v := range sentinel {
		if _, err := database.Exec("UPDATE global_config SET "+col+"=? WHERE id=1", v); err != nil {
			t.Fatalf("seed %s: %v", col, err)
		}
	}
	cfg := generateCaddyConfigFromStore(database)
	raw, _ := json.Marshal(cfg)
	s := strings.ReplaceAll(string(raw), " ", "")
	want := []string{
		`"max_size":67108864`,   // request_body 64MiB
		`"read_timeout":"33s"`,  // http 读
		`"write_timeout":"44s"`, // http 写
		`"idle_timeout":"55s"`,  // http 空闲
		`"dial_timeout":"11s"`,  // 代理拨号
		`"response_header_timeout":"22s"`,
		`"read_timeout":"77s"`,
		`"write_timeout":"88s"`,
		`"idle_timeout":"66s"`, // 上游 keepalive
		`"stream_timeout":"99s"`,
		`"flush_interval":"-1s"`,
		`"stream_close_delay":"7s"`,
	}
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("渲染缺少全局哨兵值 %s", w)
		}
	}
}

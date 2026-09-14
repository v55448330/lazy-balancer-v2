package services

import (
	"encoding/json"
	"strings"
	"testing"
)

// LB-04：health_check_timeout 默认值统一为 2——NULL 行（生成 SQL 的 COALESCE）
// 与显式 0 行（渲染兜底）生成的 active health check timeout 均应为 "2s"。
// 此前读侧/渲染侧兜底为 5，与写侧默认 2 分裂。
func TestGenerateCaddyConfig_activeHealthTimeout_defaults_to_2_for_null_and_zero_rows(t *testing.T) {
	// Given：两条启用主动健康检查的规则；timeout 分别显式置 NULL（建表列有
	// DEFAULT 5，须 UPDATE 才能构造 NULL 行——COALESCE 读取口径的靶点）与 0
	//（渲染兜底的靶点）
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_hc_null", false)
	seedGenerationRule(t, database, "lb_hc_zero", false)
	if _, err := database.Exec(`UPDATE lb_rules SET enable_active_health_check=1, listen_port=18081, health_check_timeout=NULL WHERE caddy_id='lb_hc_null'`); err != nil {
		t.Fatalf("enable active health check (null row): %v", err)
	}
	if _, err := database.Exec(`UPDATE lb_rules SET enable_active_health_check=1, health_check_timeout=0, listen_port=18082 WHERE caddy_id='lb_hc_zero'`); err != nil {
		t.Fatalf("enable active health check (zero row): %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	body, err := json.Marshal(generated["apps"])
	if err != nil {
		t.Fatalf("marshal generated apps: %v", err)
	}
	if got := strings.Count(string(body), `"timeout":"2s"`); got != 2 {
		t.Fatalf("active health timeout \"2s\" count=%d (body=%s), want 2 (NULL 行与 0 值行各一)", got, body)
	}
	if strings.Contains(string(body), `"timeout":"5s"`) {
		t.Fatalf("active health timeout still renders 5s, want unified default 2s: %s", body)
	}
}

// LB25-P2-1(第 25 轮审计):TCP 主动健检 timeout 渲染兜底 5s 与 LB-04 统一 2s
// 分裂——写侧默认 2(rules.go:789)+COALESCE 读取 2+HTTP 渲染兜底 2,独 TCP 链=5。
func TestBuildTCPServer_activeHealthTimeout_defaults_to_2(t *testing.T) {
	// Given: TCP 规则启用主动健检,timeout=0(导入路径可达 0 值)
	cfg := SingleRuleConfig{
		ListenPort:              16379,
		Protocol:                "tcp",
		EnableActiveHealthCheck: true,
		HealthCheckTimeout:      0, // 渲染兜底靶点
		Upstreams:               []UpstreamConfig{{Host: "127.0.0.1", Port: 6379, Weight: 1, Enabled: true}},
	}

	// When
	server := buildTCPServer(cfg)
	body, _ := json.Marshal(server)

	// Then: timeout 统一为 2s(与 HTTP 链/LB-04 钉口径一致)
	if strings.Contains(string(body), `"timeout":"5s"`) {
		t.Fatalf("TCP active health timeout still renders 5s, want unified default 2s: %s", body)
	}
	if !strings.Contains(string(body), `"timeout":"2s"`) {
		t.Fatalf("TCP active health timeout missing 2s: %s", body)
	}
}

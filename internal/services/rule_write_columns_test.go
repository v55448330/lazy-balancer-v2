package services

// 钉测试：唯一事实源（lbRuleWriteColumns）与 lb_rules schema、
// 值投影、快照导出 SELECT 的三向对账。

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// testLbRuleFullyPopulated 构造全部写侧字段非零值的规则模型（零值会掩盖
// 列/值错位——投影错列时零值读回仍为零）。
func testLbRuleFullyPopulated(t *testing.T) models.LbRule {
	return models.LbRule{
		ID: 42, CaddyID: "lb_p231_full", Name: "full", Description: "desc",
		Protocol: "http", Domain: "full.example.test", ListenPort: 18443, Strategy: "cookie",
		DynamicDNS: true, EnableDnsServer: true, DnsServer: "8.8.8.8", DnsFamily: "ipv6",
		HealthCheckPath: "/healthz", HealthCheckInterval: 11, HealthCheckTimeout: 3,
		HealthCheckUnhealthyThreshold: 4, HealthCheckHealthyThreshold: 5,
		EnableActiveHealthCheck: true, TCPHealthCheckPort: 19001, TCPProxyProtocol: true,
		TCPTryDuration: 7, TCPTryInterval: 251,
		RequestBodyMaxSizeMB: 13, UpstreamKeepaliveTimeout: 17, ServerTokensHidden: 2,
		NTLMCompatible: 1, UpstreamForceHTTP1: 1, CustomRoutesEnabled: true,
		ProxyDialTimeout: 21, ProxyResponseHeaderTimeout: 22, ProxyReadTimeout: 23,
		ProxyWriteTimeout: 24, ProxyStreamTimeout: 25, ProxyFlushInterval: 26, ProxyStreamCloseDelay: 27,
		HostHeader: "host.example.test", HealthCheckHost: "probe.example.test",
		EnableTLS: true, TLSSource: "manual", ACMEConfigID: 31, CAProviderID: 32,
		TLSCert: "CERT-PEM", TLSKey: "KEY-PEM", TLSHTTPRedirect: true,
		EnableCompress: true, CompressTypes: "zstd", Enabled: true, LogEnabled: true,
		CreatedBy: 51, UpdatedBy: 52,
		CreatedAt:         time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		UpdatedAt:         models.JSONNullTime{NullTime: mustParseTime(t, "2026-03-05 06:07:08")},
		BlockPageStage1ID: 61, BlockPageStage1Status: 403,
		BlockPageStage3ID: 63, BlockPageStage3Status: 503,
	}
}

// testLbRuleExpectedColumnValue 是投影的独立对照（按列名硬编码期望值——
// 与生产投影同字段即报错，防「投影与断言共用同一错误映射」的假绿）。
func testLbRuleExpectedColumnValue(rule *models.LbRule, column string) any {
	switch column {
	case "id":
		return rule.ID
	case "caddy_id":
		return rule.CaddyID
	case "name":
		return rule.Name
	case "description":
		return rule.Description
	case "protocol":
		return rule.Protocol
	case "domain":
		return rule.Domain
	case "listen_port":
		return rule.ListenPort
	case "strategy":
		return rule.Strategy
	case "dynamic_dns":
		return rule.DynamicDNS
	case "enable_dns_server":
		return rule.EnableDnsServer
	case "dns_server":
		return rule.DnsServer
	case "dns_family":
		return rule.DnsFamily
	case "health_check_path":
		return rule.HealthCheckPath
	case "health_check_interval":
		return rule.HealthCheckInterval
	case "health_check_timeout":
		return rule.HealthCheckTimeout
	case "health_check_unhealthy_threshold":
		return rule.HealthCheckUnhealthyThreshold
	case "health_check_healthy_threshold":
		return rule.HealthCheckHealthyThreshold
	case "enable_active_health_check":
		return rule.EnableActiveHealthCheck
	case "tcp_health_check_port":
		return rule.TCPHealthCheckPort
	case "tcp_proxy_protocol":
		return rule.TCPProxyProtocol
	case "tcp_try_duration":
		return rule.TCPTryDuration
	case "tcp_try_interval":
		return rule.TCPTryInterval
	case "request_body_max_size_mb":
		return rule.RequestBodyMaxSizeMB
	case "upstream_keepalive_timeout":
		return rule.UpstreamKeepaliveTimeout
	case "server_tokens_hidden":
		return rule.ServerTokensHidden
	case "ntlm_compatible":
		return rule.NTLMCompatible
	case "upstream_force_http1":
		return rule.UpstreamForceHTTP1
	case "custom_routes_enabled":
		return rule.CustomRoutesEnabled
	case "proxy_dial_timeout":
		return rule.ProxyDialTimeout
	case "proxy_response_header_timeout":
		return rule.ProxyResponseHeaderTimeout
	case "proxy_read_timeout":
		return rule.ProxyReadTimeout
	case "proxy_write_timeout":
		return rule.ProxyWriteTimeout
	case "proxy_stream_timeout":
		return rule.ProxyStreamTimeout
	case "proxy_flush_interval":
		return rule.ProxyFlushInterval
	case "proxy_stream_close_delay":
		return rule.ProxyStreamCloseDelay
	case "host_header":
		return rule.HostHeader
	case "health_check_host":
		return rule.HealthCheckHost
	case "enable_tls":
		return rule.EnableTLS
	case "tls_source":
		return rule.TLSSource
	case "acme_config_id":
		return rule.ACMEConfigID
	case "ca_provider_id":
		return rule.CAProviderID
	case "tls_cert":
		return rule.TLSCert
	case "tls_key":
		return rule.TLSKey
	case "tls_http_redirect":
		return rule.TLSHTTPRedirect
	case "enable_compress":
		return rule.EnableCompress
	case "compress_types":
		return rule.CompressTypes
	case "enabled":
		return rule.Enabled
	case "log_enabled":
		return rule.LogEnabled
	case "created_by":
		return rule.CreatedBy
	case "created_at":
		return "2026-03-04 05:06:07"
	case "updated_at":
		return "2026-03-05 06:07:08"
	case "updated_by":
		return rule.UpdatedBy
	case "block_page_stage1_id":
		return rule.BlockPageStage1ID
	case "block_page_stage1_status":
		return rule.BlockPageStage1Status
	case "block_page_stage3_id":
		return rule.BlockPageStage3ID
	case "block_page_stage3_status":
		return rule.BlockPageStage3Status
	}
	panic("未覆盖列: " + column)
}

func mustParseTime(t *testing.T, value string) sql.NullTime {
	t.Helper()
	parsed, err := time.ParseInLocation("2006-01-02 15:04:05", value, time.UTC)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return sql.NullTime{Time: parsed, Valid: true}
}

// Given 唯一事实源。
// When 与真实 schema（PRAGMA table_info(lb_rules)）对账。
// Then 列集合必须逐一相等——schema 加列而事实源未更新（或反之）即失败。
func TestLbRuleWriteColumns_matchSchema(t *testing.T) {
	_, database := newClusterTestService(t)

	rows, err := database.Query(`SELECT name FROM pragma_table_info('lb_rules')`)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	defer rows.Close()
	schema := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan schema column: %v", err)
		}
		schema[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema: %v", err)
	}

	columns := lbRuleWriteColumns()
	if len(columns) != len(schema) {
		t.Fatalf("事实源列数=%d, schema 列数=%d——新增列必须同步 lbRuleWriteColumns", len(columns), len(schema))
	}
	seen := map[string]bool{}
	for _, column := range columns {
		if !schema[column] {
			t.Fatalf("事实源列 %q 不在 lb_rules schema 中", column)
		}
		if seen[column] {
			t.Fatalf("事实源列 %q 重复", column)
		}
		seen[column] = true
	}
}

// Given 唯一事实源与值投影。
// When 逐列投影一个全字段非默认的模型。
// Then 投影值必须与模型字段逐列对应（防列序/值序脱节静默写错列）。
func TestLbRuleInsertArgs_projectModelPerColumn(t *testing.T) {
	rule := testLbRuleFullyPopulated(t)
	columns := lbRuleWriteColumns()
	args := LbRuleInsertArgs(&rule, columns)
	if len(args) != len(columns) {
		t.Fatalf("args=%d, columns=%d", len(args), len(columns))
	}
	for i, column := range columns {
		want := testLbRuleExpectedColumnValue(&rule, column)
		if fmt.Sprintf("%v", args[i]) != fmt.Sprintf("%v", want) {
			t.Errorf("列 %s 投影值=%v (%T), want %v (%T)", column, args[i], args[i], want, want)
		}
	}
}

// Given 排除清单派生。
// When 排除 id/created_at/updated_by。
// Then 子集缺且仅缺这三列，顺序与全量一致。
func TestLbRuleInsertColumns_excludesOnlyNamed(t *testing.T) {
	full := lbRuleWriteColumns()
	subset := LbRuleInsertColumns("id", "created_at", "updated_by")
	if len(subset) != len(full)-3 {
		t.Fatalf("subset=%d, want %d", len(subset), len(full)-3)
	}
	dropped := map[string]bool{"id": true, "created_at": true, "updated_by": true}
	j := 0
	for _, column := range full {
		if dropped[column] {
			continue
		}
		if subset[j] != column {
			t.Fatalf("子集第 %d 列=%s, want %s（顺序漂移）", j, subset[j], column)
		}
		j++
	}
}

// Given 唯一事实源派生的 INSERT。
// When 全量列 INSERT 后经快照导出读回。
// Then 标量字段逐字段相等（写侧清单与快照读侧投影同序同形）。
func TestLbRuleInsertSQL_snapshotSelectRoundTrip(t *testing.T) {
	service, database := newClusterTestService(t)
	rule := testLbRuleFullyPopulated(t)
	rule.CaddyID = "lb_p231_roundtrip"
	// manual 源携带 ACME/CA 引用是写路径已不可能产生的跨模式残留，会在传输
	// 归一时清零（见 rule_transport_cross_mode_test）。本用例验证「写侧可产生
	// 形态」的列往返，故取一致形态：manual 只保留证书材料。
	rule.ACMEConfigID = 0
	rule.CAProviderID = 0

	columns := lbRuleWriteColumns()
	if _, err := database.Exec(LbRuleInsertSQL(columns), LbRuleInsertArgs(&rule, columns)...); err != nil {
		t.Fatalf("insert via single-source: %v", err)
	}

	exported, err := service.snapshotRules(t.Context(), database)
	if err != nil {
		t.Fatalf("snapshot rules: %v", err)
	}
	if len(exported) != 1 {
		t.Fatalf("exported=%d, want 1", len(exported))
	}
	assertLbRuleScalarFieldsEqual(t, &rule, &exported[0])
}

func assertLbRuleScalarFieldsEqual(t *testing.T, want, got *models.LbRule) {
	t.Helper()
	mismatches := []string{}
	check := func(field string, a, b any) {
		if fmt.Sprintf("%v", a) != fmt.Sprintf("%v", b) {
			mismatches = append(mismatches, fmt.Sprintf("%s: wrote %v read %v", field, a, b))
		}
	}
	check("ID", want.ID, got.ID)
	check("CaddyID", want.CaddyID, got.CaddyID)
	check("Name", want.Name, got.Name)
	check("Description", want.Description, got.Description)
	check("Protocol", want.Protocol, got.Protocol)
	check("Domain", want.Domain, got.Domain)
	check("ListenPort", want.ListenPort, got.ListenPort)
	check("Strategy", want.Strategy, got.Strategy)
	check("DynamicDNS", want.DynamicDNS, got.DynamicDNS)
	check("EnableDnsServer", want.EnableDnsServer, got.EnableDnsServer)
	check("DnsServer", want.DnsServer, got.DnsServer)
	check("DnsFamily", want.DnsFamily, got.DnsFamily)
	check("HealthCheckPath", want.HealthCheckPath, got.HealthCheckPath)
	check("HealthCheckInterval", want.HealthCheckInterval, got.HealthCheckInterval)
	check("HealthCheckTimeout", want.HealthCheckTimeout, got.HealthCheckTimeout)
	check("HealthCheckUnhealthyThreshold", want.HealthCheckUnhealthyThreshold, got.HealthCheckUnhealthyThreshold)
	check("HealthCheckHealthyThreshold", want.HealthCheckHealthyThreshold, got.HealthCheckHealthyThreshold)
	check("EnableActiveHealthCheck", want.EnableActiveHealthCheck, got.EnableActiveHealthCheck)
	check("TCPHealthCheckPort", want.TCPHealthCheckPort, got.TCPHealthCheckPort)
	check("TCPProxyProtocol", want.TCPProxyProtocol, got.TCPProxyProtocol)
	check("TCPTryDuration", want.TCPTryDuration, got.TCPTryDuration)
	check("TCPTryInterval", want.TCPTryInterval, got.TCPTryInterval)
	check("RequestBodyMaxSizeMB", want.RequestBodyMaxSizeMB, got.RequestBodyMaxSizeMB)
	check("UpstreamKeepaliveTimeout", want.UpstreamKeepaliveTimeout, got.UpstreamKeepaliveTimeout)
	check("ServerTokensHidden", want.ServerTokensHidden, got.ServerTokensHidden)
	check("NTLMCompatible", want.NTLMCompatible, got.NTLMCompatible)
	check("UpstreamForceHTTP1", want.UpstreamForceHTTP1, got.UpstreamForceHTTP1)
	check("CustomRoutesEnabled", want.CustomRoutesEnabled, got.CustomRoutesEnabled)
	check("ProxyDialTimeout", want.ProxyDialTimeout, got.ProxyDialTimeout)
	check("ProxyResponseHeaderTimeout", want.ProxyResponseHeaderTimeout, got.ProxyResponseHeaderTimeout)
	check("ProxyReadTimeout", want.ProxyReadTimeout, got.ProxyReadTimeout)
	check("ProxyWriteTimeout", want.ProxyWriteTimeout, got.ProxyWriteTimeout)
	check("ProxyStreamTimeout", want.ProxyStreamTimeout, got.ProxyStreamTimeout)
	check("ProxyFlushInterval", want.ProxyFlushInterval, got.ProxyFlushInterval)
	check("ProxyStreamCloseDelay", want.ProxyStreamCloseDelay, got.ProxyStreamCloseDelay)
	check("HostHeader", want.HostHeader, got.HostHeader)
	check("HealthCheckHost", want.HealthCheckHost, got.HealthCheckHost)
	check("EnableTLS", want.EnableTLS, got.EnableTLS)
	check("TLSSource", want.TLSSource, got.TLSSource)
	check("ACMEConfigID", want.ACMEConfigID, got.ACMEConfigID)
	check("CAProviderID", want.CAProviderID, got.CAProviderID)
	check("TLSCert", want.TLSCert, got.TLSCert)
	check("TLSKey", want.TLSKey, got.TLSKey)
	check("TLSHTTPRedirect", want.TLSHTTPRedirect, got.TLSHTTPRedirect)
	check("EnableCompress", want.EnableCompress, got.EnableCompress)
	check("CompressTypes", want.CompressTypes, got.CompressTypes)
	check("Enabled", want.Enabled, got.Enabled)
	check("LogEnabled", want.LogEnabled, got.LogEnabled)
	check("CreatedBy", want.CreatedBy, got.CreatedBy)
	check("UpdatedBy", want.UpdatedBy, got.UpdatedBy)
	check("CreatedAt", want.CreatedAt.UTC(), got.CreatedAt.UTC())
	check("UpdatedAt.Valid", want.UpdatedAt.Valid, got.UpdatedAt.Valid)
	if want.UpdatedAt.Valid && got.UpdatedAt.Valid {
		check("UpdatedAt", want.UpdatedAt.Time.UTC(), got.UpdatedAt.Time.UTC())
	}
	check("BlockPageStage1ID", want.BlockPageStage1ID, got.BlockPageStage1ID)
	check("BlockPageStage1Status", want.BlockPageStage1Status, got.BlockPageStage1Status)
	check("BlockPageStage3ID", want.BlockPageStage3ID, got.BlockPageStage3ID)
	check("BlockPageStage3Status", want.BlockPageStage3Status, got.BlockPageStage3Status)
	if len(mismatches) > 0 {
		t.Fatalf("快照往返字段不一致:\n%s", strings.Join(mismatches, "\n"))
	}
}

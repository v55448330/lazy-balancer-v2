package services

// 规则写路径列清单与值投影唯一事实源。
// 此前 CreateRule/DuplicateRule/集群 apply（insertSnapshotRules）/快照导出
// （snapshotRules SELECT）四处各自手写列清单，已出现形态差异（Duplicate 显式
// 写审计四列、Create 依赖默认）；新增列必须同时改多处，漏一处即「保存成功
// 但与快照/副本不同形」。
//
// lbRuleColumnSpecs 是唯一手写处（规范序=集群镜像序，id 先行）；写侧 INSERT
// 列清单/语句/值投影与快照 SELECT 投影全部由此机械派生。parity 钉测
// （rule_write_columns_test.go）把 specs 与 lb_rules schema 逐列锁死——
// schema 加列而 specs 未更新即测试失败。

import (
	"strings"

	"lazy-balancer-v2/internal/models"
)

// lbRuleColumnSpec 逐列定义：name 为写侧列名；snapshotExpr 为快照导出读侧
// 投影（NULL 收敛口径，与既有 snapshotRules 逐列一致——快照哈希主从对齐
// 依赖该口径，不得随意改默认值）。
type lbRuleColumnSpec struct {
	name         string
	snapshotExpr string
}

// lbRuleColumnSpecs 规范序唯一事实源。列集合必须与 lb_rules schema 完全一致
// （parity 钉测强制）。
var lbRuleColumnSpecs = []lbRuleColumnSpec{
	{"id", "COALESCE(id,0)"},
	{"caddy_id", "COALESCE(caddy_id,'')"},
	{"name", "name"},
	{"description", "COALESCE(description,'')"},
	{"protocol", "protocol"},
	{"domain", "COALESCE(domain,'')"},
	{"listen_port", "listen_port"},
	{"strategy", "COALESCE(strategy,'weighted_round_robin')"},
	{"dynamic_dns", "COALESCE(dynamic_dns,0)"},
	{"enable_dns_server", "COALESCE(enable_dns_server,0)"},
	{"dns_server", "COALESCE(dns_server,'')"},
	{"dns_family", "COALESCE(dns_family,'ipv4')"},
	{"health_check_path", "COALESCE(health_check_path,'')"},
	{"health_check_interval", "COALESCE(health_check_interval,10)"},
	{"health_check_timeout", "COALESCE(health_check_timeout,2)"},
	{"health_check_unhealthy_threshold", "COALESCE(health_check_unhealthy_threshold,3)"},
	{"health_check_healthy_threshold", "COALESCE(health_check_healthy_threshold,2)"},
	{"enable_active_health_check", "COALESCE(enable_active_health_check,0)"},
	{"tcp_health_check_port", "COALESCE(tcp_health_check_port,0)"},
	{"tcp_proxy_protocol", "COALESCE(tcp_proxy_protocol,0)"},
	{"tcp_try_duration", "COALESCE(tcp_try_duration,0)"},
	{"tcp_try_interval", "COALESCE(tcp_try_interval,250)"},
	{"request_body_max_size_mb", "COALESCE(request_body_max_size_mb,0)"},
	{"upstream_keepalive_timeout", "COALESCE(upstream_keepalive_timeout,0)"},
	{"server_tokens_hidden", "COALESCE(server_tokens_hidden,0)"},
	{"ntlm_compatible", "COALESCE(ntlm_compatible,0)"},
	{"upstream_force_http1", "COALESCE(upstream_force_http1,0)"},
	{"custom_routes_enabled", "COALESCE(custom_routes_enabled,0)"},
	{"proxy_dial_timeout", "COALESCE(proxy_dial_timeout,0)"},
	{"proxy_response_header_timeout", "COALESCE(proxy_response_header_timeout,0)"},
	{"proxy_read_timeout", "COALESCE(proxy_read_timeout,0)"},
	{"proxy_write_timeout", "COALESCE(proxy_write_timeout,0)"},
	{"proxy_stream_timeout", "COALESCE(proxy_stream_timeout,0)"},
	{"proxy_flush_interval", "COALESCE(proxy_flush_interval,0)"},
	{"proxy_stream_close_delay", "COALESCE(proxy_stream_close_delay,0)"},
	{"host_header", "COALESCE(host_header,'')"},
	{"health_check_host", "COALESCE(health_check_host,'')"},
	{"enable_tls", "COALESCE(enable_tls,0)"},
	{"tls_source", "COALESCE(tls_source,'manual')"},
	{"acme_config_id", "COALESCE(acme_config_id,0)"},
	{"ca_provider_id", "COALESCE(ca_provider_id,0)"},
	{"tls_cert", "COALESCE(tls_cert,'')"},
	{"tls_key", "COALESCE(tls_key,'')"},
	{"tls_http_redirect", "COALESCE(tls_http_redirect,0)"},
	{"enable_compress", "COALESCE(enable_compress,0)"},
	{"compress_types", "COALESCE(compress_types,'gzip')"},
	{"enabled", "IIF(enabled IN ('1',1),1,0)"},
	{"log_enabled", "COALESCE(log_enabled,0)"},
	{"created_by", "COALESCE(created_by,0)"},
	{"created_at", "created_at"},
	{"updated_at", "updated_at"},
	{"updated_by", "COALESCE(updated_by,0)"},
	{"block_page_stage1_id", "COALESCE(block_page_stage1_id,0)"},
	{"block_page_stage1_status", "COALESCE(block_page_stage1_status,0)"},
	{"block_page_stage3_id", "COALESCE(block_page_stage3_id,0)"},
	{"block_page_stage3_status", "COALESCE(block_page_stage3_status,0)"},
}

// lbRuleWriteColumns 返回规则写侧全量列清单（规范序，含 id 与审计四列）。
// 每次返回新切片，调用方不得假定共享底层数组。
func lbRuleWriteColumns() []string {
	columns := make([]string, len(lbRuleColumnSpecs))
	for i, spec := range lbRuleColumnSpecs {
		columns[i] = spec.name
	}
	return columns
}

// LbRuleInsertColumns 派生 INSERT 列子集（规范序保持）：
//   - 从端镜像（insertSnapshotRules）：不排除任何列（保留主端 id 与审计列）
//   - 复制（DuplicateRule）：排除 id（AUTOINCREMENT 分配新主键）
//   - 新建（CreateRule）：排除 id/created_at/updated_by（主键自增分配、
//     created_at 走 schema 默认、updated_by 留 NULL 待首次更新）
func LbRuleInsertColumns(exclude ...string) []string {
	if len(exclude) == 0 {
		return lbRuleWriteColumns()
	}
	dropped := make(map[string]bool, len(exclude))
	for _, column := range exclude {
		dropped[column] = true
	}
	columns := make([]string, 0, len(lbRuleColumnSpecs)-len(exclude))
	for _, spec := range lbRuleColumnSpecs {
		if !dropped[spec.name] {
			columns = append(columns, spec.name)
		}
	}
	return columns
}

// LbRuleInsertSQL 按列清单生成 INSERT 语句（占位符数与列数一致）。
func LbRuleInsertSQL(columns []string) string {
	return "INSERT INTO lb_rules (" + strings.Join(columns, ", ") + ") VALUES (" +
		strings.TrimSuffix(strings.Repeat("?, ", len(columns)), ", ") + ")"
}

// LbRuleInsertArgs 按 columns 顺序从模型投影写侧值。时间列统一落 UTC
// 「2006-01-02 15:04:05」文本（与 Create/Duplicate 既有落库形态一致；
// 快照读侧全部按 time.Time 解析，往返同一时刻，节哈希两端对齐）。
func LbRuleInsertArgs(rule *models.LbRule, columns []string) []any {
	args := make([]any, len(columns))
	for i, column := range columns {
		args[i] = lbRuleWriteValue(rule, column)
	}
	return args
}

func lbRuleWriteValue(rule *models.LbRule, column string) any {
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
		return rule.CreatedAt.UTC().Format(crsTimeLayout)
	case "updated_at":
		if !rule.UpdatedAt.Valid {
			return nil
		}
		return rule.UpdatedAt.Time.UTC().Format(crsTimeLayout)
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
	panic("lbRuleWriteValue: 未知列 " + column)
}

// lbRuleSnapshotSelectSQL 生成快照导出 SELECT（投影 expr 规范序，与写侧
// 列清单同源——snapshotRules 不再手写列清单）。
func lbRuleSnapshotSelectSQL() string {
	exprs := make([]string, len(lbRuleColumnSpecs))
	for i, spec := range lbRuleColumnSpecs {
		exprs[i] = spec.snapshotExpr
	}
	return "SELECT " + strings.Join(exprs, ", ") + " FROM lb_rules ORDER BY caddy_id"
}

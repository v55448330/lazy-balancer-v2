package db

import "testing"

// 「enable_tls=1 且证书或私钥非空」——TCP+enable_tls=1+双空证书的存量行不被
// 迁移选中（归一函数 normalizeRuleForTransport 只要 EnableTLS=true 就清），
// 主端 DB/导出 canonical/从端落库三面同值不变量对该形态不成立。修复=WHERE
// TLS 段放宽为 OR enable_tls=1，与归一函数谓词逐字对齐。
func TestMigrateTCPRuleDeadFields_clears_tcp_enable_tls_with_empty_certs(t *testing.T) {
	// Given：真实 DB。TCP 行唯一入选特征是 enable_tls=1（其余七字段全零、
	// 证书双空=列默认 NULL）；另放一行 HTTP+TLS 控制行（迁移不得触碰非 TCP 行）。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port, enable_tls, compress_types)
		VALUES (1, 'lb_cl2tcp', 'cl2-tcp', 'tcp', '', 9443, 1, '')`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port, enable_tls, tls_cert, tls_key)
		VALUES (2, 'lb_cl2http', 'cl2-http', 'http', 'cl2.example.test', 8443, 1, 'cert', 'key')`); err != nil {
		t.Fatalf("seed http rule: %v", err)
	}

	// When
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Then：TCP 行 enable_tls 归 0、证书材料清空；HTTP 行原样保留。
	var tcpTLS, httpTLS int
	var tcpCert, tcpKey string
	if err := database.QueryRow(`SELECT COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id='lb_cl2tcp'`).
		Scan(&tcpTLS, &tcpCert, &tcpKey); err != nil {
		t.Fatalf("read tcp rule: %v", err)
	}
	if tcpTLS != 0 || tcpCert != "" || tcpKey != "" {
		t.Fatalf("tcp rule after migration: enable_tls=%d cert=%q key=%q, want 0/''/''", tcpTLS, tcpCert, tcpKey)
	}
	if err := database.QueryRow(`SELECT COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id='lb_cl2http'`).Scan(&httpTLS); err != nil {
		t.Fatalf("read http rule: %v", err)
	}
	if httpTLS != 1 {
		t.Fatalf("http rule enable_tls=%d, want untouched 1", httpTLS)
	}
}

// TCP 自愈族：TCP 自愈清单扩面——代理超时族/自定义路由/
// dynamic_dns/strategy(cookie) 同迁移清零，残留 path_rules 同事务删除；
// 非 TCP 行（含 HTTP+proxy 超时/cookie 策略）不得被触碰。
func TestMigrateTCPRuleDeadFields_clearsRemainingHTTPOnlyFields(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,tls_source,tls_http_redirect,health_check_host,
		 block_page_stage1_id,block_page_stage1_status,block_page_stage3_id,block_page_stage3_status,log_enabled)
		VALUES ('lb_migration_dead','migration-dead','tcp','dead.example.test',19444,'acme_dns',1,'probe.example.test',7,451,8,503,1)`); err != nil {
		t.Fatalf("seed TCP dead fields: %v", err)
	}

	var staleBefore int
	if err := database.QueryRow(tcpDeadFieldsProbeSQL).Scan(&staleBefore); err != nil {
		t.Fatalf("probe before migration: %v", err)
	}
	if staleBefore != 1 {
		t.Fatalf("probe before migration=%d, want 1", staleBefore)
	}
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate TCP dead fields: %v", err)
	}

	var domain, tlsSource, healthHost string
	var redirect, stage1ID, stage1Status, stage3ID, stage3Status, logEnabled int
	if err := database.QueryRow(`SELECT COALESCE(domain,''),COALESCE(tls_source,''),COALESCE(health_check_host,''),
		COALESCE(tls_http_redirect,0),COALESCE(block_page_stage1_id,0),COALESCE(block_page_stage1_status,0),
		COALESCE(block_page_stage3_id,0),COALESCE(block_page_stage3_status,0),COALESCE(log_enabled,0)
		FROM lb_rules WHERE caddy_id='lb_migration_dead'`).Scan(
		&domain, &tlsSource, &healthHost, &redirect, &stage1ID, &stage1Status, &stage3ID, &stage3Status, &logEnabled); err != nil {
		t.Fatalf("read migrated TCP rule: %v", err)
	}
	if domain != "" || tlsSource != "manual" || healthHost != "" || redirect != 0 ||
		stage1ID != 0 || stage1Status != 0 || stage3ID != 0 || stage3Status != 0 || logEnabled != 0 {
		t.Fatalf("TCP dead fields remain: domain=%q tls_source=%q health_host=%q redirect=%d stages=%d/%d/%d/%d log=%d",
			domain, tlsSource, healthHost, redirect, stage1ID, stage1Status, stage3ID, stage3Status, logEnabled)
	}
	var staleAfter int
	if err := database.QueryRow(tcpDeadFieldsProbeSQL).Scan(&staleAfter); err != nil {
		t.Fatalf("probe after migration: %v", err)
	}
	if staleAfter != 0 {
		t.Fatalf("probe after migration=%d, want 0", staleAfter)
	}
}

func TestMigrateTCPRuleDeadFields_clearsHTTPOnlyProxyRoutesAndStrategy(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port, strategy,
		custom_routes_enabled, dynamic_dns, proxy_dial_timeout, proxy_response_header_timeout, proxy_read_timeout,
		proxy_write_timeout, proxy_stream_timeout, proxy_flush_interval, proxy_stream_close_delay)
		VALUES (1, 'lb_tcp_dead88', 'tcp-dead88', 'tcp', '', 19701, 'cookie', 1, 1, 30, 60, 120, 120, 300, -1, 15)`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port, strategy,
		custom_routes_enabled, proxy_dial_timeout)
		VALUES (2, 'lb_http_ctrl88', 'http-ctrl88', 'http', 'ctrl88.example.test', 19702, 'cookie', 1, 30)`); err != nil {
		t.Fatalf("seed http control rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id, sort_order, match_type, path) VALUES ('lb_tcp_dead88', 0, 'prefix', '/legacy/')`); err != nil {
		t.Fatalf("seed tcp path rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id, sort_order, match_type, path) VALUES ('lb_http_ctrl88', 0, 'prefix', '/keep/')`); err != nil {
		t.Fatalf("seed http path rule: %v", err)
	}

	// When
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Then：TCP 行全部归零/默认策略，路径规则删除
	var strategy string
	var customRoutes, dynamicDNS, pathRules int
	var proxyDial, proxyFlush int
	if err := database.QueryRow(`SELECT strategy, COALESCE(custom_routes_enabled,0), COALESCE(dynamic_dns,0),
		COALESCE(proxy_dial_timeout,0), COALESCE(proxy_flush_interval,0)
		FROM lb_rules WHERE caddy_id='lb_tcp_dead88'`).Scan(&strategy, &customRoutes, &dynamicDNS, &proxyDial, &proxyFlush); err != nil {
		t.Fatalf("read tcp rule: %v", err)
	}
	if strategy != "weighted_round_robin" || customRoutes != 0 || dynamicDNS != 0 || proxyDial != 0 || proxyFlush != 0 {
		t.Fatalf("tcp rule after migration: strategy=%q custom_routes=%d dynamic_dns=%d proxy_dial=%d proxy_flush=%d, want 默认/0",
			strategy, customRoutes, dynamicDNS, proxyDial, proxyFlush)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_tcp_dead88'`).Scan(&pathRules); err != nil {
		t.Fatalf("count tcp path rules: %v", err)
	}
	if pathRules != 0 {
		t.Fatalf("tcp path_rules=%d, want 0", pathRules)
	}

	// 非 TCP 控制行原样保留（策略/代理超时/路径规则）
	var httpStrategy string
	var httpRoutes, httpProxyDial, httpPathRules int
	if err := database.QueryRow(`SELECT strategy, COALESCE(custom_routes_enabled,0), COALESCE(proxy_dial_timeout,0)
		FROM lb_rules WHERE caddy_id='lb_http_ctrl88'`).Scan(&httpStrategy, &httpRoutes, &httpProxyDial); err != nil {
		t.Fatalf("read http control rule: %v", err)
	}
	if httpStrategy != "cookie" || httpRoutes != 1 || httpProxyDial != 30 {
		t.Fatalf("http control rule touched: strategy=%q custom_routes=%d proxy_dial=%d", httpStrategy, httpRoutes, httpProxyDial)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_http_ctrl88'`).Scan(&httpPathRules); err != nil {
		t.Fatalf("count http path rules: %v", err)
	}
	if httpPathRules != 1 {
		t.Fatalf("http control path_rules=%d, want 1 (must be untouched)", httpPathRules)
	}
}

// TCP 行的证书材料本身是死值触发列：enable_tls=0 AND tls_source='manual'
// AND tls_cert<>” 既不满足其余谓词、也让传输归一（以 EnableTLS 为门）跳过，
// 私钥正文因此可长期随备份/快照放大。迁移必须选中并清零该形态。
func TestMigrateTCPRuleDeadFields_clearsCertMaterialWhenTLSDisabled(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_tls, tls_source, tls_cert, tls_key, compress_types, strategy)
		VALUES ('lb_tcp_cert_only', 'tcp-cert-only', 'tcp', '', 9444, 0, 'manual', 'CERT-PEM', 'KEY-PEM', '', 'weighted_round_robin')`); err != nil {
		t.Fatalf("seed tcp rule with cert material: %v", err)
	}

	var staleBefore int
	if err := database.QueryRow(tcpDeadFieldsProbeSQL).Scan(&staleBefore); err != nil {
		t.Fatalf("probe before migration: %v", err)
	}
	if staleBefore != 1 {
		t.Fatalf("probe before migration=%d, want 1（证书材料列必须是触发列）", staleBefore)
	}

	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var cert, key string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id='lb_tcp_cert_only'`).Scan(&cert, &key); err != nil {
		t.Fatalf("read migrated rule: %v", err)
	}
	if cert != "" || key != "" {
		t.Fatalf("TCP 证书材料未清零: cert=%q key=%q", cert, key)
	}
	var staleAfter int
	if err := database.QueryRow(tcpDeadFieldsProbeSQL).Scan(&staleAfter); err != nil {
		t.Fatalf("probe after migration: %v", err)
	}
	if staleAfter != 0 {
		t.Fatalf("probe after migration=%d, want 0", staleAfter)
	}
}

// 五列可空 HTTP 专属字段被带外写成 NULL 时，SQLite 裸 =1 / <>0 比较不成立。
// 迁移必须把 NULL 同其它死值一样收敛为 0，同时不得触碰 HTTP 控制行。
func TestMigrateTCPRuleDeadFields_clearsNullableHTTPOnlyFields(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls) VALUES
		('lb_tcp_null_dead','tcp-null-dead','tcp','',9445,1),
		('lb_http_null_control','http-null-control','http','null-control.example.test',8445,0)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	// 先借 enable_tls=1 让既有迁移把其余触发列收敛到规范值，再单独制造
	// 本用例的 NULL 形状，避免 fresh DDL 的其它默认值成为意外触发因。
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("canonicalize fixture: %v", err)
	}
	if _, err := database.Exec(`UPDATE lb_rules SET
		enable_compress=NULL, request_body_max_size_mb=NULL, upstream_keepalive_timeout=NULL,
		server_tokens_hidden=NULL, dynamic_dns=NULL`); err != nil {
		t.Fatalf("set nullable dead fields: %v", err)
	}

	var staleBefore int
	if err := database.QueryRow(tcpDeadFieldsProbeSQL).Scan(&staleBefore); err != nil {
		t.Fatalf("probe before migration: %v", err)
	}
	if staleBefore != 1 {
		t.Fatalf("probe before migration=%d, want 1（五列 NULL 必须入选）", staleBefore)
	}
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var tcpNulls int
	if err := database.QueryRow(`SELECT (enable_compress IS NULL)+(request_body_max_size_mb IS NULL)+
		(upstream_keepalive_timeout IS NULL)+(server_tokens_hidden IS NULL)+(dynamic_dns IS NULL)
		FROM lb_rules WHERE caddy_id='lb_tcp_null_dead'`).Scan(&tcpNulls); err != nil {
		t.Fatalf("read migrated TCP rule: %v", err)
	}
	if tcpNulls != 0 {
		t.Fatalf("TCP nullable dead fields remaining NULL=%d, want 0", tcpNulls)
	}
	var httpNulls int
	if err := database.QueryRow(`SELECT (enable_compress IS NULL)+(request_body_max_size_mb IS NULL)+
		(upstream_keepalive_timeout IS NULL)+(server_tokens_hidden IS NULL)+(dynamic_dns IS NULL)
		FROM lb_rules WHERE caddy_id='lb_http_null_control'`).Scan(&httpNulls); err != nil {
		t.Fatalf("read HTTP control: %v", err)
	}
	if httpNulls != 5 {
		t.Fatalf("HTTP control NULL count=%d, want untouched 5", httpNulls)
	}
}

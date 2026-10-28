package db

import (
	"strings"
	"testing"
)

// TCP 规则的上游回源域名是死值（origin_domain 仅 HTTP 回源消费，保存族自
// 该字段引入起即拒绝 TCP 携带）：存量残留会随 rules 节同步到从端，并让系统
// 自身导出的备份在导入校验被整包 400 拒绝（备份自毒）。启动迁移必须清零，
// 且 HTTP 规则的 per-upstream 回源域名不得被误清。
func TestMigrateTCPRuleDeadFields_clearsUpstreamOrigin(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port)
		VALUES (1, 'lb_tcp_origin', 'tcp-origin', 'tcp', '', 19443)`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port)
		VALUES (2, 'lb_http_origin', 'http-origin', 'http', 'origin.example.test', 18443)`); err != nil {
		t.Fatalf("seed http rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, enabled, protocol, origin_domain)
		VALUES ('lb_tcp_origin', '10.0.0.1', 8080, 1, 1, 'http', 'stale.example.test'),
		       ('lb_http_origin', '10.0.0.2', 8080, 1, 1, 'https', 'keep.example.test')`); err != nil {
		t.Fatalf("seed upstreams: %v", err)
	}

	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var tcpOrigin, httpOrigin string
	if err := database.QueryRow(`SELECT COALESCE(origin_domain,'') FROM upstreams WHERE rule_id='lb_tcp_origin'`).Scan(&tcpOrigin); err != nil {
		t.Fatalf("read tcp upstream: %v", err)
	}
	if err := database.QueryRow(`SELECT COALESCE(origin_domain,'') FROM upstreams WHERE rule_id='lb_http_origin'`).Scan(&httpOrigin); err != nil {
		t.Fatalf("read http upstream: %v", err)
	}
	if tcpOrigin != "" {
		t.Fatalf("tcp upstream origin=%q, want 清零", tcpOrigin)
	}
	if httpOrigin != "keep.example.test" {
		t.Fatalf("http upstream origin=%q, want 保留（per-upstream 回源仅 HTTP 消费）", httpOrigin)
	}
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d, want 1（残留清零须 bump 触发从端收敛）", version)
	}
	// 幂等：重跑无命中，不再 bump。
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate again: %v", err)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version again: %v", err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d after rerun, want 1（无命中零写）", version)
	}
}

// TCP 行的三个可空布尔列（enable_tls / tls_http_redirect / enable_dns_server）
// 在三值逻辑下用裸 =1 比较时对带外 NULL 行恒为 NULL：既逃过探测也不被复位，
// NULL 形态与其零值孪生行收敛终态不一致（主端库/导出 canonical/从端落库三面
// 同值不变量只在零值形态成立）。本测构造「其余死值全净、仅这三列 NULL」的行。
func TestMigrateTCPRuleDeadFields_normalizesNullTLSColumns(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	// 除 TLS 三列外每一列都显式取「非死值」形态，选中与否只由 TLS 列决定。
	const cleanDeadCols = `host_header, health_check_path, health_check_host, domain, enable_compress, compress_types,
		request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden, ntlm_compatible, upstream_force_http1,
		proxy_dial_timeout, proxy_response_header_timeout, proxy_read_timeout, proxy_write_timeout,
		proxy_stream_timeout, proxy_flush_interval, proxy_stream_close_delay,
		custom_routes_enabled, dynamic_dns, strategy, dns_family, tls_cert, tls_key,
		block_page_stage1_id, block_page_stage1_status, block_page_stage3_id, block_page_stage3_status, log_enabled`
	const cleanDeadVals = `'','','','',0,'',0,0,0,0,0,0,0,0,0,0,0,0,0,0,'weighted_round_robin','ipv4','','',0,0,0,0,0`
	// enable_tls / tls_http_redirect 刻意显式写 NULL（带外改库/旧备份可达）：
	// 省略列会落到 DDL DEFAULT 0，构造不出 NULL 形态。
	if _, err := database.Exec(`INSERT INTO lb_rules (id,caddy_id,name,protocol,listen_port,tls_source,enable_tls,tls_http_redirect,` + cleanDeadCols + `)
		VALUES (1,'lb_tcp_null_tls','tcp-null-tls','tcp',9443,'manual',NULL,NULL,` + cleanDeadVals + `)`); err != nil {
		t.Fatalf("seed tcp rule with NULL tls columns: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id,caddy_id,name,protocol,listen_port,tls_source,enable_tls,tls_http_redirect,` + cleanDeadCols + `)
		VALUES (2,'lb_tcp_zero_tls','tcp-zero-tls','tcp',9444,'manual',0,0,` + cleanDeadVals + `)`); err != nil {
		t.Fatalf("seed tcp rule with zero tls columns: %v", err)
	}
	// HTTP 对照行：同形 NULL 但 protocol<>'tcp'，迁移不得触碰。
	if _, err := database.Exec(`INSERT INTO lb_rules (id,caddy_id,name,protocol,domain,listen_port,enable_tls,tls_http_redirect,tls_source)
		VALUES (3,'lb_http_null_tls','http-null-tls','http','tls.example.test',443,NULL,NULL,NULL)`); err != nil {
		t.Fatalf("seed http control rule: %v", err)
	}
	var probeBefore int
	if err := database.QueryRow(tcpDeadFieldsProbeSQL).Scan(&probeBefore); err != nil {
		t.Fatalf("probe before migration: %v", err)
	}
	if probeBefore != 1 {
		t.Fatalf("probe before migration=%d, want 1（仅 NULL TLS 形态行入选）", probeBefore)
	}

	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for _, caddyID := range []string{"lb_tcp_null_tls", "lb_tcp_zero_tls"} {
		var nulls int
		var tlsSource string
		if err := database.QueryRow(`SELECT (enable_tls IS NULL)+(tls_http_redirect IS NULL), COALESCE(tls_source,'')
			FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&nulls, &tlsSource); err != nil {
			t.Fatalf("read %s: %v", caddyID, err)
		}
		if nulls != 0 {
			t.Fatalf("%s 仍留 %d 个 NULL TLS 列, want 0（NULL 与零值同形归一）", caddyID, nulls)
		}
		if tlsSource != "manual" {
			t.Fatalf("%s tls_source=%q, want manual", caddyID, tlsSource)
		}
	}
	var httpNulls int
	if err := database.QueryRow(`SELECT (enable_tls IS NULL)+(tls_http_redirect IS NULL)
		FROM lb_rules WHERE caddy_id='lb_http_null_tls'`).Scan(&httpNulls); err != nil {
		t.Fatalf("read http control: %v", err)
	}
	if httpNulls != 2 {
		t.Fatalf("HTTP 对照行 NULL 列=%d, want 2（非 TCP 行不得被触碰）", httpNulls)
	}
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d, want 1（NULL 形态归一须 bump 触发从端收敛）", version)
	}
	// 幂等：归一后零命中，不再 bump。
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate again: %v", err)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version again: %v", err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d after rerun, want 1（归一后零写）", version)
	}
}

// TCP 的 DNS 服务发现两列：enable_dns_server=NULL + dns_server=” 在
// IIF(enable_dns_server IN ('1',1),1,0)=1 谓词下不被选中，NULL 永久留在库里
// （零值孪生行则已归零），与「TCP 不保留 HTTP 专属死值」的净态不一致。
func TestMigrateTCPRuleStaleDNSServer_normalizesNullEnableFlag(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id,caddy_id,name,protocol,listen_port,enable_dns_server,dns_server) VALUES
		(1,'lb_tcp_dns_null','tcp-dns-null','tcp',19443,NULL,''),
		(2,'lb_tcp_dns_zero','tcp-dns-zero','tcp',19444,0,''),
		(3,'lb_http_dns_null','http-dns-null','http',18443,NULL,'')`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	drainSystemAuditBuffer()
	t.Cleanup(func() { drainSystemAuditBuffer() })

	if err := migrateTCPRuleStaleDNSServer(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var tcpNulls, httpNulls int
	if err := database.QueryRow(`SELECT (enable_dns_server IS NULL) FROM lb_rules WHERE caddy_id='lb_tcp_dns_null'`).Scan(&tcpNulls); err != nil {
		t.Fatalf("read tcp rule: %v", err)
	}
	if err := database.QueryRow(`SELECT (enable_dns_server IS NULL) FROM lb_rules WHERE caddy_id='lb_http_dns_null'`).Scan(&httpNulls); err != nil {
		t.Fatalf("read http control: %v", err)
	}
	if tcpNulls != 0 {
		t.Fatalf("TCP 行 enable_dns_server 仍为 NULL, want 归零（与零值孪生行同形）")
	}
	if httpNulls != 1 {
		t.Fatalf("HTTP 对照行 enable_dns_server 被改写, want 保持 NULL（HTTP 行该字段合法）")
	}
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 || !strings.Contains(entries[0].detail, "1 条") {
		t.Fatalf("清理审计=%+v, want 一条聚合留痕（命中 1 条）", entries)
	}
}

// HTTP 规则的跨模式 TLS 残留（非 manual 带证书材料、非 acme_dns 带 CA 引用、
// manual 带 ACME 配置引用）只在保存/导入写侧清零——升级前遗留行此前只有再
// 编辑才自愈。启动迁移按同一不变量归零，bump 一次触发从端收敛。
func TestMigrateRuleTLSModeResidue(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port, tls_source, tls_cert, tls_key, acme_config_id, ca_provider_id)
		VALUES (1, 'lb_acme_residue', 'acme-residue', 'http', 'acme.example.test', 443, 'acme_dns', 'CERT', 'KEY', 2, 3),
		       (2, 'lb_manual_residue', 'manual-residue', 'http', 'manual.example.test', 443, 'manual', 'KEEP_CERT', 'KEEP_KEY', 7, 9),
		       (3, 'lb_manual_clean', 'manual-clean', 'http', 'clean.example.test', 443, 'manual', 'CERT2', 'KEY2', 0, 0),
		       (4, 'lb_empty_source', 'empty-source', 'http', 'empty.example.test', 443, '', 'CERT3', 'KEY3', 5, 6)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	if err := migrateRuleTLSModeResidue(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var cert, key string
	var acmeID, caID int
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0) FROM lb_rules WHERE caddy_id='lb_acme_residue'`).
		Scan(&cert, &key, &acmeID, &caID); err != nil {
		t.Fatalf("read acme rule: %v", err)
	}
	if cert != "" || key != "" {
		t.Fatalf("acme rule cert=%q key=%q, want 清零（非 manual 不保留材料）", cert, key)
	}
	if caID != 3 {
		t.Fatalf("acme rule ca_provider_id=%d, want 3（acme 源保留 CA 引用）", caID)
	}
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0) FROM lb_rules WHERE caddy_id='lb_manual_residue'`).
		Scan(&cert, &key, &acmeID, &caID); err != nil {
		t.Fatalf("read manual rule: %v", err)
	}
	if cert != "KEEP_CERT" || key != "KEEP_KEY" {
		t.Fatalf("manual rule cert=%q key=%q, want 保留材料", cert, key)
	}
	if acmeID != 0 {
		t.Fatalf("manual rule acme_config_id=%d, want 0（manual 源不保留 ACME 引用）", acmeID)
	}
	if caID != 0 {
		t.Fatalf("manual rule ca_provider_id=%d, want 0（非 acme_dns 不保留 CA 引用）", caID)
	}
	var cleanCert string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,'') FROM lb_rules WHERE caddy_id='lb_manual_clean'`).Scan(&cleanCert); err != nil {
		t.Fatalf("read clean rule: %v", err)
	}
	if cleanCert != "CERT2" {
		t.Fatalf("clean manual rule cert=%q, want 保留", cleanCert)
	}
	// 空来源（NULL 之外的第二形态）：COALESCE 视作 manual，非 acme_dns 一律
	// 清零 ACME/CA 引用与证书材料——与保存族/导入/传输归一同一不变量。
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0) FROM lb_rules WHERE caddy_id='lb_empty_source'`).
		Scan(&cert, &key, &acmeID, &caID); err != nil {
		t.Fatalf("read empty source rule: %v", err)
	}
	if cert != "" || key != "" || acmeID != 0 || caID != 0 {
		t.Fatalf("empty source rule cert=%q key=%q acme=%d ca=%d, want 全清零", cert, key, acmeID, caID)
	}
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d, want 1", version)
	}
	if err := migrateRuleTLSModeResidue(); err != nil {
		t.Fatalf("migrate again: %v", err)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version again: %v", err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d after rerun, want 1（二次启动零写）", version)
	}
}

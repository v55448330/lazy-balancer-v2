package services

// LBH-A-U1 同族（第 69 轮，主审裁定并入）：从端应用快照时 TCP 规则的 HTTP
// 专属死配置字段族（host_header/health_check_path/enable_compress/compress_types/
// request_body_max_size_mb/upstream_keepalive_timeout/server_tokens_hidden）须
// 随 TLS 归一一并归零——否则死值在从端持久化，「提升为主」（DB 事务不重跑
// 启动迁移）后继承死配置。与 handlers/rules.go TCP 归一块同格。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestInsertSnapshotRules_tcpZeroesHTTPOnlyFieldFamily(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	// Given：快照携带 TCP 规则 + 全族死配置字段（跨版本/导入残留形态）
	rule := models.LbRule{
		CaddyID: "lb_tcpnorm1", Name: "tcpnorm", Protocol: "tcp", ListenPort: 9000,
		Strategy: "weighted_round_robin", Enabled: true,
		EnableTLS: true, TLSCert: "x", TLSKey: "y",
		HostHeader: "dead.example.com", HealthCheckPath: "/hc",
		EnableCompress: true, CompressTypes: "gzip",
		RequestBodyMaxSizeMB: 128, UpstreamKeepaliveTimeout: 30, ServerTokensHidden: 1,
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertSnapshotRules(ctx, tx, []models.LbRule{rule}); err != nil {
		t.Fatalf("insertSnapshotRules: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Then：全族字段落库前归零（R63 A-N1 TLS 归一的同族扩展）
	var (
		enableTLS                     bool
		tlsCert, tlsKey               string
		hostHeader, healthCheckPath   string
		enableCompress                bool
		compressTypes                 string
		bodyMax, keepalive, tokensHid int
	)
	err = database.QueryRow(`SELECT enable_tls, COALESCE(tls_cert,''), COALESCE(tls_key,''),
		COALESCE(host_header,''), COALESCE(health_check_path,''), enable_compress,
		COALESCE(compress_types,''), request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden
		FROM lb_rules WHERE caddy_id='lb_tcpnorm1'`).Scan(
		&enableTLS, &tlsCert, &tlsKey, &hostHeader, &healthCheckPath,
		&enableCompress, &compressTypes, &bodyMax, &keepalive, &tokensHid)
	if err != nil {
		t.Fatal(err)
	}
	if enableTLS || tlsCert != "" || tlsKey != "" {
		t.Fatalf("TLS 族未归零: enable_tls=%v cert=%q key=%q", enableTLS, tlsCert, tlsKey)
	}
	if hostHeader != "" || healthCheckPath != "" || enableCompress || compressTypes != "" ||
		bodyMax != 0 || keepalive != 0 || tokensHid != 0 {
		t.Fatalf("HTTP 专属字段族未归零: host_header=%q health_check_path=%q enable_compress=%v compress_types=%q body_max=%d keepalive=%d tokens_hidden=%d",
			hostHeader, healthCheckPath, enableCompress, compressTypes, bodyMax, keepalive, tokensHid)
	}
}

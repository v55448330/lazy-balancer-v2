package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// v2 备份导入/v1 导入）中唯一事务内零归一的写路径——转换器对 BackendDomain/
// Gzip 无协议门，TCP 行可携带 host_header/enable_compress/compress_types
// 修复=导入 INSERT 后统一调 normalizeRuleRowsForTransport（与 v2 导入共享）。
func TestImportV1Config_zeros_tcp_dead_fields(t *testing.T) {
	// Given：v1 备份——TCP 规则开启 Gzip 与回源域名开关（HTTP 专属特性），
	// 另一条 HTTP 规则同配置作对照（HTTP 行必须原样保留）。
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := `{
		"proxy_config":{"config":[
			{"pk":1,"fields":{"proxy_name":"cl3-tcp","protocol":false,"listen":9443,"server_name":"","status":true,
				"gzip":true,"backend_domain_toggle":true,"backend_domain":"origin.example.test","upstream_list":[1]}},
			{"pk":2,"fields":{"proxy_name":"cl3-http","protocol":true,"listen":8080,"server_name":"cl3.example.test","status":true,
				"gzip":true,"backend_domain_toggle":true,"backend_domain":"origin.example.test","upstream_list":[2]}}
		]},
		"upstream_config":{"config":[
			{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9001,"weight":100}},
			{"pk":2,"fields":{"status":true,"address":"127.0.0.1","port":9002,"weight":100}}
		]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功；TCP 行 HTTP 专属七字段+TLS 三字段全零，
	// HTTP 行 host_header/compress 不受影响。
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var hostHeader, healthPath, compressTypes, tlsCert, tlsKey string
	var enableCompress, bodyMax, keepalive, tokensHidden, enableTLS int
	if err := db.DB.QueryRow(`SELECT COALESCE(host_header,''), COALESCE(health_check_path,''), COALESCE(enable_compress,0), COALESCE(compress_types,''),
		COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
		COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,'')
		FROM lb_rules WHERE name='cl3-tcp'`).Scan(
		&hostHeader, &healthPath, &enableCompress, &compressTypes,
		&bodyMax, &keepalive, &tokensHidden, &enableTLS, &tlsCert, &tlsKey); err != nil {
		t.Fatalf("read tcp rule: %v", err)
	}
	if hostHeader != "" || healthPath != "" || enableCompress != 0 || compressTypes != "" ||
		bodyMax != 0 || keepalive != 0 || tokensHidden != 0 || enableTLS != 0 || tlsCert != "" || tlsKey != "" {
		t.Fatalf("tcp rule dead fields after import: host_header=%q health_check_path=%q enable_compress=%d compress_types=%q "+
			"body_max=%d keepalive=%d tokens_hidden=%d enable_tls=%d cert=%q key=%q, want all zero/empty",
			hostHeader, healthPath, enableCompress, compressTypes, bodyMax, keepalive, tokensHidden, enableTLS, tlsCert, tlsKey)
	}
	var httpHost string
	var httpCompress int
	if err := db.DB.QueryRow(`SELECT COALESCE(host_header,''), COALESCE(enable_compress,0) FROM lb_rules WHERE name='cl3-http'`).
		Scan(&httpHost, &httpCompress); err != nil {
		t.Fatalf("read http rule: %v", err)
	}
	if httpHost != "origin.example.test" || httpCompress != 1 {
		t.Fatalf("http rule host_header=%q enable_compress=%d, want preserved 'origin.example.test'/1", httpHost, httpCompress)
	}
}

// 缺 TLS 三字段（enable_tls/tls_cert/tls_key）与 path_rules 时间戳归一
// （时间戳循环只覆盖 lb_rules）。修复=改调与 v1 导入共享的
// normalizeRuleRowsForTransport（单一事实源）。
func TestImportConfigBackup_normalizes_tcp_tls_and_path_rule_timestamps(t *testing.T) {
	// Given：备份携带 TCP+enable_tls=1 行（校验链会先行钳制，但事务内归一
	// 必须同口径兜底）与 path_rules RFC3339 时间戳行（校验不触碰时间格式，
	// 事务内归一是唯一收口点——现状缺口）。
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_cl4tcp", "name": "cl4-tcp", "protocol": "tcp", "listen_port": 9443, "enabled": 1,
				"enable_tls": 1, "tls_cert": "PEMCERT", "tls_key": "PEMKEY",
				"host_header": "origin.example.test", "enable_compress": 1, "compress_types": "gzip"},
			{"caddy_id": "lb_cl4http", "name": "cl4-http", "protocol": "http", "domain": "cl4.example.test",
				"listen_port": 8080, "enabled": 1, "custom_routes_enabled": 1},
		},
		"upstreams": {
			{"rule_id": "lb_cl4tcp", "host": "127.0.0.1", "port": 9001, "weight": 1, "enabled": 1, "protocol": "tcp"},
			{"rule_id": "lb_cl4http", "host": "127.0.0.1", "port": 9002, "weight": 1, "enabled": 1},
		},
		"path_rules": {
			{"rule_id": "lb_cl4http", "sort_order": 1, "match_type": "prefix", "path": "/a",
				"created_at": "2026-10-11T08:09:10Z", "updated_at": "2026-10-11T08:09:10Z"},
		},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功；TCP 行 TLS 三字段与七字段全零；path_rules 时间戳
	// RFC3339 → SQLite 平面格式。
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var hostHeader, compressTypes, tlsCert, tlsKey string
	var enableCompress, enableTLS int
	if err := db.DB.QueryRow(`SELECT COALESCE(host_header,''), COALESCE(enable_compress,0), COALESCE(compress_types,''),
		COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,'')
		FROM lb_rules WHERE caddy_id='lb_cl4tcp'`).Scan(
		&hostHeader, &enableCompress, &compressTypes, &enableTLS, &tlsCert, &tlsKey); err != nil {
		t.Fatalf("read tcp rule: %v", err)
	}
	if hostHeader != "" || enableCompress != 0 || compressTypes != "" || enableTLS != 0 || tlsCert != "" || tlsKey != "" {
		t.Fatalf("tcp rule after import: host_header=%q enable_compress=%d compress_types=%q enable_tls=%d cert=%q key=%q, want all zero/empty",
			hostHeader, enableCompress, compressTypes, enableTLS, tlsCert, tlsKey)
	}
	var pathCreatedFlat, pathUpdatedFlat sql.NullInt64
	// 时间戳断言用 SQL 谓词直判存储字节（驱动对 DATETIME 列解析回 time.Time，
	// Go 侧 Scan *string 再格式化为 RFC3339，无法反映真实落库形态）。
	if err := db.DB.QueryRow(`SELECT (created_at = strftime('%Y-%m-%d %H:%M:%S', created_at)),
		(updated_at = strftime('%Y-%m-%d %H:%M:%S', updated_at)) FROM path_rules WHERE rule_id='lb_cl4http'`).
		Scan(&pathCreatedFlat, &pathUpdatedFlat); err != nil {
		t.Fatalf("read path rule: %v", err)
	}
	if !pathCreatedFlat.Valid || pathCreatedFlat.Int64 != 1 || !pathUpdatedFlat.Valid || pathUpdatedFlat.Int64 != 1 {
		t.Fatalf("path rule timestamps not flat (created_ok=%+v updated_ok=%+v, want both 1)", pathCreatedFlat, pathUpdatedFlat)
	}
}

func TestNormalizeRuleRowsForTransport_clearsRemainingTCPDeadFields(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,tls_source,tls_http_redirect,health_check_host,
		 block_page_stage1_id,block_page_stage1_status,block_page_stage3_id,block_page_stage3_status,log_enabled)
		VALUES ('lb_transport_dead','transport-dead','tcp','dead.example.test',19443,'acme_dns',1,'probe.example.test',7,451,8,503,1)`); err != nil {
		t.Fatalf("seed TCP dead fields: %v", err)
	}
	tx, err := db.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin normalization transaction: %v", err)
	}
	if _, err := normalizeRuleRowsForTransport(t.Context(), tx); err != nil {
		_ = tx.Rollback()
		t.Fatalf("normalize rule rows: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit normalization: %v", err)
	}

	var domain, tlsSource, healthHost string
	var redirect, stage1ID, stage1Status, stage3ID, stage3Status, logEnabled int
	if err := db.DB.QueryRow(`SELECT COALESCE(domain,''),COALESCE(tls_source,''),COALESCE(health_check_host,''),
		COALESCE(tls_http_redirect,0),COALESCE(block_page_stage1_id,0),COALESCE(block_page_stage1_status,0),
		COALESCE(block_page_stage3_id,0),COALESCE(block_page_stage3_status,0),COALESCE(log_enabled,0)
		FROM lb_rules WHERE caddy_id='lb_transport_dead'`).Scan(
		&domain, &tlsSource, &healthHost, &redirect, &stage1ID, &stage1Status, &stage3ID, &stage3Status, &logEnabled); err != nil {
		t.Fatalf("read normalized TCP rule: %v", err)
	}
	if domain != "" || tlsSource != "manual" || healthHost != "" || redirect != 0 ||
		stage1ID != 7 || stage1Status != 451 || stage3ID != 8 || stage3Status != 503 || logEnabled != 0 {
		t.Fatalf("TCP dead fields remain: domain=%q tls_source=%q health_host=%q redirect=%d stages=%d/%d/%d/%d log=%d",
			domain, tlsSource, healthHost, redirect, stage1ID, stage1Status, stage3ID, stage3Status, logEnabled)
	}
}

// 新增的 9 个 NOT NULL DEFAULT 列（upstream_path 先例确立的登记惯例未跟进）——
// 手造/损坏备份这些列为 NULL 时 restoreTable 原样落 NULL 撞列约束，整包 500
// 回滚。修复=按 schema DEFAULT 逐字补登记（response_status 归一 200）。
func TestImportConfigBackup_normalizes_new_notnull_column_nulls(t *testing.T) {
	// Given：备份四表行分别携带 9 列 NULL（lb_rules.health_check_host、
	// upstreams.origin_domain、path_rules 静态响应五列、users.login_failed_attempts/
	// auth_provider）。
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 2, "username": "core1-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1,
			"login_failed_attempts": nil, "auth_provider": nil}},
		"lb_rules": {{"caddy_id": "lb_core1", "name": "core1-rule", "protocol": "http", "domain": "core1.example.test",
			"listen_port": 8080, "enabled": 1, "custom_routes_enabled": 1, "health_check_host": nil}},
		"upstreams": {{"rule_id": "lb_core1", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": 1, "origin_domain": nil}},
		"path_rules": {{"rule_id": "lb_core1", "sort_order": 1, "match_type": "prefix", "path": "/a",
			"response_mode": nil, "response_status": nil, "response_body": nil,
			"response_content_type": nil, "redirect_to": nil}},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：导入成功（现状 NULL 撞 NOT NULL 约束整包 500），落库值与
	// schema DEFAULT 逐字一致。
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var healthCheckHost, originDomain string
	if err := db.DB.QueryRow(`SELECT COALESCE(health_check_host,'') FROM lb_rules WHERE caddy_id='lb_core1'`).Scan(&healthCheckHost); err != nil {
		t.Fatalf("read lb_rules.health_check_host: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(origin_domain,'') FROM upstreams WHERE rule_id='lb_core1'`).Scan(&originDomain); err != nil {
		t.Fatalf("read upstreams.origin_domain: %v", err)
	}
	var responseMode, responseBody, responseContentType, redirectTo string
	var responseStatus int
	if err := db.DB.QueryRow(`SELECT COALESCE(response_mode,''), COALESCE(response_status,-1), COALESCE(response_body,''),
		COALESCE(response_content_type,''), COALESCE(redirect_to,'') FROM path_rules WHERE rule_id='lb_core1'`).
		Scan(&responseMode, &responseStatus, &responseBody, &responseContentType, &redirectTo); err != nil {
		t.Fatalf("read path_rules static columns: %v", err)
	}
	var loginFailedAttempts int
	var authProvider string
	if err := db.DB.QueryRow(`SELECT COALESCE(login_failed_attempts,-1), COALESCE(auth_provider,'') FROM users WHERE username='core1-admin'`).
		Scan(&loginFailedAttempts, &authProvider); err != nil {
		t.Fatalf("read users columns: %v", err)
	}
	if healthCheckHost != "" || originDomain != "" ||
		responseMode != "" || responseStatus != 200 || responseBody != "" || responseContentType != "" || redirectTo != "" ||
		loginFailedAttempts != 0 || authProvider != "local" {
		t.Fatalf("normalized nulls: health_check_host=%q origin_domain=%q response=(%q %d %q %q %q) users=(%d %q), want ''/''/('' 200 '' '' '')/(0 'local')",
			healthCheckHost, originDomain, responseMode, responseStatus, responseBody, responseContentType, redirectTo, loginFailedAttempts, authProvider)
	}
}

// TCP 上游的 origin_domain 是死值（保存族自该字段引入起即拒绝、TCP 渲染零
// 消费）：带外残留一旦进库，实例自己导出的备份会在导入校验阶段被
// 「回源域名仅 HTTP 规则支持」整包 400——备份自毒。导入面必须按与启动迁移/
// 快照导出同一口径归一（而非拒收），HTTP 规则的上游回源域名原样保留。
func TestImportConfigBackup_normalizesTCPUpstreamOriginDomain(t *testing.T) {
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_org_tcp", "name": "org-tcp", "protocol": "tcp", "listen_port": 19443, "enabled": 1},
			{"caddy_id": "lb_org_http", "name": "org-http", "protocol": "http", "domain": "org.example.test",
				"listen_port": 18080, "enabled": 1},
		},
		"upstreams": {
			{"rule_id": "lb_org_tcp", "host": "127.0.0.1", "port": 9001, "weight": 1, "enabled": 1,
				"protocol": "tcp", "origin_domain": "stale.example.test"},
			{"rule_id": "lb_org_http", "host": "127.0.0.1", "port": 9002, "weight": 1, "enabled": 1,
				"protocol": "http", "origin_domain": "origin.example.test"},
		},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（TCP 上游回源域名残留应被归一而非整包拒收）", response.Code, response.Body.String())
	}
	var tcpOrigin, httpOrigin string
	if err := db.DB.QueryRow(`SELECT COALESCE(origin_domain,'') FROM upstreams WHERE rule_id='lb_org_tcp'`).Scan(&tcpOrigin); err != nil {
		t.Fatalf("read tcp upstream: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(origin_domain,'') FROM upstreams WHERE rule_id='lb_org_http'`).Scan(&httpOrigin); err != nil {
		t.Fatalf("read http upstream: %v", err)
	}
	if tcpOrigin != "" {
		t.Fatalf("TCP 上游 origin_domain=%q, want cleared（与启动迁移/快照导出口径一致）", tcpOrigin)
	}
	if httpOrigin != "origin.example.test" {
		t.Fatalf("HTTP 上游 origin_domain=%q, want preserved", httpOrigin)
	}
}

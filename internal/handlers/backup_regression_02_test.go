package handlers

// 覆盖：
//   节点拓扑：nodes 行级门（access_url / ip_address / port）、缺席保留本地
//   集群节点写端点在导入窗 409（门在 cluster_sync.go / cluster_status.go；
//     节点分区缓存清理直接调用 services.ClearNodeSectionReports）
//   无令牌哈希节点恢复成 pending（不保留 approved 死行）
//   导入侧 upstream weight<1 响亮拒绝（不静默归一）

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func a86ValidNodeRow() map[string]any {
	return map[string]any{
		"name": "edge-a", "ip_address": "10.0.0.2", "port": 8000,
		"protocol": "https", "is_approved": 1, "cluster_token_hash": "hash-a",
		"server_map_lat": 31.23, "server_map_lon": 121.47,
		"created_at": "2026-10-01 00:00:00",
	}
}

// a86SeedLiveAdmin 种入库存活管理员——导入事务尾部的「至少一个启用管理员」
// 守卫按导入后库实态判定，全新测试库零用户会在守卫处 400（与目标门无关的
// 假红形态），所有导入用例必须先种。
func a86SeedLiveAdmin(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed live admin: %v", err)
	}
}

func a86ImportClusterRows(t *testing.T, h *Handlers, rows []map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	a86SeedLiveAdmin(t)
	body := legacyBackupJSON(t, map[string][]map[string]any{"nodes": rows}, nil, []string{"cluster"})
	return importBackupShared(h, t, body)
}

func TestNodesImportRowGate_rejectsMalformed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(row map[string]any)
	}{
		{"port 非数值字符串", func(r map[string]any) { r["port"] = "8000x" }},
		{"port 超界", func(r map[string]any) { r["port"] = 70000 }},
		{"port 零", func(r map[string]any) { r["port"] = 0 }},
		{"纬度非数值", func(r map[string]any) { r["server_map_lat"] = "north" }},
		{"纬度越界", func(r map[string]any) { r["server_map_lat"] = 95 }},
		{"经度越界", func(r map[string]any) { r["server_map_lon"] = -181 }},
		{"缺 name", func(r map[string]any) { delete(r, "name") }},
		{"空 name", func(r map[string]any) { r["name"] = "  " }},
		{"缺 ip_address", func(r map[string]any) { delete(r, "ip_address") }},
		{"created_at 垃圾文本", func(r map[string]any) { r["created_at"] = "garbage" }},
		{"id 非整数", func(r map[string]any) { r["id"] = "node-1" }},
		{"sync_interval 非整数", func(r map[string]any) { r["sync_interval"] = "fast" }},
		{"sync_interval 越界", func(r map[string]any) { r["sync_interval"] = 100000 }},
		{"protocol 非法", func(r map[string]any) { r["protocol"] = "gopher" }},
		{"cluster_token_hash 非字符串", func(r map[string]any) { r["cluster_token_hash"] = 42 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			row := a86ValidNodeRow()
			tc.mutate(row)
			rec := a86ImportClusterRows(t, h, []map[string]any{row})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestNodesImportRowGate_nullAndBoundaryShapes(t *testing.T) {
	h := newBackupTestHandlers(t)
	// NULL 可空列由写入侧默认值归一（port 8000 / is_approved 0 / 坐标 0）；
	// 边界值 port 1/65535、坐标 ±90/±180 合法；数值字符串与既有整型门同族放行。
	rows := []map[string]any{
		{"name": "nulls", "ip_address": "10.0.0.10", "port": nil, "is_approved": nil, "server_map_lat": nil, "server_map_lon": nil, "sync_interval": nil},
		{"name": "edge-min", "ip_address": "10.0.0.11", "port": 1, "server_map_lat": -90, "server_map_lon": -180},
		{"name": "edge-max", "ip_address": "10.0.0.12", "port": 65535, "server_map_lat": 90, "server_map_lon": 180},
		{"name": "string-port", "ip_address": "10.0.0.13", "port": "8001"},
	}
	rec := a86ImportClusterRows(t, h, rows)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var port, approved, interval int
	var lat, lon float64
	if err := db.DB.QueryRow(`SELECT port,COALESCE(is_approved,9),COALESCE(sync_interval,9),server_map_lat,server_map_lon FROM nodes WHERE name='nulls'`).
		Scan(&port, &approved, &interval, &lat, &lon); err != nil {
		t.Fatalf("read null-defaulted node: %v", err)
	}
	if port != 8000 || approved != 0 || interval != 60 || lat != 0 || lon != 0 {
		t.Fatalf("null row defaults=(port %d, approved %d, interval %d, lat %v, lon %v), want (8000,0,60,0,0)", port, approved, interval, lat, lon)
	}
}

// 回归形状：无 nodes 表的旧备份不触碰本地拓扑（既有契约，防门误伤）。
func TestNodesImportRowGate_absentNodesKeepsLocal(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,is_approved,cluster_token_hash) VALUES (9,'keep','10.0.0.9',8000,1,'hash-keep')`); err != nil {
		t.Fatal(err)
	}
	body := legacyBackupJSON(t, nil, nil, []string{"users"})
	rec := importBackupShared(h, t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE id=9`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("local node lost: count=%d err=%v", count, err)
	}
}

// 无哈希节点恢复成 pending

func TestNodeWithoutTokenHashRestoredAsPending(t *testing.T) {
	h := newBackupTestHandlers(t)
	rows := []map[string]any{
		// 已批准且有哈希：保持批准 + delivered=1
		{"name": "approved", "ip_address": "10.0.1.1", "port": 8000, "is_approved": 1, "cluster_token_hash": "hash-ok"},
		// 手造/异常：approved 但无哈希 → 恢复为 pending（重新注册语义），delivered 显式清零
		{"name": "dead-approved", "ip_address": "10.0.1.2", "port": 8000, "is_approved": 1, "cluster_token_hash": "", "cluster_token_delivered": 1},
		// pending：保持 pending
		{"name": "pending", "ip_address": "10.0.1.3", "port": 8000, "is_approved": 0},
	}
	rec := a86ImportClusterRows(t, h, rows)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var approved, delivered int
	if err := db.DB.QueryRow(`SELECT COALESCE(is_approved,9),COALESCE(cluster_token_delivered,9) FROM nodes WHERE name='approved'`).Scan(&approved, &delivered); err != nil {
		t.Fatal(err)
	}
	if approved != 1 || delivered != 1 {
		t.Fatalf("approved node=(%d,%d), want (1,1)", approved, delivered)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(is_approved,9),COALESCE(cluster_token_delivered,9) FROM nodes WHERE name='dead-approved'`).Scan(&approved, &delivered); err != nil {
		t.Fatal(err)
	}
	if approved != 0 || delivered != 0 {
		t.Fatalf("hash-less approved node=(%d,%d), want pending (0,0)", approved, delivered)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(is_approved,9),COALESCE(cluster_token_delivered,9) FROM nodes WHERE name='pending'`).Scan(&approved, &delivered); err != nil {
		t.Fatal(err)
	}
	if approved != 0 || delivered != 0 {
		t.Fatalf("pending node=(%d,%d), want (0,0)", approved, delivered)
	}
}

func TestAutoBackupSectionsVersionProtected(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 三个节点本地迁移标记同族：备份携带非法形态导入跳过、
	// 本地标记不被覆盖、整型重扫不炸（启动迁移 Scan int 同形态）。
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_sections_version=1, threat_traffic_sample_unified_migrated=1, security_events_retention_migrated=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	body := legacyBackupJSON(t, nil, map[string]any{
		"auto_backup_sections_version":           "x",
		"threat_traffic_sample_unified_migrated": "y",
		"security_events_retention_migrated":     "z",
	}, nil)
	rec := importBackupShared(h, t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（保护键跳过非法值而非落库）", rec.Code, rec.Body.String())
	}
	for _, key := range []string{"auto_backup_sections_version", "threat_traffic_sample_unified_migrated", "security_events_retention_migrated"} {
		var version int
		if err := db.DB.QueryRow(`SELECT ` + key + ` FROM global_config WHERE id=1`).Scan(&version); err != nil {
			t.Fatalf("rescan %s as int: %v（导入落库的文本会破坏下次启动迁移扫描）", key, err)
		}
		if version != 1 {
			t.Fatalf("%s=%d, want 1（本地标记保持）", key, version)
		}
	}
	// 导出侧同口径剔除（保护键双消费点）。
	router := newBackupSectionRouter(h)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("export status=%d", rec2.Code)
	}
	var exported struct {
		Config map[string]any `json:"config"`
	}
	if err := json.Unmarshal(unpackExportBody(t, rec2.Body.Bytes()), &exported); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"auto_backup_sections_version", "threat_traffic_sample_unified_migrated", "security_events_retention_migrated"} {
		if _, carried := exported.Config[key]; carried {
			t.Fatalf("export leaked local migration marker %s", key)
		}
	}
}

func TestImportCountsIncludeNodes(t *testing.T) {
	h := newBackupTestHandlers(t)
	rec := a86ImportClusterRows(t, h, []map[string]any{a86ValidNodeRow()})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "节点 1 个") {
		t.Fatalf("import summary missing nodes count: %s", rec.Body.String())
	}
	var envelope struct {
		Data struct {
			Summary string `json:"summary"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(envelope.Data.Summary, "节点 1 个") {
		t.Fatalf("data.summary=%q, want 含「节点 1 个」", envelope.Data.Summary)
	}
}

// 结构性守卫：configBackupTables 每张表必须在汇总标签清单
// 或显式豁免清单中，防新增表再次漏计数。
func TestImportCountsDetailCoversAllBackupTables(t *testing.T) {
	exempt := map[string]bool{
		"path_rules":               true, // 规则子表，随 lb_rules 计数
		"security_policy_bindings": true, // 派生数据（由规则+策略重建）
	}
	labeled := make(map[string]bool, len(importCountsLabels))
	for _, item := range importCountsLabels {
		labeled[item.table] = true
	}
	for _, table := range configBackupTables {
		if !labeled[table] && !exempt[table] {
			t.Fatalf("configBackupTables 的表 %s 未在 importCountsLabels 计数，也未列入豁免", table)
		}
	}
}

func TestApiDocsBackupSectionsMatchSingleSource(t *testing.T) {
	var exportParam, autoBackupDesc string
	for _, route := range apiDocRoutes {
		if route.Method == "PUT" && route.Path == "/settings/auto-backup" {
			autoBackupDesc = route.Description
		}
	}
	if contract, ok := apiDocContracts["GET /config/export"]; ok {
		for _, param := range contract.queryParameters {
			if param.name == "sections" {
				exportParam = param.description
			}
		}
	}
	if exportParam == "" || autoBackupDesc == "" {
		t.Fatalf("apidocs entries not found: export param=%q autoBackup desc=%q", exportParam, autoBackupDesc)
	}
	for _, section := range configBackupSections {
		if !strings.Contains(exportParam, section.Key) {
			t.Fatalf("导出 query 文档缺分类 %s：%s", section.Key, exportParam)
		}
		if !strings.Contains(autoBackupDesc, section.Key) {
			t.Fatalf("自动备份设置文档缺分类 %s", section.Key)
		}
	}
	for _, stale := range []string{"三分类", "五分类"} {
		if strings.Contains(autoBackupDesc, stale) || strings.Contains(exportParam, stale) {
			t.Fatalf("文档残留「%s」陈旧口径", stale)
		}
	}
}

func TestImportAccessLogFormatGate(t *testing.T) {
	t.Run("删除受保护字段被拒绝", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		body := legacyBackupJSON(t, nil, map[string]any{"access_log_format": "request>remote_ip -> delete"}, nil)
		rec := importBackupShared(h, t, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
		}
	})
	t.Run("非字符串被拒绝", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		body := legacyBackupJSON(t, nil, map[string]any{"access_log_format": 42}, nil)
		rec := importBackupShared(h, t, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
		}
	})
	t.Run("合法格式导入并归一脱敏行", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		body := legacyBackupJSON(t, nil, map[string]any{"access_log_format": "request>remote_ip -> src"}, nil)
		rec := importBackupShared(h, t, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var stored string
		if err := db.DB.QueryRow(`SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stored, accessLogRedactionLine) {
			t.Fatalf("stored format=%q, want 归一携带 API Key 脱敏行（与保存侧同门）", stored)
		}
	})
	t.Run("预览同门", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		resp := validateResponseShared(t, h, legacyBackupJSON(t, nil, map[string]any{"access_log_format": "request>remote_ip -> delete"}, nil))
		if resp.Valid {
			t.Fatalf("preview valid=true, want false（删除受保护字段）")
		}
	})
	t.Run("超限规模被拒绝且零落库", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		if _, err := db.DB.Exec(`UPDATE global_config SET access_log_format='request>host -> h' WHERE id=1`); err != nil {
			t.Fatalf("seed access_log_format: %v", err)
		}
		readStored := func() string {
			var stored string
			if err := db.DB.QueryRow(`SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
				t.Fatalf("read access_log_format: %v", err)
			}
			return stored
		}
		importFormat := func(format string) *httptest.ResponseRecorder {
			return importBackupShared(h, t, legacyBackupJSON(t, nil, map[string]any{"access_log_format": format}, nil))
		}
		joinLines := func(n int) string {
			lines := make([]string, n)
			for i := range lines {
				lines[i] = "request>host -> h"
			}
			return strings.Join(lines, "\n")
		}
		// 201 行原始串在归一前即超限；200 行归一自动补脱敏行→201 行，按落库
		// 值口径同样拒绝（否则导入校验给绿、导入后保存反被写侧门 400）。
		if rec := importFormat(joinLines(201)); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "200 行") {
			t.Fatalf("201 行导入 status=%d body=%s, want 400 含「200 行」", rec.Code, rec.Body.String())
		}
		if rec := importFormat(joinLines(200)); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "200 行") {
			t.Fatalf("200 行（归一后 201 行）导入 status=%d body=%s, want 400 含「200 行」", rec.Code, rec.Body.String())
		}
		// 字节域：纯空白串同受规模门约束（空白语义不豁免上限）。
		overSpaces := strings.Repeat(" ", maxAccessLogFormatBytes+1)
		if rec := importFormat(overSpaces); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "字节") {
			t.Fatalf("16KiB+1 纯空格导入 status=%d body=%s, want 400 含「字节」", rec.Code, rec.Body.String())
		}
		// 预览与导入同门。
		if resp := validateResponseShared(t, h, legacyBackupJSON(t, nil, map[string]any{"access_log_format": joinLines(201)}, nil)); resp.Valid {
			t.Fatalf("preview valid=true, want false（201 行超限）")
		}
		if stored := readStored(); stored != "request>host -> h" {
			t.Fatalf("超限导入后落库=%q, want 原值（零部分写入）", stored)
		}
		// 上限内：199 行归一后 200 行、16KiB 纯空格均放行。
		if rec := importFormat(joinLines(199)); rec.Code != http.StatusOK {
			t.Fatalf("199 行（归一后 200 行）导入 status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}
		if rec := importFormat(strings.Repeat(" ", maxAccessLogFormatBytes)); rec.Code != http.StatusOK {
			t.Fatalf("16KiB 纯空格导入 status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}
		// 纯换行同样按真实数量计数，预览与导入都不能绕过上限。
		pureNewlines := func(n int) string { return strings.Repeat("\n", n) }
		if resp := validateResponseShared(t, h, legacyBackupJSON(t, nil, map[string]any{"access_log_format": pureNewlines(200)}, nil)); !resp.Valid {
			t.Fatal("200 个纯换行预览 valid=false, want true")
		}
		if resp := validateResponseShared(t, h, legacyBackupJSON(t, nil, map[string]any{"access_log_format": pureNewlines(201)}, nil)); resp.Valid {
			t.Fatal("201 个纯换行预览 valid=true, want false")
		}
		if rec := importFormat(pureNewlines(200)); rec.Code != http.StatusOK {
			t.Fatalf("200 个纯换行导入 status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}
		if _, err := db.DB.Exec(`UPDATE global_config SET access_log_format='request>host -> h' WHERE id=1`); err != nil {
			t.Fatalf("reset access_log_format: %v", err)
		}
		if rec := importFormat(pureNewlines(201)); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "200 行") {
			t.Fatalf("201 个纯换行导入 status=%d body=%s, want 400 含「200 行」", rec.Code, rec.Body.String())
		}
		if stored := readStored(); stored != "request>host -> h" {
			t.Fatalf("超限纯换行导入后落库=%q, want 原值（零部分写入）", stored)
		}
	})
}

// 导入侧 weight<1 拒绝

func TestImportRejectsUpstreamWeightBelowOne(t *testing.T) {
	rule := map[string]any{"caddy_id": "lb_w", "name": "w", "protocol": "http", "domain": "w.example.test", "listen_port": 18080, "enabled": 1}
	cases := []struct {
		name   string
		weight any
		want   int
	}{
		{"weight 0", 0, http.StatusBadRequest},
		{"weight 负数", -1, http.StatusBadRequest},
		{"weight 非数值字符串", "abc", http.StatusBadRequest},
		{"weight 合法", 2, http.StatusOK},
		{"weight 数值字符串（与既有整型门同族）", "2", http.StatusOK},
		{"weight 缺省（schema 默认 1）", nil, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			a86SeedLiveAdmin(t) // sections=rules 不导入 users，守卫按库实态判定
			upstream := map[string]any{"rule_id": "lb_w", "host": "127.0.0.1", "port": 9000, "enabled": 1}
			if tc.weight != nil {
				upstream["weight"] = tc.weight
			}
			body := legacyBackupJSON(t, map[string][]map[string]any{
				"lb_rules":  {rule},
				"upstreams": {upstream},
			}, nil, []string{"rules"})
			rec := importBackupShared(h, t, body)
			if rec.Code != tc.want {
				t.Fatalf("status=%d body=%s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}
}

func TestConflictDisabledRulePausesCertJobs(t *testing.T) {
	h := newBackupTestHandlers(t)
	dnsConfig := map[string]any{"id": 7, "name": "dns", "dns_provider": "dnspod", "dns_credentials": `{"token":"x"}`, "enabled": 1}
	// 两条同端口同域名启用规则 → 矩阵双侧置禁用；第三条独立规则不受影响。
	conflictA := map[string]any{"caddy_id": "lb_conflict_a", "name": "a", "protocol": "http", "domain": "dup.example.test", "listen_port": 18443, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 7}
	conflictB := map[string]any{"caddy_id": "lb_conflict_b", "name": "b", "protocol": "http", "domain": "dup.example.test", "listen_port": 18443, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 7}
	winner := map[string]any{"caddy_id": "lb_winner", "name": "winner", "protocol": "http", "domain": "winner.example.test", "listen_port": 18444, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 7}
	upstreamOf := func(ruleID string, port int) map[string]any {
		return map[string]any{"rule_id": ruleID, "host": "127.0.0.1", "port": port, "weight": 1, "enabled": 1}
	}
	jobOf := func(ruleID, domain, status string) map[string]any {
		return map[string]any{"rule_id": ruleID, "domain": domain, "status": status, "ca_provider_id": 0}
	}
	body := legacyBackupJSON(t, map[string][]map[string]any{
		"lb_rules":            {conflictA, conflictB, winner},
		"upstreams":           {upstreamOf("lb_conflict_a", 9001), upstreamOf("lb_conflict_b", 9002), upstreamOf("lb_winner", 9003)},
		"cert_jobs":           {jobOf("lb_conflict_a", "dup.example.test", "queued"), jobOf("lb_conflict_b", "dup.example.test", "queued"), jobOf("lb_winner", "winner.example.test", "queued")},
		"certificate_configs": {dnsConfig},
	}, map[string]any{"acme_email": "acme@example.test"}, nil)
	rec := importBackupShared(h, t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "disabled_conflicts") || !strings.Contains(rec.Body.String(), "lb_conflict_a") {
		t.Fatalf("expected conflict disable report, body=%s", rec.Body.String())
	}
	assert := func(ruleID, want string) {
		t.Helper()
		var status string
		if err := db.DB.QueryRow(`SELECT status FROM cert_jobs WHERE rule_id=?`, ruleID).Scan(&status); err != nil {
			t.Fatalf("read job %s: %v", ruleID, err)
		}
		if status != want {
			t.Fatalf("cert_jobs[%s].status=%q, want %q", ruleID, status, want)
		}
	}
	assert("lb_conflict_a", "disabled")
	assert("lb_conflict_b", "disabled")
	assert("lb_winner", "queued")
	var enabledA, enabledB int
	if err := db.DB.QueryRow(`SELECT COALESCE(enabled,9) FROM lb_rules WHERE caddy_id='lb_conflict_a'`).Scan(&enabledA); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(enabled,9) FROM lb_rules WHERE caddy_id='lb_conflict_b'`).Scan(&enabledB); err != nil {
		t.Fatal(err)
	}
	if enabledA != 0 || enabledB != 0 {
		t.Fatalf("conflict rules enabled=(%d,%d), want both disabled", enabledA, enabledB)
	}
}

func a86PinPath(dataDir, hostport string) string {
	hostHash := sha256.Sum256([]byte(hostport))
	return filepath.Join(dataDir, "cluster_ca_pins", hex.EncodeToString(hostHash[:]))
}

func TestTopologyRestoreClearsOnlyDeletedNodePins(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	// A 保留（备份携带同 ip:port）、B 删除（备份缺席）；备份行复用 B 的 id 以
	// 覆盖「id 复用携分区上报残留」形态。管理员由 a86ImportClusterRows 种入。
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,is_approved,cluster_token_hash) VALUES
		(21,'node-a','10.0.0.2',8000,'http',1,'hash-a'),
		(22,'node-b','10.0.0.3',8000,'http',1,'hash-b')`); err != nil {
		t.Fatal(err)
	}
	pinA := a86PinPath(dataDir, "10.0.0.2:8000")
	pinB := a86PinPath(dataDir, "10.0.0.3:8000")
	for _, pin := range []string{pinA, pinB} {
		if err := os.MkdirAll(filepath.Dir(pin), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pin, []byte("sha256-fingerprint\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{
		cfg:            &config.Config{CaddyAdminURL: fakeCaddy.URL, DataDir: dataDir},
		caddyService:   services.NewCaddyService(fakeCaddy.URL),
		clusterService: services.NewClusterService(db.DB, dataDir),
		syncService:    services.NewSyncService(db.DB, &config.Config{DataDir: dataDir}, nil),
	}
	now := time.Now()
	for _, id := range []int{21, 22} {
		if err := h.clusterService.ReportNode(context.Background(), id, models.ClusterReport{SectionHashes: map[string]string{"users": "u1", "rules": "r1", "security": "s1"}}, now); err != nil {
			t.Fatalf("seed section report %d: %v", id, err)
		}
	}
	// 控制组：导入前两节点分区上报均驱动出 SectionSync 视图（管道可用）。
	nodes, err := h.clusterService.Nodes(context.Background(), now)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, node := range nodes {
		if node.SectionSync == nil {
			t.Fatalf("control: node %d SectionSync=nil before import, want non-nil", node.ID)
		}
	}
	// 备份只携带 A 的身份（ip:port=10.0.0.2:8000），但复用 B 的 id=22。
	restoredA := map[string]any{"id": 22, "name": "node-a", "ip_address": "10.0.0.2", "port": 8000, "protocol": "http", "is_approved": 1, "cluster_token_hash": "hash-a"}
	rec := a86ImportClusterRows(t, h, []map[string]any{restoredA})
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}
	// B 已删除：pin 文件清除；A（同 ip:port 存活）pin 保留。
	if _, err := os.Stat(pinB); !os.IsNotExist(err) {
		t.Fatalf("deleted node pin still exists: %v", err)
	}
	if _, err := os.Stat(pinA); err != nil {
		t.Fatalf("surviving node pin wrongly removed: %v", err)
	}
	// id=22 复用节点不得携带旧分区上报（已删除节点的 SectionSync 残留）。
	nodes, err = h.clusterService.Nodes(context.Background(), now)
	if err != nil {
		t.Fatalf("list nodes after import: %v", err)
	}
	if len(nodes) != 1 || nodes[0].ID != 22 {
		t.Fatalf("nodes after import=%+v, want single restored node id=22", nodes)
	}
	if nodes[0].SectionSync != nil {
		t.Fatalf("restored node reusing deleted id carries stale SectionSync: %+v", nodes[0].SectionSync)
	}
}

func TestClusterWriteEndpoints409DuringImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.clusterService = services.NewClusterService(db.DB, t.TempDir())
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/register", h.RegisterClusterNode)
	router.POST("/cluster/registration/confirm", h.ConfirmClusterRegistration)
	router.POST("/cluster/nodes/:id/approve", h.ApproveClusterNode)
	router.POST("/cluster/nodes/:id/reject", h.RejectClusterNode)
	router.DELETE("/cluster/nodes/:id", h.DeleteClusterNode)
	router.PUT("/cluster/nodes/:id/access-url", h.UpdateClusterNodeAccessURL)
	router.PUT("/cluster/nodes/:id/site", h.UpdateClusterNodeSiteCoordinates)
	router.POST("/cluster/nodes/:id/forget-pin", h.ForgetClusterNodePin)
	router.POST("/cluster/nodes/report", h.ReportClusterNode)

	beginImportWindowForTest(t)
	calls := []struct {
		method, path, body string
	}{
		{"POST", "/cluster/register", `{"token":"x","name":"n","ip_address":"10.0.0.2","port":8000}`},
		{"POST", "/cluster/registration/confirm", `{}`},
		{"POST", "/cluster/nodes/2/approve", ``},
		{"POST", "/cluster/nodes/2/reject", ``},
		{"DELETE", "/cluster/nodes/2", ``},
		{"PUT", "/cluster/nodes/2/access-url", `{"access_url":"http://10.0.0.2:8000"}`},
		{"PUT", "/cluster/nodes/2/site", `{"server_map_lat":1.0,"server_map_lon":2.0}`},
		{"POST", "/cluster/nodes/2/forget-pin", ``},
		{"POST", "/cluster/nodes/report", `{}`},
	}
	for _, call := range calls {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s %s status=%d body=%s, want 409（导入窗口节点写端点 fast-fail）", call.method, call.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "配置导入进行中") {
			t.Fatalf("%s %s body=%s, want 配置导入进行中 文案", call.method, call.path, rec.Body.String())
		}
	}
}

func TestV1ImportQueueFailureStillConverges(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	// 注入队列恢复失败（与 v2 钉测同一测试缝）。
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errRequeueInjected }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	// 陈旧应用失败横幅：导入成功后必须清除（v2 同口径）。
	if _, err := db.DB.Exec(`UPDATE global_config SET caddy_apply_error='stale-import-failure' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// balancer_type 无法映射 → 产生转换警告，验证 warnings 不在 queue 分支丢失。
	backup := `{"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"v1-rule","protocol":true,"listen":18443,"server_name":"v1.example.test","balancer_type":"mystery_lb","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"partial":true`) {
		t.Fatalf("status=%d body=%s, want 200 partial", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "无法映射") {
		t.Fatalf("queue 分支丢失转换警告，body=%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "证书任务恢复失败") {
		t.Fatalf("queue 分支缺恢复失败警告，body=%s", rec.Body.String())
	}
	// 重载审计与陈旧横幅清理（v2 :4650-4662 同口径）。审计写 AuditDB。
	var reloadAudit int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务'`).Scan(&reloadAudit); err != nil {
		t.Fatal(err)
	}
	if reloadAudit == 0 {
		t.Fatalf("queue 分支缺「重载」审计")
	}
	var applyError string
	if err := db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&applyError); err != nil {
		t.Fatal(err)
	}
	if applyError != "" {
		t.Fatalf("陈旧 caddy_apply_error=%q 未随导入收敛清除", applyError)
	}
}

var errRequeueInjected = errors.New("requeue injected failure")

// UpdateClusterNodeAccessURL 门控必须前置——导入窗口/从节点的
// 请求体再畸形也先得 409/403 门控语义，不得先撞 JSON 解析 400（门控失真）。
func TestUpdateClusterNodeAccessURL_importGatePrecedesBodyParse(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.clusterService = services.NewClusterService(db.DB, t.TempDir())
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/cluster/nodes/:id/access-url", h.UpdateClusterNodeAccessURL)

	beginImportWindowForTest(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/cluster/nodes/2/access-url", strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（导入窗口门控先于请求体解析）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "配置导入进行中") {
		t.Fatalf("body=%s, want 配置导入进行中 文案", rec.Body.String())
	}
}

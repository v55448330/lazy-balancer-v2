package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 导入侧 upstream_keepalive_timeout 的负值/非整数归零由链内全局配置数值归一
// 单点完成并产生说明（预览 warning 与导入成功审计同源）；写侧拒绝负值，负值
// 落库后基础设置保存恒 400、规则编辑被同门卡死。
func TestImportChain_normalizesKeepaliveWithClampNote(t *testing.T) {
	normalize := func(value any) (any, []string) {
		t.Helper()
		config := map[string]any{"upstream_keepalive_timeout": value}
		chain := &importValidationChain{backup: &configBackup{Config: config}}
		if err := chain.normalizeGlobalConfigNumbers(); err != nil {
			t.Fatalf("normalizeGlobalConfigNumbers(%v): %v", value, err)
		}
		return config["upstream_keepalive_timeout"], chain.result.ConfigClampNotes
	}

	for _, tt := range []struct {
		name  string
		value any
	}{
		{"负整数", int64(-5)},
		{"负浮点", float64(-5)},
		{"非整数形态", "not-a-number"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stored, notes := normalize(tt.value)
			if got, ok := backupInteger(stored); !ok || got != 0 {
				t.Fatalf("keepalive=%v, want 0（负值/非整数必须归零）", stored)
			}
			if len(notes) != 1 || !strings.Contains(notes[0], "upstream_keepalive_timeout") {
				t.Fatalf("notes=%v, want 一条点名 upstream_keepalive_timeout 的归一说明", notes)
			}
		})
	}

	// 回归形状：合法值原样保留且不产生说明（不得把钳制扩大成恒零）。
	stored, notes := normalize(int64(60))
	if got, _ := backupInteger(stored); got != 60 {
		t.Fatalf("keepalive=%d, want 60", got)
	}
	if len(notes) != 0 {
		t.Fatalf("合法值产生归一说明: %v", notes)
	}
}

// github_proxy_url 与 oidc_config 必须前移到导入门。
func TestValidateV2BackupRuntimeSettings_rejectsUnsafeGlobalWriteSideValues(t *testing.T) {
	if err := validateV2BackupRuntimeSettings(map[string]any{"github_proxy_url": "http://evil.example/steal/"}, nil); err == nil {
		t.Fatal("白名单外 GitHub 代理地址必须 400")
	}
	if err := validateV2BackupRuntimeSettings(map[string]any{"oidc_config": "{not-json"}, nil); err == nil {
		t.Fatal("损坏 OIDC 配置必须 400")
	}
	if err := validateV2BackupRuntimeSettings(map[string]any{"oidc_config": `{"enabled":true,"issuer":"","client_id":""}`}, nil); err == nil {
		t.Fatal("启用但缺 issuer/client_id 的 OIDC 配置必须 400")
	}
	// 门必须与保存侧/登录侧共用同一条完整性判据（OIDCConfig.usable）：
	// 只查 issuer/client_id 会放行「缺 client_secret」与「issuer 不合规」的
	// 已启用配置，落库后公开状态虽隐藏按钮、直连 /auth/oidc/login 仍进入
	// discovery/令牌交换并必败（表面启用、实际不可用）。
	if err := validateV2BackupRuntimeSettings(map[string]any{"oidc_config": `{"enabled":true,"issuer":"https://idp.example.com","client_id":"cid"}`}, nil); err == nil {
		t.Fatal("启用但缺 client_secret 的 OIDC 配置必须 400")
	}
	if err := validateV2BackupRuntimeSettings(map[string]any{"oidc_config": `{"enabled":true,"issuer":"http://idp.example.com","client_id":"cid","client_secret":"sec"}`}, nil); err == nil {
		t.Fatal("非回环 http issuer 的已启用 OIDC 配置必须 400")
	}
	// 回归形状：空 OIDC（未配置）、合法白名单代理与完整合规配置放行。
	okConfigs := []map[string]any{
		{"oidc_config": ""},
		{"github_proxy_url": "https://v4.gh-proxy.org/"},
		{"oidc_config": `{"enabled":true,"issuer":"https://idp.example.com","client_id":"cid","client_secret":"sec"}`},
		{"oidc_config": `{"enabled":true,"issuer":"http://127.0.0.1:9000","client_id":"cid","client_secret":"sec"}`},
	}
	for _, cfg := range okConfigs {
		if err := validateV2BackupRuntimeSettings(cfg, nil); err != nil {
			t.Fatalf("config=%v 应放行: %v", cfg, err)
		}
	}
}

// nodes 重复身份行必须在行级门 400 点名，而不是事务内
// UNIQUE 约束失败以 500 整体回滚。
func TestValidateV2BackupNodeRows_rejectsDuplicateIdentity(t *testing.T) {
	rows := []map[string]any{
		{"name": "n1", "ip_address": "10.0.0.5", "port": int64(8000)},
		{"name": "n2", "ip_address": "10.0.0.5", "port": int64(8000)},
	}
	err := validateV2BackupNodeRows(rows)
	if err == nil {
		t.Fatal("重复 (ip_address, port) 行必须 400")
	}
	if !strings.Contains(err.Error(), "第 1 行") || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("err=%v, want 点名重复行", err)
	}
	// 回归形状：不同身份放行（端口缺省按 schema 默认 8000 归并身份）。
	ok := []map[string]any{
		{"name": "n1", "ip_address": "10.0.0.5", "port": int64(8000)},
		{"name": "n2", "ip_address": "10.0.0.6"},
	}
	if err := validateV2BackupNodeRows(ok); err != nil {
		t.Fatalf("不同身份应放行: %v", err)
	}
}

// nodes.mode 导入值域：仅 slave 合法——模式列由注册路径独占写入，巡检按
// mode='slave' 过滤，放行 master 行会让该节点永久退出离线/滞后判定（节点
// 列表仍展示、上报仍被接受）。非法值/越界值点名 400，空串按 schema DEFAULT
// （slave）归一。
func TestValidateV2BackupNodeRows_validatesModeEnum(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"name": "edge-mode", "ip_address": "10.0.0.9", "port": int64(8000)}
	}
	// 从节点行放行
	rows := []map[string]any{base()}
	rows[0]["mode"] = "slave"
	if err := validateV2BackupNodeRows(rows); err != nil {
		t.Fatalf("mode=slave 应放行: %v", err)
	}
	// 空串归一为 schema DEFAULT slave（与 protocol 空串归一同口径）
	rows = []map[string]any{base()}
	rows[0]["mode"] = ""
	if err := validateV2BackupNodeRows(rows); err != nil {
		t.Fatalf("空 mode 应归一放行: %v", err)
	}
	if rows[0]["mode"] != "slave" {
		t.Fatalf("空 mode 归一=%q, want slave", rows[0]["mode"])
	}
	// master 行点名拒绝（不静默改写：改写会掩盖备份来自别的角色/旧版本）
	rows = []map[string]any{base()}
	rows[0]["mode"] = "master"
	err := validateV2BackupNodeRows(rows)
	if err == nil || !strings.Contains(err.Error(), "master") || !strings.Contains(err.Error(), "第 1 行") {
		t.Fatalf("err=%v, want master 行点名拒绝", err)
	}
	// 非法值域点名拒绝
	rows = []map[string]any{base()}
	rows[0]["mode"] = "primary"
	err = validateV2BackupNodeRows(rows)
	if err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("err=%v, want mode 值域点名拒绝", err)
	}
	// 非字符串拒绝
	rows = []map[string]any{base()}
	rows[0]["mode"] = int64(1)
	if err := validateV2BackupNodeRows(rows); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("err=%v, want mode 类型点名拒绝", err)
	}
}

// 证书物化只针对 manual 源——acme_dns 行不得把私钥
// 物化到 /app/certs（DB 已不引用的残留材料）。
func TestCollectImportCertificates_skipsNonManualTLSSource(t *testing.T) {
	rows := []map[string]any{
		{"caddy_id": "lb_acme", "name": "acme", "domain": "acme.test", "protocol": "http", "enable_tls": int64(1), "tls_source": "acme_dns", "tls_cert": "CERT", "tls_key": "KEY"},
		{"caddy_id": "lb_manual", "name": "manual", "domain": "manual.test", "protocol": "http", "enable_tls": int64(1), "tls_source": "manual", "tls_cert": "CERT", "tls_key": "KEY"},
		{"caddy_id": "lb_tls_off", "name": "off", "domain": "off.test", "protocol": "http", "enable_tls": int64(0), "tls_source": "manual", "tls_cert": "CERT", "tls_key": "KEY"},
		{"caddy_id": "lb_tcp", "name": "tcp", "domain": "", "protocol": "tcp", "enable_tls": int64(1), "tls_source": "manual", "tls_cert": "CERT", "tls_key": "KEY"},
	}
	certs, _ := collectImportCertificates(rows)
	if len(certs) != 1 || certs[0].ruleID != "lb_manual" {
		t.Fatalf("certs=%+v, want 仅 lb_manual（acme_dns/未启 TLS/TCP 均不得物化）", certs)
	}
}

// v2 导入空体必须报「内容为空」，而不是落入通用格式错误。
func TestImportConfigBackup_emptyBodyIsExplicit(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "内容为空") {
		t.Fatalf("body=%s, want 显式「内容为空」", rec.Body.String())
	}
}

// BOM 剥离先于 lbbak 魔数检测——BOM+lbbak 必须得到
// 「请使用 /api/v1/config/import」指引而非「不是有效的 JSON」。
func TestImportV1Config_BOMWrappedLbbakGetsV2Hint(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)

	body := append([]byte{0xef, 0xbb, 0xbf, 0x1f, 0x8b}, []byte("fake-gzip-body")...)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "lbbak") {
		t.Fatalf("body=%s, want lbbak 端点指引（BOM 必须先剥离）", rec.Body.String())
	}
}

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 规则级 NTLM 兼容开关（2026-10-12 用户定稿）四组契约中的三组：
// ②校验拒绝（ntlm+非 cookie 策略 400；TCP+ntlm 400；存量启用门同口径）
// ③落库 round-trip（创建/更新/省略合并 + GetRule 回读）
// （①渲染形状在 internal/services/ntlm_render_test.go；④导入携带在文末。）

func ntlmCreateRouter(t *testing.T) *gin.Engine {
	t.Helper()
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	router.GET("/rules/:caddy_id", handler.GetRule)
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	return router
}

func serveJSON(t *testing.T, router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if body == "" {
		request = httptest.NewRequest(method, path, nil)
	} else {
		request = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// ---- ② 校验拒绝 ----

func TestCreateRule_rejects_ntlm_with_non_cookie_strategy(t *testing.T) {
	router := ntlmCreateRouter(t)

	response := serveJSON(t, router, http.MethodPost, "/rules", `{
		"name":"ntlm-poll","protocol":"http","domain":"ntlm-poll.example.test","listen_port":18001,
		"strategy":"weighted_round_robin","ntlm_compatible":1,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "NTLM 兼容模式要求负载策略为 Cookie 会话保持") {
		t.Fatalf("create ntlm+round_robin status=%d body=%s, want 400 with strategy message", response.Code, response.Body.String())
	}
}

func TestCreateRule_rejects_ntlm_on_tcp_rule(t *testing.T) {
	router := ntlmCreateRouter(t)

	response := serveJSON(t, router, http.MethodPost, "/rules", `{
		"name":"ntlm-tcp","protocol":"tcp","listen_port":18002,
		"ntlm_compatible":1,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "NTLM") {
		t.Fatalf("create tcp+ntlm status=%d body=%s, want 400 with NTLM message", response.Code, response.Body.String())
	}
}

func ntlmCreateAndWait(t *testing.T, router *gin.Engine, body string) string {
	t.Helper()
	created := serveJSON(t, router, http.MethodPost, "/rules", body)
	if created.Code != http.StatusCreated {
		t.Fatalf("seed create status=%d body=%s, want 201", created.Code, created.Body.String())
	}
	var createdPayload struct {
		Data struct {
			CaddyID string `json:"caddy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdPayload); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createdPayload.Data.CaddyID == "" {
		t.Fatalf("create response missing caddy_id: %s", created.Body.String())
	}
	return createdPayload.Data.CaddyID
}

func TestUpdateRule_rejects_strategy_change_while_ntlm_on(t *testing.T) {
	router := ntlmCreateRouter(t)
	caddyID := ntlmCreateAndWait(t, router, `{
		"name":"ntlm-edit","protocol":"http","domain":"ntlm-edit.example.test","listen_port":18003,
		"strategy":"cookie","ntlm_compatible":1,
		"tcp_try_duration":-1,"upstream_force_http1":1,"proxy_flush_interval":-1,"upstream_keepalive_timeout":300,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`)

	response := serveJSON(t, router, http.MethodPut, "/rules/"+caddyID, `{"strategy":"ip_hash"}`)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "NTLM 兼容模式要求负载策略为 Cookie 会话保持") {
		t.Fatalf("update strategy away from cookie status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}

func TestValidateStoredRuleConfig_rejects_stored_ntlm_with_wrong_strategy(t *testing.T) {
	newRuleFeatureTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,ntlm_compatible,enabled)
		VALUES ('lb_ntlmdead','dead','http','dead.example.test',18004,'ip_hash',1,0)`); err != nil {
		t.Fatalf("seed stored rule: %v", err)
	}

	err := validateStoredRuleConfig(context.Background(), "lb_ntlmdead")
	if err == nil || !strings.Contains(err.Error(), "NTLM") {
		t.Fatalf("enable gate err=%v, want NTLM rejection for stored ntlm=1 + ip_hash", err)
	}
}

// ---- ③ 落库 round-trip ----

func TestCreateRule_persists_ntlm_and_getrule_returns_it(t *testing.T) {
	router := ntlmCreateRouter(t)

	created := serveJSON(t, router, http.MethodPost, "/rules", `{
		"name":"ntlm-ok","protocol":"http","domain":"ntlm-ok.example.test","listen_port":18005,
		"strategy":"cookie","ntlm_compatible":1,
		"tcp_try_duration":-1,"upstream_force_http1":1,"proxy_flush_interval":-1,"upstream_keepalive_timeout":300,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create ntlm+cookie status=%d body=%s, want 201", created.Code, created.Body.String())
	}

	var stored int
	if err := db.DB.QueryRow(`SELECT COALESCE(ntlm_compatible,0) FROM lb_rules WHERE listen_port=18005`).Scan(&stored); err != nil {
		t.Fatalf("read stored ntlm_compatible: %v", err)
	}
	if stored != 1 {
		t.Fatalf("stored ntlm_compatible=%d, want 1", stored)
	}

	var caddyID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE listen_port=18005`).Scan(&caddyID); err != nil {
		t.Fatalf("read caddy_id: %v", err)
	}

	fetched := serveJSON(t, router, http.MethodGet, "/rules/"+caddyID, "")
	if fetched.Code != http.StatusOK {
		t.Fatalf("get rule status=%d body=%s", fetched.Code, fetched.Body.String())
	}
	var payload struct {
		Data struct {
			NTLMCompatible int `json:"ntlm_compatible"`
		} `json:"data"`
	}
	if err := json.Unmarshal(fetched.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode get rule: %v", err)
	}
	if payload.Data.NTLMCompatible != 1 {
		t.Fatalf("GetRule ntlm_compatible=%d, want 1 (round-trip)", payload.Data.NTLMCompatible)
	}
}

func TestUpdateRule_ntlm_off_restores_zero_and_omitted_keeps_value(t *testing.T) {
	router := ntlmCreateRouter(t)
	caddyID := ntlmCreateAndWait(t, router, `{
		"name":"ntlm-off","protocol":"http","domain":"ntlm-off.example.test","listen_port":18006,
		"strategy":"cookie","ntlm_compatible":1,
		"tcp_try_duration":-1,"upstream_force_http1":1,"proxy_flush_interval":-1,"upstream_keepalive_timeout":300,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`)

	// 省略 ntlm_compatible（nil=保留原值）
	omitted := serveJSON(t, router, http.MethodPut, "/rules/"+caddyID, `{"name":"ntlm-off-2"}`)
	if omitted.Code != http.StatusOK {
		t.Fatalf("update without ntlm status=%d body=%s", omitted.Code, omitted.Body.String())
	}
	var kept int
	if err := db.DB.QueryRow(`SELECT COALESCE(ntlm_compatible,0) FROM lb_rules WHERE listen_port=18006`).Scan(&kept); err != nil {
		t.Fatalf("read kept ntlm: %v", err)
	}
	if kept != 1 {
		t.Fatalf("omitted ntlm_compatible=%d, want 1 (nil keeps stored value)", kept)
	}

	// 显式关闭（0）——策略同步回默认
	off := serveJSON(t, router, http.MethodPut, "/rules/"+caddyID, `{"ntlm_compatible":0,"strategy":"weighted_round_robin"}`)
	if off.Code != http.StatusOK {
		t.Fatalf("update ntlm off status=%d body=%s", off.Code, off.Body.String())
	}
	var after int
	if err := db.DB.QueryRow(`SELECT COALESCE(ntlm_compatible,0) FROM lb_rules WHERE listen_port=18006`).Scan(&after); err != nil {
		t.Fatalf("read ntlm after off: %v", err)
	}
	if after != 0 {
		t.Fatalf("ntlm_compatible after off=%d, want 0", after)
	}
	// ntlm=0 不负责复位接管四列（设计契约：UI 的 restoreNtlmDefaults 才复位；
	// 后端不静默改写用户显式/存量的代理参数）。
	var tryDuration, forceHTTP1, flushInterval, keepalive int
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_duration,0), COALESCE(upstream_force_http1,0),
		COALESCE(proxy_flush_interval,0), COALESCE(upstream_keepalive_timeout,0)
		FROM lb_rules WHERE listen_port=18006`).
		Scan(&tryDuration, &forceHTTP1, &flushInterval, &keepalive); err != nil {
		t.Fatalf("read takeover columns: %v", err)
	}
	if tryDuration != -1 || forceHTTP1 != 1 || flushInterval != -1 || keepalive != 300 {
		t.Fatalf("ntlm=0 不得复位接管四列: td=%d force=%d flush=%d keepalive=%d, want -1/1/-1/300",
			tryDuration, forceHTTP1, flushInterval, keepalive)
	}
}

// ---- ④ 导入携带 ntlm 字段 ----

func TestConfigBackup_export_import_roundtrip_preserves_ntlm(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, strategy, ntlm_compatible, enabled,
		tcp_try_duration, upstream_force_http1, proxy_flush_interval, upstream_keepalive_timeout)
		VALUES ('lb_ntlmbak', 'ntlm-backup', 'http', 'ntlm-backup.example.test', 8080, 'cookie', 1, 1, -1, 1, -1, 300)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, enabled) VALUES ('lb_ntlmbak', '127.0.0.1', 9000, 1, 1)`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES ('keep', 'hash', 'admin')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)

	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d", exportResponse.Code)
	}
	backup := string(unpackExportBody(t, exportResponse.Body.Bytes()))
	if !strings.Contains(backup, `"ntlm_compatible":1`) {
		t.Fatalf("export missing ntlm_compatible=1: %.400s", backup)
	}

	if _, err := db.DB.Exec("DELETE FROM lb_rules"); err != nil {
		t.Fatalf("destructive change: %v", err)
	}
	importResponse := httptest.NewRecorder()
	importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	importRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResponse, importRequest)
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%.400s", importResponse.Code, importResponse.Body.String())
	}

	var restored int
	if err := db.DB.QueryRow(`SELECT COALESCE(ntlm_compatible,0) FROM lb_rules WHERE caddy_id='lb_ntlmbak'`).Scan(&restored); err != nil {
		t.Fatalf("read restored ntlm: %v", err)
	}
	if restored != 1 {
		t.Fatalf("restored ntlm_compatible=%d, want 1 (backup import must carry the flag)", restored)
	}
}

func TestImportConfigBackup_rejects_ntlm_with_invalid_shape(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	cases := []struct {
		name string
		rule map[string]any
		want string
	}{
		{
			name: "ntlm+轮询策略",
			rule: map[string]any{"caddy_id": "lb_ntlmbad1", "name": "bad1", "protocol": "http", "domain": "bad1.example.test",
				"listen_port": 18007, "strategy": "weighted_round_robin", "ntlm_compatible": 1, "enabled": 1},
			want: "NTLM 兼容模式要求负载策略为 Cookie 会话保持",
		},
		{
			name: "tcp+ntlm",
			rule: map[string]any{"caddy_id": "lb_ntlmbad2", "name": "bad2", "protocol": "tcp",
				"listen_port": 18008, "strategy": "weighted_round_robin", "ntlm_compatible": 1, "enabled": 1},
			want: "NTLM",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{"lb_rules": {testCase.rule}}, EmptyConfigIfNil: true})
			response := httptest.NewRecorder()
			importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
			importRequest.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, importRequest)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), testCase.want) {
				t.Fatalf("import status=%d body=%.300s, want 400 containing %q", response.Code, response.Body.String(), testCase.want)
			}
		})
	}
}

// TCP 行的 ntlm_compatible 是死列（TCP 规则创建/导入显式携带即 400）。
// 存量/直改 DB 的残留 1 不得让任何无关编辑恒 400（死端），也不得被用户显式
// 携带的 1 静默改写成 0（意图丢失）。形态一：未携带 → 200 且存量 1 自愈归零；
// 形态二：显式携带 1 → 400 点名 NTLM，且库值保持 0（未落库）。
func TestUpdateRule_tcpExplicitNTLMRejectedAndStaleValueSelfHeals(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,ntlm_compatible)
		VALUES ('lb_tcpntlm','tcp-ntlm','','tcp','',18021,'weighted_round_robin',1,1)`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcpntlm','127.0.0.1',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed tcp upstream: %v", err)
	}

	// ① 未携带 ntlm：存量死值自愈归零，编辑成功。
	response := serveJSON(t, router, http.MethodPut, "/rules/lb_tcpntlm", `{"name":"tcp-ntlm-renamed","protocol":"tcp"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("omitted ntlm update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var ntlm int
	if err := db.DB.QueryRow(`SELECT COALESCE(ntlm_compatible,0) FROM lb_rules WHERE caddy_id='lb_tcpntlm'`).Scan(&ntlm); err != nil {
		t.Fatal(err)
	}
	if ntlm != 0 {
		t.Fatalf("存量 ntlm 死值未自愈: ntlm_compatible=%d, want 0", ntlm)
	}

	// ② 显式携带 1：保存门 400 点名，不静默弃置。
	response = serveJSON(t, router, http.MethodPut, "/rules/lb_tcpntlm", `{"ntlm_compatible":1,"protocol":"tcp"}`)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "NTLM") {
		t.Fatalf("explicit ntlm update status=%d body=%s, want 400 with NTLM message", response.Code, response.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(ntlm_compatible,0) FROM lb_rules WHERE caddy_id='lb_tcpntlm'`).Scan(&ntlm); err != nil {
		t.Fatal(err)
	}
	if ntlm != 0 {
		t.Fatalf("被拒的显式 ntlm 不得落库: ntlm_compatible=%d, want 0", ntlm)
	}
}

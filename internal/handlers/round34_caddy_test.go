package handlers

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// Round 34 F-1: 存量 upstreams.enabled 为 NULL（schema 无 NOT NULL）时
// UpdateRule 的旧上游回读（oldUpstreams）裸 scan 会 500；IIF 归一化后
// NULL 视同禁用（与生成侧同口径），更新必须成功且上游保留。
func TestUpdateRule_toleratesNullEnabledUpstream(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	seedAuditRule(t, "lb_null_crud", "before", "nullcrud.example.test", 8080, true, "manual", false)
	// 混合上游：一个启用 + 一个 NULL（NULL 行走 IIF 归一化，不再炸 scan）；
	// schema 已 NOT NULL，先回退为迁移前可空结构再写入 NULL 行
	simulateLegacyNullableUpstreams(t, db.DB)
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_null_crud','127.0.0.1',9000,1,NULL,'http'), ('lb_null_crud','127.0.0.1',9001,1,1,'http')`); err != nil {
		t.Fatalf("seed null-enabled upstream: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_null_crud", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then 200，上游保留
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var hosts []string
	rows, err := db.DB.Query(`SELECT host FROM upstreams WHERE rule_id='lb_null_crud' ORDER BY port`)
	if err != nil {
		t.Fatalf("query upstreams: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			t.Fatalf("scan upstream: %v", err)
		}
		hosts = append(hosts, host)
	}
	if len(hosts) != 2 || hosts[0] != "127.0.0.1" || hosts[1] != "127.0.0.1" {
		t.Fatalf("upstreams=%v, want 两个保留", hosts)
	}
	// And 保存后不再存在 NULL 行（IIF 读回 NULL=禁用，重写落库为 0，迁移口径一致）
	var nulls int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM upstreams WHERE rule_id='lb_null_crud' AND enabled IS NULL`).Scan(&nulls); err != nil {
		t.Fatalf("count null upstreams: %v", err)
	}
	if nulls != 0 {
		t.Fatalf("null enabled rows=%d after save, want 0（不再存在 NULL 行）", nulls)
	}
	var enabledSum int
	if err := db.DB.QueryRow(`SELECT COALESCE(SUM(enabled),0) FROM upstreams WHERE rule_id='lb_null_crud'`).Scan(&enabledSum); err != nil {
		t.Fatalf("sum enabled upstreams: %v", err)
	}
	if enabledSum != 1 {
		t.Fatalf("enabled sum=%d, want 1（NULL→0，显式 1 保持）", enabledSum)
	}
}

// Round 35 F-1: 仅含 NULL 启用上游的规则 EnableRule 不再「看似有上游」——loader
// 与渲染同口径（NULL=禁用）后命中零上游特判：启用成功且渲染侧明确提示跳过
// （规则「已启用」但无可用上游不再静默）。
func TestEnableRule_ruleWithOnlyNullEnabledUpstreams_clearSkipLog(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	seedAuditRule(t, "lb_null_enable", "only-null", "nullenable.example.test", 8080, false, "manual", false)
	simulateLegacyNullableUpstreams(t, db.DB)
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_null_enable','127.0.0.1',9000,1,NULL,'http')`); err != nil {
		t.Fatalf("seed null-enabled upstream: %v", err)
	}
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_null_enable/enable", nil))

	// Then 启用成功（零上游特判与渲染侧跳过一致，无幻影校验失败）
	if response.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_null_enable'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if !enabled {
		t.Fatal("rule should be enabled")
	}
	// And 渲染侧明确提示「没有可用的启用上游」，不再静默丢流量
	if !strings.Contains(logs.String(), "没有可用的启用上游") {
		t.Fatalf("render skip log missing:\n%s", logs.String())
	}
}

// Round 34 F-1: DuplicateRule 复制含 NULL enabled 上游的规则不得 500；
// 副本上游显式落 0（NULL 视同禁用，复制后不意外启用）。
func TestDuplicateRule_toleratesNullEnabledUpstream(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	seedAuditRule(t, "lb_null_dup", "source", "nulldup.example.test", 8080, true, "manual", false)
	simulateLegacyNullableUpstreams(t, db.DB)
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_null_dup','127.0.0.1',9000,1,NULL,'http')`); err != nil {
		t.Fatalf("seed null-enabled upstream: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules/lb_null_dup/duplicate", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then 201，副本上游存在且为禁用（0）
	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			CaddyID string `json:"caddy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("parse response: %v body=%s", err, response.Body.String())
	}
	var count int
	var enabled int
	if err := db.DB.QueryRow(`SELECT COUNT(*), COALESCE(enabled,9) FROM upstreams WHERE rule_id=?`, payload.Data.CaddyID).Scan(&count, &enabled); err != nil {
		t.Fatalf("read duplicated upstream: %v", err)
	}
	if count != 1 || enabled != 0 {
		t.Fatalf("duplicated upstream count=%d enabled=%d, want 1/0", count, enabled)
	}
}

// Round 34 F-4: AuditLogSizeMB ≤ 0 拒绝（与 RuntimeLogSizeMB/CertJobLogSizeMB
// 的 >0 校验同口径），负值不再经集群同步照单全收。
func TestUpdateConfig_rejectsAuditLogSizeMBAtOrBelowZero(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	for _, body := range []string{`{"source":"basic","audit_log_size_mb":0}`, `{"source":"basic","audit_log_size_mb":-5}`} {
		// When
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		// Then 400 + 明确中文文案
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d, want 400", body, response.Code)
		}
		if !strings.Contains(response.Body.String(), "审计日志轮转大小必须大于 0") {
			t.Fatalf("body=%s, want 审计日志轮转大小必须大于 0", response.Body.String())
		}
	}
}

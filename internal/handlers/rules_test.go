package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)


// RH-1(第 5 轮审计 P2):CreateRule 对禁用规则(enabled=false)不应创建
// ACME 签发任务——复制向导硬编码 enabled:false,每次复制白烧 1 次 LE 配额。
// UpdateRule 已有此门(rules.go:1704),CreateRule 缺失(系统不变量:禁用⇒不签发)。
func TestCreateRule_disabledRuleDoesNotQueueCertJob(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	// Seed: DNS 提供商配置(通过 ACMEConfigID 引用)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id, name, dns_provider, dns_credentials, enabled) VALUES (1, 'test-dns', 'dnspod', '{}', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET default_ca_provider_id=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.POST("/api/v1/rules", handler.CreateRule)

	enabled := false
	body := map[string]any{
		"name": "disabled-acme", "protocol": "http", "domain": "disabled-acme.test",
		"listen_port": 443, "strategy": "weighted_round_robin",
		"enable_tls": true, "tls_source": "acme_dns", "acme_config_id": 1, "enabled": enabled,
		"upstreams": []map[string]any{{"host": "10.0.0.1", "port": 8080, "weight": 1, "enabled": true}},
	}
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create disabled rule status=%d body=%s", rec.Code, rec.Body.String())
	}
	// 从响应取 caddy_id 查 cert_jobs
	var resp struct {
		Data struct {
			CaddyID string `json:"caddy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id=?", resp.Data.CaddyID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count > 0 {
		t.Fatalf("禁用规则不应创建签发任务, got %d cert_jobs", count)
	}
}

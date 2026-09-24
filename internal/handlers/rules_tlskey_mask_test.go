package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// F50-7（第 50 轮审计）：手动证书私钥与导出备份同敏感级——GET /rules/:caddy_id
// 仅管理员 JWT 与管理员读写 Key 可回读 tls_key；只读 Key/非管理员掩码为空串，
// 并以 tls_key_set 区分「已有隐藏私钥」与「未配置」。

func seedManualTLSRuleWithKey(t *testing.T, caddyID, certPEM, keyPEM string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, description, protocol, domain, listen_port, enabled, enable_tls, tls_source, tls_cert, tls_key)
		VALUES (?, '手动证书规则', '', 'http', 'mask.example.test', 443, 1, 1, 'manual', ?, ?)`, caddyID, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
}

func getRuleAs(t *testing.T, h *Handlers, caddyID string, sets map[string]any) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id", func(c *gin.Context) {
		for k, v := range sets {
			c.Set(k, v)
		}
		h.GetRule(c)
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/rules/"+caddyID, nil))
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	data, _ := body["data"].(map[string]any)
	return recorder.Code, data
}

func TestGetRule_masksTLSKeyForNonAdminAndReadOnlyKey(t *testing.T) {
	// Given 手动证书规则（含真实私钥材料）
	h := newRuleFeatureTestHandlers(t)
	certPEM, keyPEM, err := generateTestCert("mask.example.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	seedManualTLSRuleWithKey(t, "lb_maskkey", certPEM, keyPEM)

	cases := []struct {
		name      string
		sets      map[string]any
		wantKey   bool
		wantKeyID bool
	}{
		{"管理员 JWT 明文", map[string]any{"role": "admin", "auth_type": "jwt"}, true, false},
		{"管理员读写 Key 明文", map[string]any{"role": "admin", "auth_type": "api_key", "api_key_read_only": false}, true, false},
		{"非管理员 JWT 掩码", map[string]any{"role": "user", "auth_type": "jwt"}, false, true},
		{"只读 API Key 掩码", map[string]any{"role": "admin", "auth_type": "api_key", "api_key_read_only": true}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// When
			code, data := getRuleAs(t, h, "lb_maskkey", tc.sets)

			// Then
			if code != http.StatusOK {
				t.Fatalf("status=%d", code)
			}
			key, _ := data["tls_key"].(string)
			keySet, _ := data["tls_key_set"].(bool)
			if tc.wantKey && key != keyPEM {
				t.Fatalf("tls_key 未回明文（len=%d）", len(key))
			}
			if !tc.wantKey && key != "" {
				t.Fatalf("tls_key=%q, want 掩码空串", key)
			}
			if keySet != tc.wantKeyID {
				t.Fatalf("tls_key_set=%v, want %v", keySet, tc.wantKeyID)
			}
		})
	}
}

func TestUpdateRule_emptyTLSKeyPreservesStoredKey(t *testing.T) {
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	// Given 手动证书规则（含真实私钥材料）——掩码表单回提交空 tls_key
	h := newRuleFeatureTestHandlers(t)
	certPEM, keyPEM, err := generateTestCert("mask.example.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	seedManualTLSRuleWithKey(t, "lb_keepkey", certPEM, keyPEM)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("role", "user")
		h.UpdateRule(c)
	})

	// When 提交空 tls_key（证书原样、其余字段原样）
	body, _ := json.Marshal(map[string]any{
		"name": "手动证书规则", "protocol": "http", "domain": "mask.example.test", "listen_port": 443,
		"enabled": true, "enable_tls": true, "tls_source": "manual", "tls_cert": certPEM, "tls_key": "",
		"upstreams": []map[string]any{{"host": "127.0.0.1", "port": 9000, "weight": 100, "enabled": true}},
	})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/rules/lb_keepkey", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)

	// Then 私钥保留（不被空值覆盖）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id='lb_keepkey'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != keyPEM {
		t.Fatalf("tls_key 未被保留（len=%d, want %d）", len(stored), len(keyPEM))
	}
}

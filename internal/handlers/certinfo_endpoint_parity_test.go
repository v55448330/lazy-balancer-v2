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
)

func certInfoTestRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/rules/:caddy_id/cert-info", h.GetRuleCertInfo)
	r.POST("/rules/cert-info", h.GetRulesCertInfo)
	return r
}

// 单规则与批量证书信息必须同口径：禁用规则（enabled=0，仍保留 enable_tls=1 与
// 证书材料）在两个端点都返回 null。批量接口此前只读 enable_tls，于是同一张证书
// 在列表 tooltip 有详情、在规则流程详情显示「规则禁用或证书未就绪」——
// 104 轮修了服务侧单规则路径，批量 handler 未同步。
func TestCertInfoEndpoints_disabledRuleIsNullOnBothEndpoints(t *testing.T) {
	h := newBackupTestHandlers(t)
	certPEM, keyPEM, err := generateTestCert("disabled-both.test", time.Now().Add(-time.Hour), time.Now().Add(720*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_ci_disabled','禁用','disabled-both.test','http',8443,0,1,'manual',?,?),
		('lb_ci_enabled','启用','enabled-both.test','http',8444,1,1,'manual',?,?)`, certPEM, keyPEM, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES
		('lb_ci_disabled_acme','禁用 ACME','disabled-acme.test','http',8445,0,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,updated_at)
		VALUES ('lb_ci_disabled_acme','disabled-acme.test','issued',?,?,datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	router := certInfoTestRouter(h)

	for _, tc := range []struct {
		ruleID  string
		wantNil bool
	}{
		{"lb_ci_disabled", true},
		{"lb_ci_disabled_acme", true},
		{"lb_ci_enabled", false},
	} {
		t.Run(tc.ruleID, func(t *testing.T) {
			// 单规则端点
			single := httptest.NewRecorder()
			router.ServeHTTP(single, httptest.NewRequest(http.MethodGet, "/rules/"+tc.ruleID+"/cert-info", nil))
			if single.Code != http.StatusOK {
				t.Fatalf("单规则 status=%d body=%s", single.Code, single.Body.String())
			}
			var singleResp struct {
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(single.Body.Bytes(), &singleResp); err != nil {
				t.Fatal(err)
			}
			singleNil := string(singleResp.Data) == "null"

			// 批量端点
			batch := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/rules/cert-info", strings.NewReader(`{"caddy_ids":["`+tc.ruleID+`"]}`))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(batch, req)
			if batch.Code != http.StatusOK {
				t.Fatalf("批量 status=%d body=%s", batch.Code, batch.Body.String())
			}
			var batchResp struct {
				Data map[string]json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(batch.Body.Bytes(), &batchResp); err != nil {
				t.Fatal(err)
			}
			batchNil := string(batchResp.Data[tc.ruleID]) == "null"

			if singleNil != tc.wantNil || batchNil != tc.wantNil {
				t.Fatalf("单规则 null=%v / 批量 null=%v, want 两者都为 %v（端点口径必须一致）", singleNil, batchNil, tc.wantNil)
			}
		})
	}
}

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
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
	// ACME 候选按「证书 DNS 名覆盖规则域名」选取（selectCertificate），材料证书
	// 必须签给该规则域名，否则两端只会各自返回「尚未签发」而比较不到真实字段值。
	acmeCertPEM, acmeKeyPEM, err := generateTestCert("enabled-acme.test", time.Now().Add(-time.Hour), time.Now().Add(720*time.Hour))
	if err != nil {
		t.Fatalf("generate acme cert: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_ci_disabled','禁用','disabled-both.test','http',8443,0,1,'manual',?,?),
		('lb_ci_enabled','启用','enabled-both.test','http',8444,1,1,'manual',?,?)`, certPEM, keyPEM, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES
		('lb_ci_disabled_acme','禁用 ACME','disabled-acme.test','http',8445,0,1,'acme_dns'),
		('lb_ci_enabled_acme','启用 ACME','enabled-acme.test','http',8446,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,updated_at)
		VALUES ('lb_ci_disabled_acme','disabled-acme.test','issued',?,?,datetime('now')),
		('lb_ci_enabled_acme','enabled-acme.test','issued',?,?,datetime('now'))`, acmeCertPEM, acmeKeyPEM, acmeCertPEM, acmeKeyPEM); err != nil {
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
		{"lb_ci_enabled_acme", false},
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
			batchRaw, batchPresent := batchResp.Data[tc.ruleID]
			batchNil := !batchPresent || string(batchRaw) == "null"

			if singleNil != tc.wantNil || batchNil != tc.wantNil {
				t.Fatalf("单规则 null=%v / 批量 null=%v, want 两者都为 %v（端点口径必须一致）", singleNil, batchNil, tc.wantNil)
			}
			if tc.wantNil {
				return
			}
			// 非 nil 时逐字段深度比对：只比「是否 nil」时，not_after /
			// days_remaining / status / issuer 任一侧错位用例仍绿——两端走两套
			// 查询（handlers/certinfo.go 单规则 GetRuleCertInfo vs
			// services/certinfo.go 的 GetRuleCertInfo / getACMECertInfo），
			// 口径分裂恰恰先从字段值暴露。
			// 豁免键：无。payload 里没有证书任务行 id（models.RuleCertInfo 无 id
			// 字段，caddy_id 两侧同为规则编号），故同一规则必须全字段相等；未来
			// 若出现可证明合法的差异字段，必须在此显式登记并写明理由。
			var singleInfo, batchInfo map[string]any
			if err := json.Unmarshal(singleResp.Data, &singleInfo); err != nil {
				t.Fatalf("解析单规则 data: %v", err)
			}
			if err := json.Unmarshal(batchRaw, &batchInfo); err != nil {
				t.Fatalf("解析批量 data: %v", err)
			}
			if diff := certInfoFieldDiff(singleInfo, batchInfo); diff != "" {
				t.Fatalf("同一规则的证书详情在两端不一致：%s", diff)
			}
		})
	}
}

// certInfoFieldDiff 返回两端证书详情 JSON 对象的逐字段差异（空串=完全一致）。
func certInfoFieldDiff(single, batch map[string]any) string {
	keys := make(map[string]struct{}, len(single)+len(batch))
	for key := range single {
		keys[key] = struct{}{}
	}
	for key := range batch {
		keys[key] = struct{}{}
	}
	diffs := make([]string, 0, len(keys))
	for key := range keys {
		singleValue, singleOK := single[key]
		batchValue, batchOK := batch[key]
		if singleOK != batchOK || !reflect.DeepEqual(singleValue, batchValue) {
			diffs = append(diffs, fmt.Sprintf("%s（单规则=%v 存在=%v；批量=%v 存在=%v）", key, singleValue, singleOK, batchValue, batchOK))
		}
	}
	sort.Strings(diffs)
	return strings.Join(diffs, "；")
}

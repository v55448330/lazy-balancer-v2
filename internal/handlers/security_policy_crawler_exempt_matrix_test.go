package handlers

// 爬虫豁免落库值 ×（policy_type, geoip_mode）表驱动钉：INSERT 侧活跃判定
// 单源 geoIPActive（空/off 非启用）——此前 Create 多一个 stage0 合取、与
// Update/Split 口径分叉（一致化对所有合法路径行为不变：stage0/2/3 归一先把
// geoip_mode 折为 off、exempt 折为 false；exempt=true 且 mode 空/off 仅在
// 归一未触及该族的 stage1 被 validatePolicyCrawlerExemption 前置 400）。本表
// 把「哪些形态能落 1」钉成显式矩阵，防止未来再引入按路径分叉的合取项。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestCreateSecurityPolicy_crawlerExemptPersistedMatrix(t *testing.T) {
	for _, tc := range []struct {
		policyType string
		geoipMode  string
		wantExempt bool
	}{
		// stage0：GeoIP 族整体归零（mode→off、exempt→false）——恒 0。
		{"stage0", "deny", false},
		// stage1：GeoIP/爬虫豁免保留——deny 落 1。
		{"stage1", "deny", true},
		// stage2/3：GeoIP 族归零——mode 请求值不落库，恒 0。
		{"stage2", "deny", false},
		{"stage3", "deny", false},
	} {
		t.Run(tc.policyType+"_geoip_"+tc.geoipMode, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			router := newSecurityRouter(t)
			// geoip_countries 留空：空名单不触 IP 库可用性门（矩阵钉的是
			// 豁免位与 geoip_mode 的联动，不是 IP 库装配形态）。
			body := `{"name":"crawler-matrix-` + tc.policyType + `","policy_type":"` + tc.policyType + `",
				"geoip_mode":"` + tc.geoipMode + `",
				"geoip_crawler_exempt":true,"geoip_crawler_engines":"[]"}`
			request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("create status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var payload struct {
				Data struct {
					ID int `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			var exempt bool
			var mode string
			if err := db.DB.QueryRow(`SELECT COALESCE(geoip_crawler_exempt,0), COALESCE(geoip_mode,'') FROM security_policies WHERE id=?`, payload.Data.ID).Scan(&exempt, &mode); err != nil {
				t.Fatal(err)
			}
			if exempt != tc.wantExempt {
				t.Fatalf("geoip_crawler_exempt=%v, want %v", exempt, tc.wantExempt)
			}
			if tc.wantExempt && mode != tc.geoipMode {
				t.Fatalf("geoip_mode=%q, want %q（落 1 的行必须保留活跃 mode）", mode, tc.geoipMode)
			}
		})
	}
}

// 豁免开启但 geoip_mode=off 的分叉口径：stage1 的 GeoIP 族不被归一触碰——
// validatePolicyCrawlerExemption 对「exempt=true ∧ mode off/空」前置 400；
// stage0/2/3 的 GeoIP 族先被 applyStageZerosToCreate 归零（exempt→false、
// mode→off），同一载荷按归一后值校验，200 落库恒 0（归一先于校验的单向闸）。
func TestCreateSecurityPolicy_crawlerExemptWithOffGeoIPMode(t *testing.T) {
	for _, tc := range []struct {
		policyType         string
		wantStatus         int
		wantStoredExemptOK bool
	}{
		{"stage0", http.StatusOK, true},
		{"stage1", http.StatusBadRequest, false},
		{"stage2", http.StatusOK, true},
		{"stage3", http.StatusOK, true},
	} {
		t.Run(tc.policyType, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			router := newSecurityRouter(t)
			body := `{"name":"crawler-off-` + tc.policyType + `","policy_type":"` + tc.policyType + `",
				"geoip_mode":"off","geoip_crawler_exempt":true,"geoip_crawler_engines":"[]"}`
			request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("create status=%d body=%s, want %d", response.Code, response.Body.String(), tc.wantStatus)
			}
			if !tc.wantStoredExemptOK {
				return
			}
			var exempt bool
			if err := db.DB.QueryRow(`SELECT COALESCE(geoip_crawler_exempt,0) FROM security_policies WHERE name=?`, "crawler-off-"+tc.policyType).Scan(&exempt); err != nil {
				t.Fatal(err)
			}
			if exempt {
				t.Fatal("归一后落库的豁免位必须为 0")
			}
		})
	}
}

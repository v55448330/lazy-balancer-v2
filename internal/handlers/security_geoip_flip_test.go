package handlers

// SEC40-B1-1(第 40 轮审计):GeoIP off→非 off 翻转门——存量读取与可用性
// 校验不得只挂在「请求携带 geoip_countries」上;只发 geoip_mode 的翻转、
// 条目未变仅翻 mode 的翻转,都必须过缺库 fail-closed 门。

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/services"
)

func withIP2RegionUnloaded(t *testing.T) {
	t.Helper()
	services.SetIP2RegionLiveProvincesForTest([]string{"海外"})
	t.Cleanup(func() { services.SetIP2RegionLiveProvincesForTest(nil) })
}

// 形状 A:off 策略(保留名单非空)只发 geoip_mode=deny——缺库必须 400。
func TestUpdateSecurityPolicy_geoipModeFlipWithoutEntriesRejected(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	withIP2RegionUnloaded(t)

	id := createTestPolicy(t, router, map[string]any{
		"name": "flip-mode-only", "geoip_mode": "off", "geoip_countries": `["广东"]`,
	})
	rec := putJSON(t, router, "/security/policies/1", map[string]any{"geoip_mode": "deny"})
	_ = id
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mode-only flip with missing xdb must 400, got %d %s", rec.Code, rec.Body.String())
	}
}

// 形状 B:off+条目未变,仅翻 mode——条目相等豁免不得放行翻转。
func TestUpdateSecurityPolicy_geoipModeFlipWithUnchangedEntriesRejected(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	withIP2RegionUnloaded(t)

	createTestPolicy(t, router, map[string]any{
		"name": "flip-unchanged", "geoip_mode": "off", "geoip_countries": `["火星"]`,
	})
	rec := putJSON(t, router, "/security/policies/1", map[string]any{
		"geoip_mode": "deny", "geoip_countries": `["火星"]`,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("flip with unchanged garbage entries must 400, got %d %s", rec.Code, rec.Body.String())
	}
}

// 回归形状:off 态编辑(缺库)仍放行——翻转门只约束 off→非 off。
func TestUpdateSecurityPolicy_offStateEditStillPassesWithoutXdb(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	withIP2RegionUnloaded(t)

	createTestPolicy(t, router, map[string]any{
		"name": "off-edit", "geoip_mode": "off", "geoip_countries": `["广东"]`,
	})
	rec := putJSON(t, router, "/security/policies/1", map[string]any{"description": "still off"})
	if rec.Code != http.StatusOK {
		t.Fatalf("off-state edit without xdb must pass, got %d %s", rec.Code, rec.Body.String())
	}
	// off 态改条目(形状合法)同样放行
	rec = putJSON(t, router, "/security/policies/1", map[string]any{"geoip_countries": `["海外"]`})
	if rec.Code != http.StatusOK {
		t.Fatalf("off-state entry edit without xdb must pass, got %d %s", rec.Code, rec.Body.String())
	}
}

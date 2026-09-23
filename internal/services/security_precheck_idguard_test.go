package services

// U1-3（第 45 轮审计）：GeoIP 预检链 id 上界守卫。policyID 过大使
// 800000+policyID 落入 CRS 保留段（900000+）时必须跳过该策略链并告警——
// 危害是事件归因/分桶错位（securityEventsPolicyContainsRule 的 800xxx case
// 与 stage-stats 分桶都不再命中），而非编译失败（预检是独立 coraza 配置，
// 段内 id 彼此唯一，无同 id 冲突）。测试仍以引擎编译作回归面（R-10）。

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestEngineGate_precheckGeoipPolicyIDGuard(t *testing.T) {
	// 越界形状：ID=100000 → 预检 id=900000 撞 CRS 保留段，必须整链跳过。
	pBig := &models.SecurityPolicy{ID: 100000, Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["CN"]`)}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{pBig}, 0))
	if strings.Contains(directives, "id:900000") {
		t.Fatalf("policy id 100000 must skip its precheck geoip chain (900000 collides CRS reserved space), got:\n%s", directives)
	}
	compileForEngineGate(t, directives)
	// 回归形状：常规 ID=42 照常发射 id:800042（与 precheckGeoipChainShapes 同口径）。
	pOK := &models.SecurityPolicy{ID: 42, Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["CN"]`)}
	dOK := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{pOK}, 0))
	if !strings.Contains(dOK, "id:800042,") {
		t.Fatalf("policy id 42 must still emit id:800042 chain, got:\n%s", dOK)
	}
	compileForEngineGate(t, dOK)
}

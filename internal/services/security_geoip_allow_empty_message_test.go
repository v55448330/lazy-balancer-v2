package services

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// allow + 空名单的 400 文案必须与实际渲染语义一致：PolicyHasGeoIP 要求名单
// 非空，空名单不发射 GeoIP 链 = 全部放行。提示写成「拒绝所有请求」会把管理员
// 引向相反的安全结论（以为留空是收紧、实际是放开）。
func TestValidateGeoIPCountries_allowEmptyMessageMatchesRenderSemantics(t *testing.T) {
	err := ValidateGeoIPCountries("[]", "allow")
	if err == nil {
		t.Fatalf("allow + 空名单必须 400，否则保存后地域控制静默全放行")
	}
	msg := err.Error()
	if strings.Contains(msg, "拒绝所有请求") {
		t.Fatalf("文案与实际渲染相反（空名单=全部放行）: %q", msg)
	}
	if !strings.Contains(msg, "放行全部") && !strings.Contains(msg, "全部放行") {
		t.Fatalf("文案必须说明空名单会放行全部请求: %q", msg)
	}
}

// 回归形状：deny 空名单保持历史「未配置」兼容语义（不发射、不拦截），
// 文案修订不得把该校验门扩大成 400。
func TestValidateGeoIPCountries_denyEmptyStillAccepted(t *testing.T) {
	if err := ValidateGeoIPCountries("[]", "deny"); err != nil {
		t.Fatalf("deny 空名单是历史「未配置」语义，必须继续通过: %v", err)
	}
	if err := ValidateGeoIPCountries(`["海外"]`, "off"); err != nil {
		t.Fatalf("区域控制关闭时名单仅保留数据，必须继续通过: %v", err)
	}
}

func TestBuildIPPrecheckDirectives_allowEmptyFailsVisible(t *testing.T) {
	policies := []*models.SecurityPolicy{{ID: 1, Name: "脏策略", GeoIPMode: "allow", GeoIPCountries: json.RawMessage("[]")}}
	if _, err := buildIPPrecheckDirectives(policies, 403, "lb_geoip_empty"); err == nil || !strings.Contains(err.Error(), "放行全部") {
		t.Fatalf("allow+空名单必须拒绝渲染并说明 fail-open 语义，err=%v", err)
	}
}

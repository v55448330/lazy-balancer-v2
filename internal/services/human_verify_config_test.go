package services

import (
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 人机验证 handler 配置键集（2026-11-12 用户裁定）：
//   - 无 exempt_ips：IP 级放行唯一入口=阶段 0 信任名单（命中跳过整条安全链），
//     不留"只跳挑战"的第二套放行口径；
//   - 无 challenge_html：自定义挑战页退役（拦截页已覆盖页面定制场景），挑战页
//     恒由 lb_human 插件内置渲染。
func TestBuildHumanHandlerConfig_hasNoRetiredKeys(t *testing.T) {
	setupGeoipConfigTestDB(t)
	// cookie 签名密钥来自 global_config.human_secret；DB 初始化后惰性生成即可，
	// 清缓存避免跨用例串值。
	humanSecretMu.Lock()
	humanSecretCache = ""
	humanSecretMu.Unlock()
	p := &models.SecurityPolicy{
		ID: 1, Name: "人机", Mode: "off",
		HumanVerifyMode: "auto", HumanVerifyType: "slider", HumanVerifyTTL: 30,
		HumanExemptPaths: []byte(`["/health/"]`),
	}
	cfg := buildHumanHandler("lb-test", []*models.SecurityPolicy{p})
	if cfg == nil {
		t.Fatal("启用人机验证的规则必须渲染 lb_human handler")
	}
	for _, dead := range []string{"exempt_ips", "challenge_html"} {
		if _, ok := cfg[dead]; ok {
			t.Fatalf("handler 配置不得再含退役键 %q：%v", dead, cfg)
		}
	}
	if cfg["handler"] != "lb_human" {
		t.Fatalf("handler=%v，want lb_human", cfg["handler"])
	}
	paths, _ := cfg["exempt_paths"].([]string)
	if len(paths) != 1 || paths[0] != "/health/" {
		t.Fatalf("exempt_paths=%v，want [/health/]", cfg["exempt_paths"])
	}
	if cfg["mode"] != "auto" || cfg["type"] != "slider" {
		t.Fatalf("mode/type=%v/%v，want auto/slider", cfg["mode"], cfg["type"])
	}
}

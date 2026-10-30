package caddyl4sec

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
	// 被测配置引用的 caddy-l4 既有模块（close/proxy）——集成测试二进制需
	// 显式导入以进入模块注册表（生产镜像由 xcaddy --with 编入）。
	_ "github.com/mholt/caddy-l4/modules/l4close"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
)

// l4ValidateConfigRaw 构造含本模块的 layer4 配置 JSON（契约 C2 路由形状）；
// mutate 在序列化前改写路由数组（负向对照用，避免对 marshal 后字节做
// 顺序敏感的字符串替换）。
func l4ValidateConfigRaw(xdb string, mutate func(routes []any)) string {
	geoipRoute := map[string]any{
		"match": []any{
			map[string]any{
				"lb_geoip": map[string]any{
					"countries": []string{"江苏省", "United States", "海外"},
					"xdb_path":  xdb,
				},
			},
		},
		"handle": []any{
			map[string]any{"handler": "lb_l4_sec", "rule_caddy_id": "r-int", "reason": "geoip", "policy_id": 7},
			map[string]any{"handler": "close"},
		},
	}
	fallbackRoute := map[string]any{
		"handle": []any{
			map[string]any{"handler": "lb_l4_sec", "rule_caddy_id": "r-int", "mode": "allow_sample"},
			map[string]any{"handler": "proxy", "upstreams": []any{map[string]any{"dial": []string{"127.0.0.1:59996"}}}},
		},
	}
	routes := []any{geoipRoute, fallbackRoute}
	if mutate != nil {
		mutate(routes)
	}
	raw, err := json.Marshal(map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{
			"layer4": map[string]any{
				"servers": map[string]any{
					"lb4-int": map[string]any{
						"listen": []string{"127.0.0.1:59997"},
						"routes": routes,
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func l4ValidateConfig(xdb string) string {
	return l4ValidateConfigRaw(xdb, nil)
}

// TestL4ConfigValidateLoadsModules 模块可被 Caddy 配置加载（Provision+Validate
// 形状）：lb_geoip/lb_l4_sec/close/proxy 组合整份配置校验通过。
func TestL4ConfigValidateLoadsModules(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available")
	}
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "") // 校验不投递：IPC 关闭形态
	resetConnStatsForTest()

	var cfg caddy.Config
	if err := json.Unmarshal([]byte(l4ValidateConfig(xdb)), &cfg); err != nil {
		t.Fatalf("config unmarshal: %v", err)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("Validate() = %v（模块未被 Caddy 配置接受）", err)
	}
}

// TestL4ConfigValidateRejectsUnknownHandler 负向对照：未知 handler 名必须被
// 拒绝——证明上面的绿是真消费了模块注册表，而非静默丢弃未知段。
func TestL4ConfigValidateRejectsUnknownHandler(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available")
	}
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	raw := l4ValidateConfigRaw(xdb, func(routes []any) {
		geoipRoute := routes[0].(map[string]any)
		geoipRoute["handle"].([]any)[0].(map[string]any)["handler"] = "lb_l4_nope"
	})
	if raw == l4ValidateConfig(xdb) {
		t.Fatal("setup: negative control did not mutate config")
	}
	var cfg caddy.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("config unmarshal: %v", err)
	}
	if err := caddy.Validate(&cfg); err == nil {
		t.Fatal("Validate() = nil, want error for unknown handler（负向对照失败）")
	}
}

// TestL4ConfigValidateRejectsMalformedHandlerConfig 畸形 handler config 在
// Caddy 加载期显性报错（reason/allow_sample 互斥贯穿到配置装载）。
func TestL4ConfigValidateRejectsMalformedHandlerConfig(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available")
	}
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	raw := l4ValidateConfigRaw(xdb, func(routes []any) {
		geoipRoute := routes[0].(map[string]any)
		geoipRoute["handle"].([]any)[0].(map[string]any)["mode"] = "allow_sample"
	})
	if raw == l4ValidateConfig(xdb) {
		t.Fatal("setup: malformed control did not mutate config")
	}
	var cfg caddy.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("config unmarshal: %v", err)
	}
	if err := caddy.Validate(&cfg); err == nil {
		t.Fatal("Validate() = nil, want error for malformed lb_l4_sec config")
	}
}

// TestModuleIDsInCaddyRegistry 三模块 ID 全部在 Caddy 注册表（含 admin.api）。
func TestModuleIDsInCaddyRegistry(t *testing.T) {
	for _, id := range []string{
		"layer4.handlers.lb_l4_sec",
		"layer4.matchers.lb_geoip",
		"admin.api.lb_l4_conn_stats",
	} {
		if _, err := caddy.GetModule(id); err != nil {
			t.Errorf("module %q not registered: %v", id, err)
		}
	}
}

// TestSpoolDirContractName spool 目录契约名（任务契约：/app/data/security-events-spool-l4）。
func TestSpoolDirContractName(t *testing.T) {
	if l4DefaultSpoolDirPath != "/app/data/security-events-spool-l4" {
		t.Fatalf("l4DefaultSpoolDirPath = %q, want /app/data/security-events-spool-l4", l4DefaultSpoolDirPath)
	}
	if l4SpoolDir == "" {
		t.Fatal("l4SpoolDir must default to the contract path")
	}
	if l4SpoolDir != l4DefaultSpoolDirPath {
		t.Fatalf("l4SpoolDir initial value = %q, want l4DefaultSpoolDirPath（单源）", l4SpoolDir)
	}
}

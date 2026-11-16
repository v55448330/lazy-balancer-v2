package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 人机验证 handler 配置键集（2026-11-12 用户裁定）：
//   - 无 exempt_ips：IP 级放行唯一入口=阶段 0 信任名单（命中跳过整条安全链），
//     不留"只跳挑战"的第二套放行口径；
//   - 无 challenge_html：自定义挑战页退役（拦截页已覆盖页面定制场景），挑战页
//     恒由 lb_human 插件内置渲染；
//   - 无 session_ban_file：NAT 会话精修退役（封禁最终都以封禁 IP 为主），
//     会话封禁交换文件通道整体移除。
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
	for _, dead := range []string{"exempt_ips", "challenge_html", "session_ban_file"} {
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

// Given 无任何启用 CC 检测的策略（纯回退形态）。
// When loadCCConfig 求 CC 检测配置。
// Then 回退值必须等于 db.Default* 治理常量，且源码形态必须把这些字段绑成
// db 包选择器表达式——私抄字面量（40/10/70/5）会在 DDL/启动回填默认值调整后
// 静默分叉（本文件原实现即手抄，无任何对账钉）。
func TestLoadCCConfig_defaultsBindGovernedConstants(t *testing.T) {
	cfg := loadCCConfig(nil)
	if cfg.RPSLimit != db.DefaultCCRPSLimit || cfg.WindowSec != db.DefaultCCRPSWindow ||
		cfg.Ratio4xx != db.DefaultCC4xxRatio || cfg.SessionUAThresh != db.DefaultCCSessionUAThreshold {
		t.Fatalf("CC 回退配置=%+v, want db.Default*=%d/%d/%d/%d", cfg,
			db.DefaultCCRPSLimit, db.DefaultCCRPSWindow, db.DefaultCC4xxRatio, db.DefaultCCSessionUAThreshold)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "human_verify.go", nil, 0)
	if err != nil {
		t.Fatalf("parse human_verify.go: %v", err)
	}
	bindings := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "loadCCConfig" {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			kv, ok := inner.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				return true
			}
			if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "db" {
					bindings[key.Name] = sel.Sel.Name
				}
			}
			return true
		})
		return false
	})
	want := map[string]string{
		"RPSLimit":        "DefaultCCRPSLimit",
		"WindowSec":       "DefaultCCRPSWindow",
		"Ratio4xx":        "DefaultCC4xxRatio",
		"SessionUAThresh": "DefaultCCSessionUAThreshold",
	}
	for field, constant := range want {
		if bindings[field] != constant {
			t.Fatalf("loadCCConfig.%s 必须绑定 db.%s（选择器表达式），实际=%q（字面量即私抄）",
				field, constant, bindings[field])
		}
	}
}

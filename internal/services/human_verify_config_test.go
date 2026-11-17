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

// Given 策略启用人机验证但方式/有效期为空/零值（带外直写或旧备份形态）。
// When humanPolicyMerged 合并策略配置。
// Then 缺省回退必须绑定 db.DefaultHumanVerify* 治理常量（与 DDL DEFAULT/
// 启动回填单源）——私抄字面量会在治理常量调整后与创建侧静默分叉；源码形态
// 与 loadCCConfig 同款 AST 钉（选择器表达式，注释提及不算）。
func TestHumanPolicyMerged_defaultsBindGovernedConstants(t *testing.T) {
	p := &models.SecurityPolicy{HumanVerifyMode: "force"}
	_, typ, ttl, _ := humanPolicyMerged([]*models.SecurityPolicy{p})
	if typ != db.DefaultHumanVerifyType || ttl != db.DefaultHumanVerifyTTL {
		t.Fatalf("缺省回退=%s/%d, want db.Default*=%s/%d", typ, ttl,
			db.DefaultHumanVerifyType, db.DefaultHumanVerifyTTL)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "human_verify.go", nil, 0)
	if err != nil {
		t.Fatalf("parse human_verify.go: %v", err)
	}
	bindings := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "humanPolicyMerged" {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			assign, ok := inner.(*ast.AssignStmt)
			if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}
			lhs, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			if sel, ok := assign.Rhs[0].(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "db" {
					bindings[lhs.Name] = sel.Sel.Name
				}
			}
			return true
		})
		return false
	})
	want := map[string]string{
		"typ": "DefaultHumanVerifyType",
		"ttl": "DefaultHumanVerifyTTL",
	}
	for name, constant := range want {
		if bindings[name] != constant {
			t.Fatalf("humanPolicyMerged 的 %s 缺省回退必须绑定 db.%s（选择器表达式），实际=%q（字面量即私抄）",
				name, constant, bindings[name])
		}
	}
}

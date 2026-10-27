package services

// caddygeoip 是独立 module（xcaddy 构建期编译），主模块无法 import 它的常量。
// 两处跨模块约定因此只能靠「两份字面量」维持，而两侧测试各自钉自己的字面量：
//   - 默认库路径：渲染侧仅在派生值 ≠ 默认时发射键，插件按自身 Provision 兜底
//     读库。只改一侧时容器默认部署会「渲染省略键 + 插件读另一路径」→ GeoIP 与
//     爬虫段静默失效（GeoIP 全量判「海外」，deny 海外策略全误拦）。
//   - 控制头清单：客户端伪造的同名头必须由反向代理无条件剥离；新增控制头只加
//     插件、忘了加删除清单即让头直通上游。
//
// 本文件用源码 AST/文本对账把两侧钉在一起（与 cmd/server 的 pause 三方路径
// 对账同手法：插件侧读源码取字面量，不新增生产机制）。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

func pluginSourcePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "caddygeoip", name)
}

// pluginStringDecl 取 caddygeoip 源码里 CONST/VAR 声明的字符串字面量值。
func pluginStringDecl(t *testing.T, file, name string) string {
	t.Helper()
	path := pluginSourcePath(t, file)
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	found := ""
	value := ""
	ast.Inspect(parsed, func(node ast.Node) bool {
		decl, ok := node.(*ast.GenDecl)
		if !ok || (decl.Tok != token.CONST && decl.Tok != token.VAR) {
			return true
		}
		for _, spec := range decl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, ident := range valueSpec.Names {
				if ident.Name != name || index >= len(valueSpec.Values) {
					continue
				}
				literal, ok := valueSpec.Values[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("unquote %s.%s: %v", file, name, err)
				}
				found, value = "yes", unquoted
			}
		}
		return true
	})
	if found == "" {
		t.Fatalf("%s 未找到字符串声明 %s（契约对账失效）", file, name)
	}
	return value
}

// pluginStringSliceDecl 取 `var name = []string{...}` 的字面量元素。
func pluginStringSliceDecl(t *testing.T, file, name string) []string {
	t.Helper()
	path := pluginSourcePath(t, file)
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		decl, ok := node.(*ast.GenDecl)
		if !ok || decl.Tok != token.VAR {
			return true
		}
		for _, spec := range decl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok || len(valueSpec.Names) != 1 || valueSpec.Names[0].Name != name || len(valueSpec.Values) != 1 {
				continue
			}
			literal, ok := valueSpec.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			out = out[:0]
			for _, element := range literal.Elts {
				basic, ok := element.(*ast.BasicLit)
				if !ok || basic.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(basic.Value)
				if err != nil {
					t.Fatalf("unquote %s.%s element: %v", file, name, err)
				}
				out = append(out, unquoted)
			}
		}
		return true
	})
	if len(out) == 0 {
		t.Fatalf("%s 未找到字符串切片声明 %s（契约对账失效）", file, name)
	}
	return out
}

// renderedUpstreamDeleteHeaders 渲染一条 http 规则并取反向代理的
// headers.request.delete 清单（控制头剥离面的唯一生产形态）。
func renderedUpstreamDeleteHeaders(t *testing.T) map[string]bool {
	t.Helper()
	upstreams := []UpstreamConfig{{Host: "127.0.0.1", Port: 8080, Weight: 1, Enabled: true}}
	rule := SingleRuleConfig{
		HealthCheckInterval: 10, HealthCheckTimeout: 2,
		HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2,
		GlobalRequestBodyMaxSizeMB: 128, CaddyID: "lb_plugin_contract", Protocol: "http", ListenPort: 80,
	}
	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	last, ok := chain[len(chain)-1].(map[string]interface{})
	if !ok || last["handler"] != "reverse_proxy" {
		t.Fatalf("last handler must be reverse_proxy, got %#v", chain[len(chain)-1])
	}
	headers, ok := last["headers"].(map[string]interface{})
	if !ok {
		t.Fatalf("reverse_proxy headers=%#v", last["headers"])
	}
	request, ok := headers["request"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers.request=%#v", headers["request"])
	}
	del, ok := request["delete"].([]string)
	if !ok || len(del) == 0 {
		t.Fatalf("headers.request.delete must be a non-empty []string, got %#v", request["delete"])
	}
	have := make(map[string]bool, len(del))
	for _, h := range del {
		have[h] = true
	}
	return have
}

// TestGeoIPPluginPathDefaults_matchRenderDefaults：默认库路径两侧必须同值
// （渲染侧省略键的前提是插件自己的兜底默认与派生基准完全一致）。
func TestGeoIPPluginPathDefaults_matchRenderDefaults(t *testing.T) {
	// 插件 Provision 的 xdb 兜底：`h.XdbPath = "<默认>"`。
	handlerPath := pluginSourcePath(t, "handler.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), handlerPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", handlerPath, err)
	}
	pluginXdbPath := ""
	ast.Inspect(parsed, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		selector, ok := assign.Lhs[0].(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "XdbPath" {
			return true
		}
		literal, ok := assign.Rhs[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		unquoted, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatalf("unquote XdbPath default: %v", err)
		}
		pluginXdbPath = unquoted
		return true
	})
	if pluginXdbPath == "" {
		t.Fatal("未找到 caddygeoip Provision 的 XdbPath 兜底默认")
	}

	if pluginXdbPath != defaultIP2RegionLivePath {
		t.Fatalf("插件 xdb 兜底默认=%q 与渲染侧默认=%q 不一致：容器默认部署会「渲染省略键 + 插件读另一路径」，GeoIP 静默失效",
			pluginXdbPath, defaultIP2RegionLivePath)
	}

	pluginCrawlerPath := pluginStringDecl(t, "crawler_verify.go", "defaultCrawlerIPListFile")
	if pluginCrawlerPath != defaultCrawlerIPListFile {
		t.Fatalf("插件爬虫快照默认=%q 与渲染侧默认=%q 不一致：爬虫 IP 段豁免静默失效",
			pluginCrawlerPath, defaultCrawlerIPListFile)
	}
}

// TestGeoIPPluginControlHeaders_areStrippedFromUpstream：插件声明/注入的
// 每个进程内控制头都必须出现在反向代理的无条件删除清单里。
func TestGeoIPPluginControlHeaders_areStrippedFromUpstream(t *testing.T) {
	have := renderedUpstreamDeleteHeaders(t)

	expected := pluginStringSliceDecl(t, "handler.go", "geoipCorazaHeaders")
	expected = append(expected,
		pluginStringDecl(t, "handler.go", "crawlerVerifiedHeader"),
		pluginStringDecl(t, "handler.go", "crawlerSpoofHeader"),
		pluginStringDecl(t, "security_timing.go", "securityTimingHeader"),
		pluginStringDecl(t, "security_timing.go", "securityTimingStartHeader"),
	)
	for _, header := range expected {
		if !have[header] {
			t.Errorf("插件控制头 %s 不在反向代理 delete 清单中——客户端伪造的同名头会直达上游", header)
		}
	}
	// 反向控制：删除清单里的 X-LB-* 头必须都能在插件侧找到来源，否则说明
	// 清单行与插件脱钩（拼写漂移会让真实头既不剥离也不报错）。
	// 例外：X-LB-Rule-ID 由渲染层自己的链首 headers handler 注入（主模块），
	// 来源不在插件，故不参与「插件亦有同源声明」的反向断言。
	renderOwnedHeaders := map[string]bool{"X-LB-Rule-ID": true}
	declared := make(map[string]bool, len(expected))
	for _, header := range expected {
		declared[header] = true
	}
	for header := range have {
		if len(header) > 5 && header[:5] == "X-LB-" && !declared[header] && !renderOwnedHeaders[header] {
			t.Errorf("反向代理 delete 清单里的 %s 在 caddygeoip 中找不到同源声明（拼写漂移或已退役未清理）", header)
		}
	}
}

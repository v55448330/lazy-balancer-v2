package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// 消息键必须是语义键。用户 2026-11-25 裁定：后端只返回稳定键 + 参数、展示文案归
// 前端；键采用语义键，不保留旧键兼容期。此前的键是中文原文的哈希（k_ + 8 位十六
// 进制）——改一个字键就变，无法当契约使用。
//
// 形状：目标（全部键符合 `域名.驼峰名`）、回归（键唯一、域名小写）、畸形（哈希键、
// 连字符、下划线、双点、大写开头的域名都被拒）。

// hashKeyPattern 旧键形态：中文原文的哈希。
var hashKeyPattern = regexp.MustCompile(`\bk_[0-9a-f]{8}\b`)

// registeredCatalogKeys 解析目录文件里 Register(key, zh) 的第一个参数字面量。
func registeredCatalogKeys(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("catalog_*.go")
	if err != nil || len(paths) == 0 {
		t.Fatalf("目录文件缺失: %v %v", paths, err)
	}
	fset := token.NewFileSet()
	var keys []string
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || fn.Name != "Register" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			key, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("%s: 键字面量解析失败: %v", path, err)
			}
			keys = append(keys, key)
			return true
		})
	}
	if len(keys) < 100 {
		t.Fatalf("扫描面异常：只读到 %d 个键，守卫会假绿", len(keys))
	}
	return keys
}

func TestCatalogKeys_areSemantic(t *testing.T) {
	seen := map[string]bool{}
	for _, key := range registeredCatalogKeys(t) {
		if hashKeyPattern.MatchString(key) {
			t.Errorf("仍是哈希键 %q（中文原文的哈希，改文案即变）——改成 `域名.驼峰名` 的语义键", key)
			continue
		}
		if !messageKeyPattern.MatchString(key) {
			t.Errorf("键 %q 不是语义键形态 `域名.驼峰名`（域名小写，驼峰名以小写字母开头，中间一个点）", key)
		}
		if seen[key] {
			t.Errorf("键 %q 重复登记", key)
		}
		seen[key] = true
	}
}

func TestSemanticKeyPattern_rejectsMalformed(t *testing.T) {
	for _, good := range []string{"rule.versionConflict", "backup.importV1RulesConverted", "common.databaseError", "cert.caProviderDisabled"} {
		if !messageKeyPattern.MatchString(good) {
			t.Errorf("合规键 %q 被拒", good)
		}
	}
	for _, bad := range []string{"k_de8cc6aa", "rule", ".versionConflict", "rule.", "Rule.versionConflict", "rule.VersionConflict", "rule.version_conflict", "rule.version-conflict", "rule.a.b", "rule.versionConflict ", "1rule.x", "rule.x"} {
		if messageKeyPattern.MatchString(bad) {
			t.Errorf("畸形键 %q 被放行", bad)
		}
	}
	// 目录文件自身不得再出现哈希键（改名后遗留的注释、测试键都算）。
	for _, path := range []string{"catalog_gen.go", "catalog_manual.go"} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if hashKeyPattern.Match(src) {
			t.Errorf("%s 仍含哈希键", path)
		}
	}
}

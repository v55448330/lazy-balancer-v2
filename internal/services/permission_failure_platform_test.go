package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestPermissionFailureTests_guardRootBeforeChmod(t *testing.T) {
	targets := map[string][]string{
		"crawlerbot_update_test.go": {
			"TestCrawlerUpdate_partialCommitFailureMessage",
			"TestPrimeCrawlerIPLists_partialFailureKeepsSnapshotAndHeals",
		},
		"crs_rule_index_test.go": {"TestBuildCRSRuleIndex_logsReadFailure"},
		"crsinstall_test.go": {
			"TestCopyDir_copiesProbeLastSoPartialTreeFailsGate",
			"TestMoveTree_copyFallbackLeavesNoPartialTreeOnFailure",
		},
	}
	for path, names := range targets {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, name := range names {
			var fn *ast.FuncDecl
			for _, decl := range parsed.Decls {
				if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == name {
					fn = candidate
					break
				}
			}
			if fn == nil {
				t.Errorf("%s: missing %s", path, name)
				continue
			}
			var rootPos, chmodPos token.Pos
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "os" {
					return true
				}
				switch sel.Sel.Name {
				case "Geteuid":
					if rootPos == token.NoPos {
						rootPos = call.Pos()
					}
				case "Chmod":
					if chmodPos == token.NoPos {
						chmodPos = call.Pos()
					}
				}
				return true
			})
			if chmodPos == token.NoPos || rootPos == token.NoPos || rootPos > chmodPos {
				t.Errorf("%s: %s must skip root before relying on permission-bit failure", path, name)
			}
		}
	}
}

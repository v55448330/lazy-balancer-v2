package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

func serviceFunctionFromFile(t *testing.T, path, name string) *ast.FuncDecl {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	fn := serviceFunctionFromAST(parsed, name)
	if fn == nil {
		t.Fatalf("function %s not found in %s", name, path)
	}
	return fn
}

func serviceFunctionFromSource(t *testing.T, source, name string) *ast.FuncDecl {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	fn := serviceFunctionFromAST(parsed, name)
	if fn == nil {
		t.Fatalf("function %s not found in fixture", name)
	}
	return fn
}

func serviceFunctionFromAST(parsed *ast.File, name string) *ast.FuncDecl {
	for _, decl := range parsed.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func crsStockSetupWriteOrder(fn *ast.FuncDecl) []string {
	var order []string
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		fnName, ok := call.Fun.(*ast.Ident)
		if !ok || fnName.Name != "copyFile" {
			return true
		}
		first, firstOK := call.Args[0].(*ast.Ident)
		destination, destinationOK := call.Args[1].(*ast.Ident)
		if firstOK && destinationOK && first.Name == "newSetup" && (destination.Name == "stockPath" || destination.Name == "setupPath") {
			order = append(order, destination.Name)
		}
		return true
	})
	return order
}

func crsRunningAuditDeferOrder(fn *ast.FuncDecl) []string {
	var order []string
	for _, statement := range fn.Body.List {
		deferStatement, ok := statement.(*ast.DeferStmt)
		if !ok {
			continue
		}
		kind := ""
		ast.Inspect(deferStatement.Call.Fun, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if selector, ok := lhs.(*ast.SelectorExpr); ok && selector.Sel.Name == "running" {
						kind = "running-reset"
					}
				}
			case *ast.CallExpr:
				if fn, ok := node.Fun.(*ast.Ident); ok && fn.Name == "RecordAuditLog" {
					kind = "audit"
				}
			}
			return true
		})
		if kind != "" {
			order = append(order, kind)
		}
	}
	return order
}

func TestCRSSourceOrderHelpers_rejectMutationsAndIgnoreComments(t *testing.T) {
	writeCases := []struct {
		name   string
		source string
		want   []string
	}{
		{name: "correct", source: `package p; func swap(){ copyFile(newSetup, stockPath); copyFile(newSetup, setupPath) }`, want: []string{"stockPath", "setupPath"}},
		{name: "swapped", source: `package p; func swap(){ copyFile(newSetup, setupPath); copyFile(newSetup, stockPath) }`, want: []string{"setupPath", "stockPath"}},
		{name: "comment text is not a call", source: `package p; func swap(){ /* copyFile(newSetup, stockPath) */; copyFile(newSetup, setupPath) }`, want: []string{"setupPath"}},
	}
	for _, tc := range writeCases {
		t.Run(tc.name, func(t *testing.T) {
			fn := serviceFunctionFromSource(t, tc.source, "swap")
			if got := crsStockSetupWriteOrder(fn); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("order=%v, want %v", got, tc.want)
			}
		})
	}

	deferCases := []struct {
		name   string
		source string
		want   []string
	}{
		{name: "correct", source: `package p; func run(){ defer func(){ m.running = false }(); defer func(){ RecordAuditLog() }() }`, want: []string{"running-reset", "audit"}},
		{name: "swapped", source: `package p; func run(){ defer func(){ RecordAuditLog() }(); defer func(){ m.running = false }() }`, want: []string{"audit", "running-reset"}},
		{name: "comment text is not a defer", source: `package p; func run(){ /* defer func(){ m.running = false }() */; defer func(){ RecordAuditLog() }() }`, want: []string{"audit"}},
	}
	for _, tc := range deferCases {
		t.Run(tc.name, func(t *testing.T) {
			fn := serviceFunctionFromSource(t, tc.source, "run")
			if got := crsRunningAuditDeferOrder(fn); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("order=%v, want %v", got, tc.want)
			}
		})
	}
}

package services

// cert_jobs 候选装载单源守卫：列序 + 行装配 + Leaf 预解析策略此前在四处
// （续期扫描的 selectStoredRuleCertificate、证书信息单规则端点、渲染补查
// acmeCertCandidatesForRule、handlers 批量端点）各写一份 SELECT+扫描循环，
// 三处已按不同口径分叉（谓词、错误语义、Leaf 预解析条件）。列序或预解析策略
// 在一侧漂移不会让任何单侧测试红——只会让同一行证书在不同入口给出不同结论。
//
// 机制：
//   - 候选列序（`julianday(COALESCE(updated_at, created_at))`）只允许出现在
//     CertificateCandidateColumnList 常量里：services 包出现 >1 次、handlers
//     包出现 >0 次即红灯；
//   - 四个装载落点必须经单源入口：services 侧走 loadCertificateCandidates，
//     handlers 批量端点走 services.NewCertificateCandidate（行装配与预解析同源）。
//
// 行为等价由既有门禁承担：handlers/certinfo_endpoint_parity_test.go（单/批量
// 同值）与 TestACMECertCandidatesForRule_preparses_leaf（保留 disabled 行的
// 预解析口径）。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const candidateColumnFingerprint = "julianday(COALESCE(updated_at, created_at))"

// candidateLoaderSources 是必须经单源入口装载候选的函数所在文件
// （selectStoredRuleCertificate 是 var + 函数字面量测试缝，其余是普通方法/函数）。
var candidateLoaderSources = map[string]string{
	"selectStoredRuleCertificate": "certificates.go",
	"getACMECertInfo":             "certinfo.go",
	"acmeCertCandidatesForRule":   "caddy.go",
}

// declarationText 返回文件中名为 name 的声明（FuncDecl 或带函数字面量的
// ValueSpec）的源码文本；定位用 AST 偏移，注释/字符串内容不受影响。
func declarationText(t *testing.T, path, name string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return string(data[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
		}
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, ident := range valueSpec.Names {
				if ident.Name == name {
					return string(data[fset.Position(valueSpec.Pos()).Offset:fset.Position(valueSpec.End()).Offset])
				}
			}
		}
	}
	t.Fatalf("%s 未找到声明 %s", path, name)
	return ""
}

func TestCertificateCandidateLoad_hasSingleSource(t *testing.T) {
	servicesFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob services sources: %v", err)
	}
	total := 0
	for _, path := range servicesFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		count := strings.Count(string(data), candidateColumnFingerprint)
		if count == 0 {
			continue
		}
		total += count
		if path != "certselector.go" {
			t.Errorf("%s 内联了候选列序（%d 处）：必须使用 CertificateCandidateColumnList", path, count)
		}
	}
	if total != 1 {
		t.Errorf("services 包内候选列序定义 %d 处, want 1（CertificateCandidateColumnList 单源）", total)
	}

	handlerFiles, err := filepath.Glob(filepath.Join("..", "handlers", "cert*.go"))
	if err != nil {
		t.Fatalf("glob handler cert files: %v", err)
	}
	for _, path := range handlerFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		if strings.Contains(string(data), candidateColumnFingerprint) {
			t.Errorf("%s 内联了候选列序：批量端点必须复用 services.CertificateCandidateColumnList", path)
		}
	}

	// 装载落点必须调用单源入口。
	for function, file := range candidateLoaderSources {
		if file == "" {
			continue
		}
		body := declarationText(t, file, function)
		if !strings.Contains(body, "loadCertificateCandidates(") {
			t.Errorf("%s 未调用 loadCertificateCandidates：候选装载在该落点被重新内联", function)
		}
	}
	handlerCertInfo, err := os.ReadFile(filepath.Join("..", "handlers", "certinfo.go"))
	if err != nil {
		t.Fatalf("read handlers/certinfo.go: %v", err)
	}
	if !strings.Contains(string(handlerCertInfo), "services.NewCertificateCandidate(") {
		t.Error("handlers/certinfo.go 批量端点未复用 services.NewCertificateCandidate：行装配/预解析策略在该落点分叉")
	}
}

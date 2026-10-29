package services

// 「零写判据」单源守卫与内容×权限矩阵：
//
// 证书对是否「已与期望一致（内容 + 0644/0600 权限）」同时决定
//   ①apply 写侧 writeCertPair 是否跳过写盘（免 tmp+fsync+rename 写放大）；
//   ②启动物化 materializeCertPair 的 changed（审计/任务日志只统计真正的恢复）；
//   ③事务式批量物化 MaterializeCertPairs 的差异集（只快照/回滚真正改过的对）。
// 三处曾是三份平行判据——任一处漏改（例如只比对内容不比对权限）就让「重复
// 物化修复权限」的既有契约在一条链路上静默失效，而另两条链路仍绿。
//
// 守卫机制（双向）：①写死权限字面量的比较只允许出现在单源谓词
// certPairMatchesSnapshot 体内（扫描 certstore.go 的每个 `Mode == 0644/0600`
// 命中位置必须落在该函数体内）；②三个决策点都必须**调用**该谓词——有人在
// 某条链路里重新内联判据即红灯。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const certPairZeroWritePredicate = "certPairMatchesSnapshot"

func TestCertPairZeroWriteCriterion_hasSingleSource(t *testing.T) {
	const sourceFile = "certstore.go"
	data, err := os.ReadFile(sourceFile)
	if err != nil {
		t.Fatalf("读取 %s: %v", sourceFile, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, sourceFile, data, 0)
	if err != nil {
		t.Fatalf("解析 %s: %v", sourceFile, err)
	}

	type span struct {
		name       string
		start, end int
	}
	var funcs []span
	declared := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Name.Name == certPairZeroWritePredicate {
			declared++
		}
		funcs = append(funcs, span{
			name:  fn.Name.Name,
			start: fset.Position(fn.Body.Pos()).Offset,
			end:   fset.Position(fn.Body.End()).Offset,
		})
	}
	if declared != 1 {
		t.Fatalf("%s 声明 %d 次，want 1（零写判据必须单源）", certPairZeroWritePredicate, declared)
	}
	enclosing := func(offset int) string {
		for _, fn := range funcs {
			if offset >= fn.start && offset < fn.end {
				return fn.name
			}
		}
		return ""
	}

	// ① 权限字面量比较只能出现在单源谓词体内。
	text := string(data)
	for _, marker := range []string{".Mode == 0644", ".Mode == 0600"} {
		for offset := 0; ; {
			index := strings.Index(text[offset:], marker)
			if index < 0 {
				break
			}
			absolute := offset + index
			if owner := enclosing(absolute); owner != certPairZeroWritePredicate {
				t.Errorf("零写判据的权限比较 %q 出现在 %s（不在 %s 内）：判据必须单源",
					marker, ownerOrFile(owner), certPairZeroWritePredicate)
			}
			offset = absolute + len(marker)
		}
	}

	// ② 三个决策点都必须调用单源谓词。
	calls := map[string]int{}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if ok && ident.Name == certPairZeroWritePredicate {
			calls[enclosing(fset.Position(call.Pos()).Offset)]++
		}
		return true
	})
	for _, consumer := range []string{"writeCertPairFiles", "MaterializeCertPairs"} {
		if calls[consumer] == 0 {
			t.Errorf("%s 未调用 %s：零写判据在该链路上被重新内联或遗漏", consumer, certPairZeroWritePredicate)
		}
	}
}

func ownerOrFile(owner string) string {
	if owner == "" {
		return "包级位置"
	}
	return owner
}

// 内容 × 权限 × 存在性矩阵：只有「内容一致且两侧权限正确」才允许零写；其余
// 形态（内容不符、权限被改错、文件缺失）必须落盘并修复到 0644/0600。
func TestMaterializeCertPair_zeroWriteMatrix(t *testing.T) {
	certPEM, keyPEM := matchingCertificatePair(t, "matrix.example.test")
	otherCertPEM, _ := matchingCertificatePair(t, "other.example.test")
	cases := []struct {
		name                    string
		certContent, keyContent string
		certMode, keyMode       os.FileMode
		certExists, keyExists   bool
		wantChanged             bool
	}{
		{"content_match_permissions_ok", certPEM, keyPEM, 0644, 0600, true, true, false},
		{"content_match_cert_permission_tightened", certPEM, keyPEM, 0600, 0600, true, true, true},
		{"content_match_key_permission_loosened", certPEM, keyPEM, 0644, 0644, true, true, true},
		{"content_match_both_permissions_wrong", certPEM, keyPEM, 0600, 0644, true, true, true},
		{"cert_content_mismatch", otherCertPEM, keyPEM, 0644, 0600, true, true, true},
		{"key_content_mismatch", certPEM, otherCertPEM, 0644, 0600, true, true, true},
		{"both_content_mismatch", otherCertPEM, otherCertPEM, 0644, 0600, true, true, true},
		{"both_content_mismatch_permissions_wrong", otherCertPEM, otherCertPEM, 0600, 0644, true, true, true},
		{"cert_file_missing", certPEM, keyPEM, 0644, 0600, false, true, true},
		{"key_file_missing", certPEM, keyPEM, 0644, 0600, true, false, true},
		{"both_files_missing", certPEM, keyPEM, 0644, 0600, false, false, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			useTemporaryCertDir(t)
			const ruleID = "lb_zero_write_matrix"
			certPath, keyPath := CertFilePaths(ruleID)
			if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
				t.Fatalf("创建证书目录: %v", err)
			}
			for _, seeded := range []struct {
				path, content string
				mode          os.FileMode
				exists        bool
			}{
				{certPath, testCase.certContent, testCase.certMode, testCase.certExists},
				{keyPath, testCase.keyContent, testCase.keyMode, testCase.keyExists},
			} {
				if !seeded.exists {
					continue
				}
				if err := os.WriteFile(seeded.path, []byte(seeded.content), seeded.mode); err != nil {
					t.Fatalf("seed %s: %v", seeded.path, err)
				}
				if err := os.Chmod(seeded.path, seeded.mode); err != nil {
					t.Fatalf("chmod %s: %v", seeded.path, err)
				}
			}
			if !testCase.wantChanged {
				// 零写 = 连临时文件都不创建：把 tmp 路径占成目录，任何写尝试都会
				// 失败（零写判据漏判时本用例因此报错而不是静默通过）。
				for _, blocked := range []string{certPath + ".tmp", keyPath + ".tmp"} {
					if err := os.Mkdir(blocked, 0700); err != nil {
						t.Fatalf("block temporary path %s: %v", blocked, err)
					}
				}
			}

			changed, err := materializeCertPair(ruleID, certPEM, keyPEM)
			if err != nil {
				t.Fatalf("materializeCertPair: %v", err)
			}
			if changed != testCase.wantChanged {
				t.Fatalf("changed=%v, want %v（零写判据与内容×权限期望不符）", changed, testCase.wantChanged)
			}
			for _, written := range []struct {
				path        string
				wantContent string
				wantMode    os.FileMode
			}{
				{certPath, certPEM, 0644},
				{keyPath, keyPEM, 0600},
			} {
				content, readErr := os.ReadFile(written.path)
				if readErr != nil {
					t.Fatalf("读取 %s: %v", written.path, readErr)
				}
				if string(content) != written.wantContent {
					t.Fatalf("%s 内容未被修复到期望证书", written.path)
				}
				info, statErr := os.Stat(written.path)
				if statErr != nil {
					t.Fatalf("stat %s: %v", written.path, statErr)
				}
				if info.Mode().Perm() != written.wantMode {
					t.Fatalf("%s 权限=%#o, want %#o（重复物化必须修复权限）", written.path, info.Mode().Perm(), written.wantMode)
				}
			}
		})
	}
}

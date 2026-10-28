package testsupport

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 包文档承诺 testsupport 只进测试二进制；用 AST 而非文本匹配，防止生产
// import 夹带测试辅助且 go vet/go build 仍然通过。
func TestProductionFiles_doNotImportTestSupport(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	const packagePath = "lazy-balancer-v2/internal/testsupport"
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "dist") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if importPath == packagePath {
				t.Errorf("production file %s imports test-only package %s", path, packagePath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan production imports: %v", err)
	}
}

package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 部署生命周期状态集必须由 jobLifecycleByStatus 单源派生：切片与 SQL IN 片段
// 是同一份真源的两个消费形态，新增/重命名状态时不得出现第二处字面量。
func TestDeploymentLifecycleStatusSetDerivedFromLifecycleMap(t *testing.T) {
	want := make([]string, 0, 3)
	for status, lifecycle := range jobLifecycleByStatus {
		if lifecycle == JobLifecycleDownloaded {
			want = append(want, status)
		}
	}
	sort.Strings(want)
	if len(want) == 0 {
		t.Fatal("jobLifecycleByStatus 未定义任何 downloaded 生命周期状态")
	}
	if strings.Join(deploymentLifecycleJobStatuses, ",") != strings.Join(want, ",") {
		t.Fatalf("deploymentLifecycleJobStatuses=%v, want %v（必须由 jobLifecycleByStatus 派生）",
			deploymentLifecycleJobStatuses, want)
	}
	for _, status := range want {
		if !strings.Contains(DeploymentLifecycleJobStatusSQL, "'"+status+"'") {
			t.Fatalf("SQL 片段缺状态 %q: %s", status, DeploymentLifecycleJobStatusSQL)
		}
	}
	if got := strings.Count(DeploymentLifecycleJobStatusSQL, "','") + 1; got != len(want) {
		t.Fatalf("SQL 片段状态数=%d, want %d（%s）", got, len(want), DeploymentLifecycleJobStatusSQL)
	}
}

// cleanup 子集与全集的差集只能是 downloaded：补扫 cleanup 分支不带窗口/沉降
// 判据，若把 downloaded 也算进去，downloaded 行会绕过窗口判据被无条件重排。
func TestDeploymentCleanupStatusSetExcludesDownloaded(t *testing.T) {
	want := make([]string, 0, len(deploymentLifecycleJobStatuses))
	for _, status := range deploymentLifecycleJobStatuses {
		if status != "downloaded" {
			want = append(want, status)
		}
	}
	if len(want) == 0 || len(want) == len(deploymentLifecycleJobStatuses) {
		t.Fatalf("cleanup 子集派生不成立：全集=%v 子集=%v", deploymentLifecycleJobStatuses, want)
	}
	if strings.Join(deploymentCleanupJobStatuses, ",") != strings.Join(want, ",") {
		t.Fatalf("deploymentCleanupJobStatuses=%v, want %v", deploymentCleanupJobStatuses, want)
	}
	joined := DeploymentCleanupJobStatusSQL
	if strings.Contains(joined, "'downloaded'") {
		t.Fatalf("cleanup SQL 片段不得含 downloaded: %s", joined)
	}
	for _, status := range want {
		if !strings.Contains(joined, "'"+status+"'") {
			t.Fatalf("cleanup SQL 片段缺状态 %q: %s", status, joined)
		}
	}
}

// deploymentLifecycleStatusNames 是部署生命周期状态集（派生点见 jobstate.go）。
var deploymentLifecycleStatusNames = map[string]bool{
	"downloaded":      true,
	"cleanup_dns":     true,
	"cleanup_warning": true,
}

// deploymentLifecycleLiteralScanExempt 是「可持有集合字面量」的路径豁免（附裁定）：
//   - internal/services/jobstate.go：派生点本体（唯一允许持有集合的地方）；
//   - internal/db/db.go：cert_jobs.status 规范枚举真源（certJobStatuses，db 不能
//     反向 import services，见该处注释）——它是枚举的声明点，不是部署生命周期
//     集合的第二份副本。
var deploymentLifecycleLiteralScanExempt = map[string]bool{
	"internal/services/jobstate.go": true,
	"internal/db/db.go":             true,
}

// 部署生命周期状态集的字面量只允许出现在派生点（及其上游枚举真源）。
// 消费点重新写字面量不会报错，只会在状态机扩展时静默漏收：启动/补扫装载的
// CAS 源态集、补扫查询与文案回写都按旧集合求值，任务失去周期通道。
//
// 扫描面=仓库根全量 Go 生产文件（旧实现只扫 services 根 + handlers/cert*.go，
// 其它包新增第二份集合静默通过），且 Go 字面量按 AST 按「语句」取集合——
// 旧实现逐行 strings.Contains，多行切片
// （`[]string{\n"downloaded",\n"cleanup_dns",\n}`）逐行计数 0/1 逃逸。
func TestDeploymentLifecycleStatusLiteralOnlyInDerivation(t *testing.T) {
	// 相邻两个生命周期状态被写成 SQL 字面量（'a','b'）即视为第二份集合；
	// 单状态比较（status='downloaded'）仍是合法用法，不在本守卫范围。
	literalSet := regexp.MustCompile(`'(downloaded|cleanup_dns|cleanup_warning)'\s*,\s*'(downloaded|cleanup_dns|cleanup_warning)'`)
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("扫描根必须为仓库根（含 go.mod）: %v", err)
	}
	skipDirs := map[string]bool{".git": true, "vendor": true, "node_modules": true, "web": true, ".codegraph": true}
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if skipDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	for _, path := range paths {
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			t.Fatalf("relativize %s: %v", path, relErr)
		}
		rel = filepath.ToSlash(rel)
		if deploymentLifecycleLiteralScanExempt[rel] {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if match := literalSet.FindString(string(data)); match != "" {
			t.Errorf("%s 重新写死了部署生命周期状态集字面量 %s，必须复用 DeploymentLifecycleJobStatusSQL/DeploymentCleanupJobStatusSQL", rel, match)
		}
		if violation, hit := deploymentLifecycleGoLiteralInFile(t, path); hit {
			t.Errorf("%s 重新写死了部署生命周期状态集（Go 字面量）: %s，必须复用 deploymentLifecycleJobStatuses/JobLifecycle", rel, violation)
		}
	}
}

// deploymentLifecycleGoLiteralInFile 用 AST 在单个文件的每条语句/包级声明里
// 收集部署生命周期字符串字面量：同一语句命中 ≥2 个不同状态即视为第二份集合
// （多行切片、跨行字符串拼接均有效；注释不参与）。返回首处违规描述。
func deploymentLifecycleGoLiteralInFile(t *testing.T, path string) (string, bool) {
	t.Helper()
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	reported := map[string]bool{}
	var violation string
	found := false
	check := func(node ast.Node) {
		if found {
			return
		}
		statuses := map[string]bool{}
		var positions []string
		ast.Inspect(node, func(inner ast.Node) bool {
			literal, ok := inner.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil || !deploymentLifecycleStatusNames[value] {
				return true
			}
			statuses[value] = true
			positions = append(positions, fileSet.Position(literal.Pos()).String())
			return true
		})
		if len(statuses) < 2 {
			return
		}
		sort.Strings(positions)
		key := strings.Join(positions, "|")
		if reported[key] {
			return
		}
		reported[key] = true
		found = true
		violation = strings.Join(positions, ", ")
	}
	// 只检查「直接持有字面量」的叶子节点：把 BlockStmt/IfStmt/ForStmt 之类
	// 含子语句的容器纳入会把「同一 if 内两条不同阶段的 log("cleanup_dns")/
	// log("downloaded")」误判成集合副本（internal/acme/issuer.go 即此形态）。
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch node.(type) {
		case *ast.AssignStmt, *ast.DeclStmt, *ast.ValueSpec, *ast.ReturnStmt,
			*ast.ExprStmt, *ast.GenDecl, *ast.CompositeLit, *ast.BinaryExpr, *ast.CaseClause:
			check(node)
		}
		return true
	})
	return violation, found
}

// 部署链回写源态集 = 部署生命周期 + downloading（唯一「证书字节已到手、
// downloaded 进度行未落库」的 active 形态）。终态（issued/failed/disabled）在
// 集合外——那是并发胜者已提交的状态，陈旧部署回调不得把成功结果拉回部署生命
// 周期；其余 active 签发态（creating_order/validating…）也在集合外——它们发生在
// 证书字节到手之前，到达部署失败回写的材料只能是陈旧回调的，写回 downloaded 会
// 越权改写正在进行的签发（doesNotDowngradeOutsideDeployableLifecycle 契约）；
// queued/waiting_ca 由队列/CA 退避链维护。
func TestDeploymentPersistenceStatusSetDerivedFromLifecycleMap(t *testing.T) {
	want := append([]string{}, deploymentLifecycleJobStatuses...)
	want = append(want, "downloading")
	sort.Strings(want)
	if strings.Join(deploymentPersistenceJobStatuses, ",") != strings.Join(want, ",") {
		t.Fatalf("deploymentPersistenceJobStatuses=%v, want %v（部署生命周期 + downloading）",
			deploymentPersistenceJobStatuses, want)
	}
	contains := func(status string) bool {
		for _, got := range deploymentPersistenceJobStatuses {
			if got == status {
				return true
			}
		}
		return false
	}
	for _, status := range []string{"downloaded", "cleanup_dns", "cleanup_warning", "downloading"} {
		if !contains(status) {
			t.Fatalf("集合缺 %q（部署链必须能从该状态收敛材料）: %v", status, deploymentPersistenceJobStatuses)
		}
	}
	for _, status := range []string{"issued", "failed", "disabled", "queued", "waiting_ca", "creating_order", "validating", "finalized"} {
		if contains(status) {
			t.Fatalf("集合不得含 %q（终态=并发胜者/在途签发=不得越权改写）: %v", status, deploymentPersistenceJobStatuses)
		}
	}
}

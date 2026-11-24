package handlers

// handlers 包的产品文件（非 *_test.go）不得承载 test-only **入口**。
//
// 这些函数只被测试消费（复位缓存/退避/采样状态），宿主本是同包测试文件：
// 留在产品文件里会让「生产调用面」判断失真——排障时会以为它是生产路径的一环，
// 改动也只覆盖被测的那条；同时它扩展了包的导出面语义（同包测试不需要）。
//
// 注入型 seam（`var xxxForTest func(...)` / `var xxxHook func(...)`）是唯一的
// 例外：生产代码要读它决定分支，只能留在产品文件。这类 seam 必须逐条登记
// （登记表=绊线），新增未登记即报错，删除后残留登记同样报错。
//
// 识别面=「名字以 ForTest 或 Hook 结尾的包级 var」+「名字以 ForTest/Hook 结尾
// 的函数」。只认 *ForTest 会漏掉 `enableCertJobResumePreUpdateHook` 一族
// （测试专用但无 ForTest 后缀），绊线对其完全失效。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// productionInjectionSeams 登记**必须**留在产品文件的注入型 seam（名字 → 生产
// 读取侧）。值只作说明，判据是键集与实测集合完全相等。
var productionInjectionSeams = map[string]string{
	"txCommitForTest":                           "submitTx 提交路径注入提交失败",
	"txRollbackForTest":                         "submitTx 回滚路径注入回滚失败",
	"ipListCommitTxForTest":                     "IP 名单提交路径注入提交失败",
	"mfaGenerateSecretForTest":                  "MFASetup 注入 TOTP 密钥生成失败",
	"pinLastGoodForTest":                        "规则生成注入「钉住 last-good」失败",
	"caddyMetricsSnapshotDoBeforeForTest":       "面板指标抓取在请求发出前注入观测/失败",
	"threatRuleNamePointQueriesForTest":         "威胁大屏按 id 点查计数（只增观测）",
	"toastSummaryBetweenMaxAndAggregateForTest": "toast 聚合区间注入并发切换",
	"securityOverviewMutatedRebuildHookForTest": "安全总览脏标志重建注入并发置位窗口（generation CAS 回归）",
	// *Hook 族（测试专用钩子，无 ForTest 后缀）：生产读取后按 nil 判定
	// 是否跳过，故只能留在产品文件——同样必须逐条登记。
	"updateUserPasswordRaceHook":           "自助改密乐观守卫竞态注入",
	"oidcJITInsertAttemptHook":             "OIDC JIT 开户唯一冲突重试注入",
	"autoBackupBeforeSectionsReadHook":     "自动备份读取备份范围窗口取消注入",
	"autoBackupBeforeDirCreateHook":        "自动备份目录创建窗口取消注入",
	"brandingReloadAuditHook":              "品牌热重载留痕锁序观测",
	"logTailWindowStatHook":                "尾窗尺寸快照/Read 增长窗口观测",
	"deleteCertificateConfigPreDeleteHook": "证书配置删除前引用查询窗口注入",
	"issueCertificateBatchSnapshotHook":    "批量签发目标快照介入",
	"retryCertJobPreEnqueueHook":           "证书任务重试入队前状态窗口注入",
	"deleteCertJobPreDisableHook":          "删除证书任务禁用前窗口注入",
	"deleteCertJobPreRestoreHook":          "删除证书任务失败恢复前窗口注入",
	"deleteCertJobPreLockHook":             "删除证书任务取锁窗口注入",
	"configImportAfterSessionHook":         "配置导入会话结束后注入",
	"configImportBeginAttemptHook":         "配置导入尝试开始注入",
	"configImportBeforePrelockHook":        "配置导入预锁前注入",
	"importPostCommitCleanupHook":          "配置导入提交后清理注入",
	"enableCertJobResumePreUpdateHook":     "启用规则恢复证书任务 UPDATE 前窗口注入",
	"updateRuleLockWindowHook":             "更新规则放锁窗口注入",
	"disableRuleLockWindowHook":            "禁用规则放锁窗口注入",
	"createSecurityCustomRulePreLockHook":  "创建自定义规则取锁前注入",
}

// isTestOnlySeamName 报告包级 seam/入口名是否属于绊线识别面：*ForTest（历史
// 后缀）与 *Hook（规则/证书/备份族测试钩子，生产读取侧按 nil 判定是否跳过）。
func isTestOnlySeamName(name string) bool {
	return strings.HasSuffix(name, "ForTest") || strings.HasSuffix(name, "Hook")
}

// scanProductionTestOnlySymbols 扫描 dir 下产品文件（非 *_test.go）：返回违规
// 的 test-only 函数、发现的注入型 seam var 与已扫描文件数。
func scanProductionTestOnlySymbols(dir string) (forbiddenFuncs []string, foundSeams map[string]bool, scanned int, err error) {
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		return nil, nil, 0, readErr
	}
	fset := token.NewFileSet()
	foundSeams = make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, parseErr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if parseErr != nil {
			return nil, nil, scanned, parseErr
		}
		for _, decl := range file.Decls {
			switch node := decl.(type) {
			case *ast.FuncDecl:
				if isTestOnlySeamName(node.Name.Name) {
					forbiddenFuncs = append(forbiddenFuncs, fset.Position(node.Pos()).String()+" "+node.Name.Name)
				}
			case *ast.GenDecl:
				if node.Tok != token.VAR {
					continue
				}
				for _, spec := range node.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, ident := range value.Names {
						if isTestOnlySeamName(ident.Name) {
							foundSeams[ident.Name] = true
						}
					}
				}
			}
		}
	}
	return forbiddenFuncs, foundSeams, scanned, nil
}

func TestHandlersPackageHasNoProductionTestOnlyEntryPoints(t *testing.T) {
	forbiddenFuncs, foundSeams, scanned, err := scanProductionTestOnlySymbols(".")
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("没有扫描到任何产品文件——目录枚举失效，本守卫会静默恒绿")
	}
	for _, entry := range forbiddenFuncs {
		t.Errorf("%s：产品文件声明 test-only 函数——请移到 *_test.go（同包测试可访问未导出符号）", entry)
	}
	registered := make([]string, 0, len(productionInjectionSeams))
	for name := range productionInjectionSeams {
		registered = append(registered, name)
	}
	found := make([]string, 0, len(foundSeams))
	for name := range foundSeams {
		found = append(found, name)
	}
	slices.Sort(registered)
	slices.Sort(found)
	if !slices.Equal(registered, found) {
		t.Fatalf("注入型 seam 登记表与实测不一致：\n登记=%v\n实测=%v\n新增 seam 必须登记（并说明生产读取侧），删除 seam 必须同步删登记", registered, found)
	}
}

// 识别面自证：*Hook 注入 seam 与 *ForTest 同列绊线，函数形入口同样被拦。
// 夹具放临时目录（不污染真实产品文件），证明仅 *ForTest 的旧口径会漏掉的
// 形状现在会让登记表对账转红。
func TestProductionTestOnlySymbols_detectsHookForms(t *testing.T) {
	dir := t.TempDir()
	source := `package handlers

var unregisteredHook func()
var registeredForTest func()

func helperHook() {}
func helperForTest() {}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	forbidden, found, scanned, err := scanProductionTestOnlySymbols(dir)
	if err != nil {
		t.Fatal(err)
	}
	if scanned != 1 {
		t.Fatalf("scanned=%d, want 1（夹具只含一个产品文件）", scanned)
	}
	if !found["unregisteredHook"] {
		t.Fatalf("发现集合=%v, want 含 unregisteredHook（*Hook 注入 seam 必须被识别）", found)
	}
	if !found["registeredForTest"] {
		t.Fatalf("发现集合=%v, want 含 registeredForTest", found)
	}
	if len(forbidden) != 2 {
		t.Fatalf("禁止函数=%v, want 2 条（helperHook/helperForTest 均为 test-only 入口）", forbidden)
	}
}

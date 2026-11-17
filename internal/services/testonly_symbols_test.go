package services

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// testOnlyEntryList 是 test-only 符号的**全称登记名单**：产品文件里名字含
// ForTest 的声明（FuncDecl 含方法、包级 var/const）必须「入名单 + 带
// //testseam: 文档标记」双登记，缺一即违规——纯名单 opt-in 会让新增未登记
// ForTest 入口静默放行，打标不入名单则让可移动 helper 打标即留驻绕登记
// （与 handlers 姊妹守卫的全称禁令、wafiplist 同型守卫同口径）。
//
// 名单承载两类条目：
//   - 已迁 *_test.go 的入口绊线（无标记；搬回产品文件即报错）；
//   - 有意留驻产品文件的测试缝（跨包测试消费的导出入口、生产路径自增的
//     观测计数器/注入钩子等宿主不可迁移的形态）：入名单并就地加
//     //testseam: 标记。标记用在名字不含 ForTest 的声明上属误用，同样
//     报错（防标记腐化成任意豁免通道）。
//
// 形态覆盖 FuncDecl（含方法）与 var/const（ValueSpec）：var 形态的测试缝
// （计数器/钩子变量）此前完全无机械拦截。
var testOnlyEntryList = map[string]bool{
	"StopLogRotate":         true,
	"logCleanupSummaryLine": true,
	"taskLogsHousekeeping":  true,
	"parseRuleLabelMetrics": true,
	"storeRuleMetricsText":  true,
	"updateOverview":        true,
	// 已迁到 *_test.go 的入口登记为绊线：搬回产品文件（含方法形态，
	// FuncDecl 同时覆盖 Recv!=nil）即报错。
	"parsePrometheusMetrics":     true,
	"estimateLatencyPercentiles": true,
	"upsertCrawlerIPList":        true,
	"upsertCrawlerIPListChanged": true,
	// 自动封禁单事件喂入测试缝（生产摄取只走 autobanObserveBatch）：
	// 宿主已迁到 autoban_testonly_helpers_test.go。
	"autobanObserveEvent":       true,
	"autobanObserveEventScoped": true,
	// 累犯表的 test-only 导出入口（生产守卫/删除恒走
	// DeleteAutobanRecidivismGuarded 的事务视图）：宿主已迁
	// autoban_recidivism_test.go，搬回产品文件即报错。
	"AutobanIdentityActivelyBanned": true,
	"DeleteAutobanRecidivism":       true,
	// 安全事件 spool 测试缝（有意留驻产品文件：Reset 入口被 handlers 测试
	// 跨包消费、计数器由生产读取路径自增供测试观测——宿主不可能在 *_test.go）。
	"ResetSecurityEventsSpoolStateForTest":           true,
	"resetSecurityEventsSpoolEntryCountCacheForTest": true,
	"securityEventsSpoolEntryReadBytesForTest":       true,
	// crawler 快照交换文件测试缝（导出入口被 handlers 测试跨包消费，返回
	// 还原闭包；同带 //testseam: 标记）。
	"SetCrawlerIPListFileForTest": true,
	// 集群快照行隔离限频复位缝（同包测试消费）：宿主已迁 *_test.go，
	// 搬回产品文件即报错。
	"resetSnapshotRowIsolationThrottle": true,
	// 同步循环 Resume 观测计数缝（生产路径自增、handlers 测试跨包消费，
	// 宿主留驻产品文件；同带 //testseam: 标记）。
	"SyncResumeCallsForTest": true,
	// CRS 池指纹求值计数缝（生产渲染路径自增、同包测试读取；宿主留驻
	// 产品文件，同带 //testseam: 标记）。
	"crsPoolFingerprintEvalsForTest": true,
	// —— 存量留驻缝逐条定性登记（全称化收编：宿主不可迁移，均带 //testseam:）——
	// 跨包测试消费的导出入口（handlers/cmd 测试直接调用，宿主必须在产品文件）。
	"ResetCRSUpdateManagerForTest":            true,
	"AutobanSetSuggestionsForTest":            true,
	"AutobanSeedCounterForTest":               true,
	"SetCLIValidatorForTest":                  true,
	"ResetCAQueueManagerForTest":              true,
	"StartDispatchForTest":                    true,
	"MarkJobRunningForTest":                   true,
	"MarkRetiredJobRunningForTest":            true,
	"EnqueueForTest":                          true,
	"SetCertDirForTest":                       true,
	"ResetIP2RegionSearcherForTest":           true,
	"ResetIP2RegionUpdateManagerForTest":      true,
	"ResetIPListProjectionStateForTest":       true,
	"MFAResetVerifyAttemptsForTest":           true,
	"SetRuleLogDirForTest":                    true,
	"ResetLogStateTransitionForTest":          true,
	"SecurityEventsSetIngestionHealthForTest": true,
	"SetTaskEngineForTest":                    true,
	"CollectSystemTasksCallsForTest":          true,
	"ResetCollectSystemTasksCallsForTest":     true,
	"ResetThreatScreenAttackFlowForTest":      true,
	"ThreatScreenAttackFlowAppendForTest":     true,
	"ResetThreatUpdateManagerForTest":         true,
	"OverrideThreatWafDirForTest":             true,
	"OverrideWafLivePathsForTest":             true,
	"SetIP2RegionLiveProvincesForTest":        true,
	"SetSecurityLibsDirsForTest":              true,
	// 生产路径读写的注入钩子/观测计数器（自增/判 nil 点在生产热路径，
	// 宿主不可迁移；同包或跨包测试观测/注入）。
	"configDriftCheckForTest":                          true,
	"ruleLogOrphanPurgeBeforeRemoveForTest":            true,
	"securityEventsMappingLoadsForTest":                true,
	"threatTextScanRunsForTest":                        true,
	"threatScreenAttackFlowGenerationResetHookForTest": true,
	"threatRunPanicHookForTest":                        true,
	// 进程级单例/缓存/状态复位缝（同包测试消费；状态由生产路径持有，
	// 复位入口与状态同宿主，登记留驻防未评估回迁）。
	"resetPendingDeltaCorruptStreakForTest":   true,
	"resetClusterSectionHashCacheForTest":     true,
	"forgetIPListRenderRefForTest":            true,
	"resetSecurityEventsMappingsCacheForTest": true,
	"ResetRuntimeAdminTLSForTest":             true,
	"ClearThreatUpdateManagerForTest":         true,
}

// productTestOnlyViolations 扫描单个产品文件源码，返回违规描述（空切片=通过）。
// 判定：
//  1. 名字含 ForTest 的声明未入名单 → 违规（不论是否带标记——全称登记）；
//  2. 名单内名字以 FuncDecl 或包级 var/const 形态声明、文档无 //testseam: → 违规；
//  3. 声明文档带 //testseam: 但既不在名单、名字也不含 ForTest → 标记误用违规。
func productTestOnlyViolations(filename string, src []byte, list map[string]bool) []string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return []string{fmt.Sprintf("parse %s: %v", filename, err)}
	}
	hasTestseam := func(doc *ast.CommentGroup) bool {
		if doc == nil {
			return false
		}
		for _, comment := range doc.List {
			if strings.Contains(comment.Text, "testseam:") {
				return true
			}
		}
		return false
	}
	var violations []string
	flag := func(name, kind string, doc *ast.CommentGroup) {
		marked := hasTestseam(doc)
		inList := list[name]
		isForTest := strings.Contains(name, "ForTest")
		switch {
		case marked && !inList && !isForTest:
			violations = append(violations, fmt.Sprintf(
				"%s:%s %q 带 //testseam: 标记但名字不含 ForTest——标记误用（只用于 test-only 缝登记）", filename, kind, name))
		case isForTest && !inList:
			violations = append(violations, fmt.Sprintf(
				"%s:%s %q 产品文件声明 test-only 符号未登记——迁到 *_test.go，或（宿主不可迁移的留驻缝）入绊线名单并就地加 //testseam: 标记",
				filename, kind, name))
		case inList && !marked:
			violations = append(violations, fmt.Sprintf(
				"%s:%s %q 在绊线名单且无 //testseam: 登记——宿主应为 *_test.go，或就地加 //testseam: 标记（跨包消费/生产自增的留驻缝）",
				filename, kind, name))
		}
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			flag(d.Name.Name, "func", d.Doc)
		case *ast.GenDecl:
			if d.Tok != token.VAR && d.Tok != token.CONST {
				continue
			}
			for _, spec := range d.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				doc := valueSpec.Doc
				if doc == nil {
					doc = d.Doc
				}
				for _, name := range valueSpec.Names {
					flag(name.Name, d.Tok.String(), doc)
				}
			}
		}
	}
	return violations
}

// TestServicePackageHasNoProductionTestOnlyEntryPoints 产品文件（非 *_test.go）
// 不得承载未登记的 test-only 入口。留在生产文件里会让「生产调用面」判断
// 失真——误复用即把已被优化掉的旧形态重新拉回主链，且无调用点可核对。
func TestServicePackageHasNoProductionTestOnlyEntryPoints(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, violation := range productTestOnlyViolations(name, src, testOnlyEntryList) {
			t.Error(violation)
		}
	}
}

// 绊线自测：全形态覆盖——名单内名字的 var 形态必须被拦（此前只覆盖
// FuncDecl）、func 形态仍被拦、//testseam: 标记放行名单内名字、标记误用
// （标在非 ForTest 名字上）必须被拦。
func TestProductTestOnlyViolations_coversVarShapeAndTestseamMarker(t *testing.T) {
	list := map[string]bool{
		"autobanObserveEvent":                      true,
		"securityEventsSpoolEntryReadBytesForTest": true,
		"registeredSeamForTest":                    true,
	}
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"名单函数形态仍被拦", "package services\n\nfunc autobanObserveEvent() {}\n", 1},
		{"名单 var 形态被拦", "package services\n\nvar autobanObserveEvent int\n", 1},
		{"名单 const 形态被拦", "package services\n\nconst autobanObserveEvent = 1\n", 1},
		{"名单内带标记放行", "package services\n\n// testseam: 生产自增观测计数器。\nvar securityEventsSpoolEntryReadBytesForTest int\n", 0},
		{"未登记 ForTest func 被拦", "package services\n\nfunc brandNewSeamForTest() {}\n", 1},
		{"未登记 ForTest var 被拦", "package services\n\nvar brandNewCounterForTest int\n", 1},
		{"打标但未入名单被拦", "package services\n\n// testseam: 打标即留驻绕登记。\nvar markedOnlyForTest int\n", 1},
		{"打标未入名单 func 被拦", "package services\n\n// testseam: 可移动 helper 打标留驻。\nfunc markedHelperForTest() {}\n", 1},
		{"名单内带标记放行", "package services\n\n// testseam: 生产自增观测计数器。\nvar registeredSeamForTest int\n", 0},
		{"标记误用被拦", "package services\n\n// testseam: 误标。\nvar notASeam = 1\n", 1},
	}
	for _, tc := range cases {
		if got := len(productTestOnlyViolations("craft.go", []byte(tc.src), list)); got != tc.want {
			t.Fatalf("%s: violations=%d, want %d\nsrc:\n%s\nviolations: %v",
				tc.name, got, tc.want, tc.src, productTestOnlyViolations("craft.go", []byte(tc.src), list))
		}
	}
}

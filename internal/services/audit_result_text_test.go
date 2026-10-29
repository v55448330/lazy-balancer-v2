package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// TestAuditResultText_literalArgsCovered：审计结果码渲染
// 硬卡控。扫描 internal/ 全部非测试源码中 AuditResultPart 调用的**字面量**实参，
// 断言每个结果码都在 auditResultTextMap 有中文映射——否则失败详情渲染
// 「结果：<英文码>」，与中文口径分裂（"failure"/"storage_corrupted" 曾如此）。
// 新增结果码漏映射时此测试直接红；映射成为唯一事实源（switch → map 收敛）。
// 动态传参（变量/表达式）不在本钉范围——其取值集由各调用点自身约束。
func TestAuditResultText_literalArgsCovered(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	missing := map[string]string{} // 结果码 → 首处证据位置
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if name != "AuditResultPart" || len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if _, mapped := auditResultTextMap[value]; !mapped {
				if _, seen := missing[value]; !seen {
					missing[value] = fset.Position(call.Pos()).String()
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	if len(missing) == 0 {
		return
	}
	codes := make([]string, 0, len(missing))
	for code := range missing {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	var b strings.Builder
	for _, code := range codes {
		b.WriteString("  ")
		b.WriteString(strconv.Quote(code))
		b.WriteString(" @ ")
		b.WriteString(missing[code])
		b.WriteString("\n")
	}
	t.Fatalf("AuditResultPart 字面量结果码缺中文映射（请在 auditResultTextMap 补齐）:\n%s", b.String())
}

// 字面量、动态闭包与票据硬清单之外，整表逐项执行同一中文渲染契约。
// 防止只在 AST 扫描中出现的码退化成英文或回显内部码而逃过分组用例。
func TestAuditResultText_allMappingsRenderChinese(t *testing.T) {
	if len(auditResultTextMap) == 0 {
		t.Fatal("auditResultTextMap 为空——整表扫描失效")
	}
	for code := range auditResultTextMap {
		assertChineseAuditRendering(t, code)
	}
}

// 动态实参（变量/表达式）不在字面量扫描范围；新增动态入口必须同步审查
// 其取值域。这里钉住当前动态调用点数量：新增即红，强制补映射/白名单。
func TestAuditResultText_dynamicCallSitesTripwire(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatal(err)
	}
	dynamic := 0
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if name != "AuditResultPart" || len(call.Args) == 0 {
				return true
			}
			if _, ok := call.Args[0].(*ast.BasicLit); !ok {
				dynamic++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// 11 处动态入口（结果码为变量、原因文本只进 detail），逐项取值域：
	//   certificates.go IssueCertificate 的 auditFailure 闭包 1 处
	//     （blocked/conflict/failed/invalid_request/skipped）
	//   caproviders.go 测试 CA 提供商 1 处——auditCAProviderTestResult
	//     单源 helper（not_found/provider_error/missing_acme_email/
	//     invalid_config/register_failed）；原 6 处同形 recordAudit 已收敛
	//     进该 helper（P4 同族收敛，取值域不变）
	//   users.go 修改用户状态 1 处（enabled/disabled）
	//   cluster_ticket.go 2 处——生成失败（failed/blocked）与 TicketLogin
	//     失败归因（invalid_ticket/invalid_signature/expired/replay/
	//     user_unavailable/database_error）
	//   cluster_registration.go 节点操作闭包 2 处——clusterNodeAction 与站点
	//     坐标保存各 1（blocked/invalid_request/failed）
	//   certjobs.go 2 处——retryCertJobByID 的失败出口闭包（auditFailure 与
	//     auditFailureWithRule 各 1，取值域见 auditDynamicResultCodes 的
	//     证书任务重试/删除失败组）
	//   certjobs.go DeleteCertJob 1 处——失败出口闭包
	//   cluster_status.go ReportClusterNode 的 recordDetached 闭包 1 处——
	//     脱离请求的失败/拒绝/成功归因（success/failed/blocked）
	// 取值域逐项登记在 auditDynamicResultCodes，新增码仍受
	// TestAuditResultText_auditFailureLiteralsRegistered 与本表约束。
	const want = 11
	// 注释与常数同步门：上面那条「N 处」此前写成 12 而枚举与常数都是 15——
	// 维护者读注释判断「面有多大」时会误判漏枚举。注释数字必须等于 want。
	source, err := os.ReadFile("audit_result_text_test.go")
	if err != nil {
		t.Fatalf("读取本文件以核对注释计数: %v", err)
	}
	commentCount := regexp.MustCompile(`// (\d+) 处动态入口`).FindSubmatch(source)
	if len(commentCount) != 2 {
		t.Fatal("缺少「// N 处动态入口」计数注释（本门失去锚点）")
	}
	if documented, err := strconv.Atoi(string(commentCount[1])); err != nil || documented != want {
		t.Fatalf("注释声明 %s 处动态入口，常数 want=%d——注释与枚举/实现已漂移", commentCount[1], want)
	}
	if dynamic != want {
		t.Fatalf("AuditResultPart 动态调用点=%d，want %d：新增动态入口必须审查取值域并更新本绊线", dynamic, want)
	}
}

func TestAuditResultText_ticketFailureCodes(t *testing.T) {
	for _, code := range []string{"invalid_ticket", "invalid_signature", "expired", "replay", "user_unavailable", "database_error"} {
		assertChineseAuditRendering(t, code)
	}
	if got := AuditResultText("unknown_ticket_reason"); got != "unknown_ticket_reason" {
		t.Fatalf("unknown codes must pass through unchanged, got %q", got)
	}
}

// assertChineseAuditRendering 断言结果码渲染成中文且不回显内部码。
// 「非空且不等于码」不够：映射成任意英文串（如 "ticket expired"）也算通过，
// 审计详情仍是中英混杂——判据改为「含 CJK 且不含内部码」。
func assertChineseAuditRendering(t *testing.T, code string) {
	t.Helper()
	got := AuditResultText(code)
	if got == "" || got == code {
		t.Fatalf("结果码 %q 缺中文映射（渲染为 %q）", code, got)
	}
	hasCJK := false
	for _, r := range got {
		if unicode.Is(unicode.Han, r) {
			hasCJK = true
			break
		}
	}
	if !hasCJK {
		t.Fatalf("结果码 %q 的渲染 %q 不含中文（审计详情中英混杂）", code, got)
	}
	if strings.Contains(got, code) {
		t.Fatalf("结果码 %q 的渲染 %q 仍回显内部码", code, got)
	}
}

// handlers/certificates.go 的 auditFailure 是局部闭包，结果码
// 以动态实参进入 AuditResultPart——字面量扫描钉测（literalArgsCovered）天然
// 覆盖不到，"blocked" 与 "conflict" 由此两次缺映射（审计详情渲染英文码）。
// 取值域的唯一事实源是 services.auditDynamicResultCodes：本用例直接遍历该
// 常量集（不再在测试里手写清单——手写清单曾与映射表同步漂移漏掉 conflict），
// 要求每一项都有中文映射。
func TestAuditResultText_dynamicClosureCodes(t *testing.T) {
	if len(auditDynamicResultCodes) == 0 {
		t.Fatal("动态结果码常量集为空——守护失效")
	}
	for _, code := range auditDynamicResultCodes {
		assertChineseAuditRendering(t, code)
	}
	if got := AuditResultText("blocked"); got != "重试被阻止" {
		t.Fatalf("blocked 渲染=%q，want 重试被阻止", got)
	}
	if got := AuditResultText("conflict"); got != "状态冲突" {
		t.Fatalf("conflict 渲染=%q，want 状态冲突", got)
	}
}

// TestAuditResultText_auditFailureLiteralsRegistered 用 AST 扫出所有
// auditFailure(...) 的**字面量**首参（证书签发路径的闭包以动态实参进入
// AuditResultPart，字面量扫描覆盖不到），要求每个结果码既在
// auditResultTextMap 有中文映射、也在 auditDynamicResultCodes 登记——新增
// 结果码漏登记/漏映射即红。同名 helper 在 cluster_service.go 首参是节点编号
// （整数），非字符串字面量，天然不在扫描面。
func TestAuditResultText_auditFailureLiteralsRegistered(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	registered := make(map[string]struct{}, len(auditDynamicResultCodes))
	for _, code := range auditDynamicResultCodes {
		registered[code] = struct{}{}
	}
	missing := map[string]string{} // 结果码 → 首处证据位置
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "auditFailure" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			_, inMap := auditResultTextMap[value]
			_, inSet := registered[value]
			if !inMap || !inSet {
				if _, seen := missing[value]; !seen {
					missing[value] = fset.Position(call.Pos()).String()
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	if len(missing) == 0 {
		return
	}
	codes := make([]string, 0, len(missing))
	for code := range missing {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	var b strings.Builder
	for _, code := range codes {
		b.WriteString("  ")
		b.WriteString(strconv.Quote(code))
		b.WriteString(" @ ")
		b.WriteString(missing[code])
		b.WriteString("\n")
	}
	t.Fatalf("auditFailure 字面量结果码未登记/未映射（请在 auditDynamicResultCodes 登记并补 auditResultTextMap）:\n%s", b.String())
}

// TestAuditResultText_dynamicAssignmentsRegistered 扫「局部变量字面量赋值 →
// 结果码实参」这条链路：`result := "..."` / `result = "..."` 后把 result 传给
// auditFailure / auditFailureWithRule / AuditResultPart 是最常见的动态结果码
// 形态，却同时落在两道路标之外（字面量扫描只看 AuditResultPart("码")，
// auditFailure 扫描只看 auditFailure("码")）。本用例按函数作用域收集这些变量
// 的字符串字面量取值，要求全部登记在 auditDynamicResultCodes——与
// TestAuditResultText_dynamicClosureCodes（清单 → 映射）构成双向校验：清单值
// 必有中文映射，实际赋值取值必有清单登记。query_failed 曾因两侧都看不见而
// 漏登记（渲染未受影响，靠 auditResultTextMap 的既有映射兜住）。
func TestAuditResultText_dynamicAssignmentsRegistered(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	registered := make(map[string]struct{}, len(auditDynamicResultCodes))
	for _, code := range auditDynamicResultCodes {
		registered[code] = struct{}{}
	}
	missing := map[string]string{} // 结果码 → 首处证据位置
	links := 0
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// 函数作用域内的「标识符 → 字面量取值集」（含 := 与 = 两种形态）。
			assigned := map[string][]string{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				stmt, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, lhs := range stmt.Lhs {
					if i >= len(stmt.Rhs) {
						continue
					}
					ident, ok := lhs.(*ast.Ident)
					if !ok {
						continue
					}
					lit, ok := stmt.Rhs[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					value, uerr := strconv.Unquote(lit.Value)
					if uerr != nil {
						continue
					}
					assigned[ident.Name] = append(assigned[ident.Name], value)
				}
				return true
			})
			if len(assigned) == 0 {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				var name string
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					name = fun.Name
				case *ast.SelectorExpr:
					name = fun.Sel.Name
				}
				switch name {
				case "auditFailure", "auditFailureWithRule", "AuditResultPart":
				default:
					return true
				}
				ident, ok := call.Args[0].(*ast.Ident)
				if !ok {
					return true
				}
				for _, value := range assigned[ident.Name] {
					links++
					if _, ok := registered[value]; ok {
						continue
					}
					if _, seen := missing[value]; !seen {
						missing[value] = fset.Position(call.Pos()).String()
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	if links == 0 {
		t.Fatal("未收集到任何「变量赋值 → 结果码实参」链路——扫描器形态已变更，需同步本用例")
	}
	if len(missing) == 0 {
		return
	}
	codes := make([]string, 0, len(missing))
	for code := range missing {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	var b strings.Builder
	for _, code := range codes {
		b.WriteString("  ")
		b.WriteString(strconv.Quote(code))
		b.WriteString(" @ ")
		b.WriteString(missing[code])
		b.WriteString("\n")
	}
	t.Fatalf("动态结果码赋值未登记 auditDynamicResultCodes:\n%s", b.String())
}

// 审计来源码渲染——

// scanAuditSourceLiterals 扫描 internal/ 非测试源码中给定函数的**字面量**首参，
// 返回 字面量 → 首处位置。
func scanAuditSourceLiterals(t *testing.T, funcs map[string]struct{}) map[string]string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	found := map[string]string{}
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if _, wanted := funcs[name]; !wanted {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if _, seen := found[value]; !seen {
				found[value] = fset.Position(call.Pos()).String()
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	return found
}

// hasASCIILetter 报告 s 是否含 ASCII 字母（区分「内部来源码」与「已中文化
// 字面量」——handlers 侧存在直接传中文展示串的调用点，如「保存前测试」）。
func hasASCIILetter(s string) bool {
	for i := range s {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// 来源码字面量覆盖钉（与 TestAuditResultText_literalArgsCovered 对称）。
// 扫描 AuditSourcePart 的字面量实参以及两条把首参直接转发给它的链
// （recordSystemReloadAudit / txReloadDetail）——每个含 ASCII 字母的字面量必须
// 在 auditSourceTextMap 有中文映射，否则落 default 渲染英文内部标识
// （runtime_reconcile/runtime_sweep/promote_or_startup 曾如此）。
func TestAuditSourcePart_literalArgsCovered(t *testing.T) {
	found := scanAuditSourceLiterals(t, map[string]struct{}{
		"AuditSourcePart":         {},
		"recordSystemReloadAudit": {},
		"txReloadDetail":          {},
	})
	missing := make([]string, 0, len(found))
	for value, pos := range found {
		if !hasASCIILetter(value) {
			continue // 已中文化的展示串（不经码表）
		}
		if _, ok := auditSourceTextMap[value]; !ok {
			missing = append(missing, strconv.Quote(value)+" @ "+pos)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("来源码缺中文映射（请在 auditSourceTextMap 补齐）:\n  %s", strings.Join(missing, "\n  "))
	}
}

// 动态实参（变量/表达式）不在字面量扫描范围——新增动态入口必须
// 同步审查取值域。这里钉住当前动态调用点数量：新增即红。
func TestAuditSourcePart_dynamicCallSitesTripwire(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatal(err)
	}
	dynamic := 0
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if name != "AuditSourcePart" {
				return true
			}
			if _, ok := call.Args[0].(*ast.BasicLit); !ok {
				dynamic++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// 当前动态入口：recordSystemReloadAudit 内 2 处（失败/成功）、txReloadDetail
	// 1 处（handlers）、renewExpiringCertificates 的 source 变量 1 处。
	const want = 4
	if dynamic != want {
		t.Fatalf("AuditSourcePart 动态调用点=%d，want %d：新增动态入口必须审查取值域并更新本绊线", dynamic, want)
	}
}

// 内部来源码必须渲染中文（映射值不得回显内部码）。
func TestAuditSourcePart_internalCodesRenderChinese(t *testing.T) {
	want := map[string]string{
		"runtime_reconcile":  "来源：运行时对账",
		"runtime_sweep":      "来源：运行时清扫",
		"promote_or_startup": "来源：升主或启动补建",
	}
	for code, expected := range want {
		if got := AuditSourcePart(code); got != expected {
			t.Errorf("AuditSourcePart(%q)=%q, want %q", code, got, expected)
		}
	}
	for code, text := range auditSourceTextMap {
		if strings.Contains(text, code) {
			t.Errorf("映射值 %q → %q 仍含内部来源码（渲染仍中英混杂）", code, text)
		}
		if !strings.HasPrefix(text, "来源：") {
			t.Errorf("映射值 %q → %q 缺「来源：」前缀（详情段口径）", code, text)
		}
	}
	// 动态取值域（certificates.go renewExpiringCertificates / txReloadDetail /
	// recordSystemReloadAudit 调用方）必须在表内。
	for _, code := range []string{
		"renewal", "first_issuance_retry",
		"rule_create", "rule_update", "rule_delete", "rule_enable", "rule_disable",
		"certificate_issued", "crs_update", "threat_update", "ip2region_update", "autoban",
	} {
		if _, ok := auditSourceTextMap[code]; !ok {
			t.Errorf("动态来源码 %q 缺映射（落 default 渲染英文）", code)
		}
	}
	if got := AuditSourcePart("unknown_source_code"); got != "来源：unknown_source_code" {
		t.Errorf("未知来源码必须原样兜底（便于定位漏映射）, got %q", got)
	}
}

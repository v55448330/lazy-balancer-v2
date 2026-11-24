package apimsg

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// 后端不再新增展示文案（基线钉）。用户 2026-11-25 裁定：后端只返回稳定键 + 参数，
// 展示文案归前端词条（web/docs/I18N.md 第 0 节）。
//
// 数两样东西，当前数量必须恰好等于基线——变多 = 新增违规；变少 = 基线过松，
// 请在同一提交里把基线调低：
//
//	A. internal/i18n 里「中 → 英」登记的条数：Register（响应词条）与 RegisterErrTpl（错误模板）。
//	   后端不该再翻译文案；存量随迁移搬到前端后删除，登记数只应下降。
//	   注意：键 → 中文原文的对照在迁移后仍由后端保留（响应 message 的中文母本），
//	   所以后续若登记形态变为「只有中文」，这里的判别要随之改成只数带英文译文的登记。
//	B. handlers / middleware 里 APIResponse.Message 直接写中文字面量的处数
//	   （含 fmt.Sprintf 的中文字面量格式串）。新文案应返回稳定键 + 参数。
//
// 豁免：机器接口文件（集群节点上报 / 注册、MCP 鉴权）——消费方是从节点重试逻辑与
// API 客户端，没有用户语言面。
//
// 本测试是基线钉：它钉的是当前存量，按 TDD 规范豁免 RED；判别是否有效由
// TestBackendTextRatchet_detector 的自检与变异验证证明。

// 当前存量（2026-11-25 基线）。修掉存量后把数字调低；调高即新增违规。
const (
	baselineCatalogRegistrations = 661
	baselineErrTplRegistrations  = 750
	baselineLiteralMessageSinks  = 5
)

var backendTextMachineOnlyFiles = map[string]bool{
	"cluster_events_report.go":     true,
	"cluster_node_stats_report.go": true,
	"cluster_auth.go":              true,
	"mcp.go":                       true,
}

type backendTextCounts struct{ catalog, errtpl, literalMessage int }

func hasHan(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// isHanSprintf：fmt.Sprintf("中文…", …) 的格式串是中文字面量。
func isHanSprintf(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	fn, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || fn.Sel.Name != "Sprintf" {
		return false
	}
	if id, ok := fn.X.(*ast.Ident); !ok || id.Name != "fmt" {
		return false
	}
	text, ok := stringLiteral(call.Args[0])
	return ok && hasHan(text)
}

// countBackendTextIn 统计一份源码里的三类计数（供真实文件与判别自检共用）。
func countBackendTextIn(src, filename string) (counts backendTextCounts, offenders []string) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return counts, []string{"解析失败 " + filename + ": " + err.Error()}
	}
	at := func(n ast.Node) string { return filename + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) }
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			name := ""
			switch fn := v.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			// 只数「带英文译文」的中→英登记：Register(key, zh, en)、RegisterErrTpl(zh, en)。
			// 键 → 中文原文的对照（响应 message 的中文母本）不算译文。
			switch {
			case name == "Register" && len(v.Args) >= 3:
				if zh, ok := stringLiteral(v.Args[1]); ok && hasHan(zh) {
					if en, ok := stringLiteral(v.Args[2]); ok && en != "" {
						counts.catalog++
					}
				}
			case name == "RegisterErrTpl" && len(v.Args) >= 2:
				if zh, ok := stringLiteral(v.Args[0]); ok && hasHan(zh) {
					if en, ok := stringLiteral(v.Args[1]); ok && en != "" {
						counts.errtpl++
					}
				}
			}
		case *ast.CompositeLit:
			typeName := ""
			switch ty := v.Type.(type) {
			case *ast.SelectorExpr:
				typeName = ty.Sel.Name
			case *ast.Ident:
				typeName = ty.Name
			}
			if typeName != "APIResponse" {
				return true
			}
			for _, elt := range v.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, _ := kv.Key.(*ast.Ident)
				if key == nil || key.Name != "Message" {
					continue
				}
				if text, ok := stringLiteral(kv.Value); ok && hasHan(text) || isHanSprintf(kv.Value) {
					counts.literalMessage++
					offenders = append(offenders, at(kv))
				}
			}
		}
		return true
	})
	return counts, offenders
}

// nonTestGoFiles 列出目录下的非测试 .go 文件。
func nonTestGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") || backendTextMachineOnlyFiles[filepath.Base(path)] {
			continue
		}
		out = append(out, path)
	}
	if len(out) == 0 {
		t.Fatalf("扫描面异常：%s 下没有非测试源码，守卫会假绿", dir)
	}
	return out
}

func TestBackendTextRatchet_detector(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want backendTextCounts
	}{
		{"响应词条登记计入 catalog", `package x
func init() { Register("a", "查询成功", "Query succeeded") }`, backendTextCounts{catalog: 1}},
		{"错误模板登记计入 errtpl", `package x
func init() { RegisterErrTpl("%s 不是有效 CIDR: %s", "%s is not a valid CIDR: %s") }`, backendTextCounts{errtpl: 1}},
		{"不带中文的 Register 不计（避免把别的同名函数算进来）", `package x
func init() { Register("a", "plain", "plain") }`, backendTextCounts{}},
		{"只有中文原文、没有英文译文的登记不计（迁移后的保留形态）", `package x
func init() { Register("a", "查询成功", ""); RegisterErrTpl("%s 无效", "") }`, backendTextCounts{}},
		{"Message 直接写中文字面量计入", `package x
func h() { _ = models.APIResponse{Code: 500, Message: "删除成功"} }`, backendTextCounts{literalMessage: 1}},
		{"Message 写 fmt.Sprintf 中文字面量计入", `package x
import "fmt"
func h() { _ = models.APIResponse{Message: fmt.Sprintf("规则 %s 已禁用", id)} }`, backendTextCounts{literalMessage: 1}},
		{"Message 经词条键取值不计（合规形态）", `package x
func h() { _ = models.APIResponse{Code: 0, Message: apimsg.T(c, "rule.saved"), MessageKey: "rule.saved"} }`, backendTextCounts{}},
		{"Message 是错误原文或变量不计（另有运行期口径）", `package x
func h() { _ = models.APIResponse{Message: err.Error()}; _ = models.APIResponse{Message: msg} }`, backendTextCounts{}},
		{"非 APIResponse 的 Message 字段不计", `package x
func h() { _ = models.Event{Message: "内部事件"} }`, backendTextCounts{}},
		{"Message 的英文 Sprintf 不计", `package x
import "fmt"
func h() { _ = models.APIResponse{Message: fmt.Sprintf("rule %s disabled", id)} }`, backendTextCounts{}},
	}
	for _, c := range cases {
		got, _ := countBackendTextIn(c.src, "probe.go")
		if got != c.want {
			t.Errorf("%s: 计数=%+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestBackendTextRatchet_backendAddsNoDisplayText(t *testing.T) {
	var total backendTextCounts
	var offenders []string
	for _, path := range nonTestGoFiles(t, "../i18n") {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		counts, bad := countBackendTextIn(string(src), filepath.Base(path))
		total.catalog += counts.catalog
		total.errtpl += counts.errtpl
		offenders = append(offenders, bad...)
	}
	for _, dir := range []string{"../handlers", "../middleware"} {
		for _, path := range nonTestGoFiles(t, dir) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			counts, bad := countBackendTextIn(string(src), filepath.Base(path))
			total.literalMessage += counts.literalMessage
			offenders = append(offenders, bad...)
		}
	}
	check := func(name string, got, want int) {
		t.Helper()
		if got != want {
			t.Errorf("后端展示文案「%s」现有 %d 处，基线 %d 处。变多了=新增违规：后端只返回稳定键 + 参数，文案放前端词条；"+
				"变少了=请把基线调到 %d。", name, got, want, got)
		}
	}
	check("响应词条中→英登记", total.catalog, baselineCatalogRegistrations)
	check("错误模板中→英登记", total.errtpl, baselineErrTplRegistrations)
	check("响应 Message 直接写中文", total.literalMessage, baselineLiteralMessageSinks)
	if total.literalMessage != baselineLiteralMessageSinks {
		for _, line := range offenders {
			t.Log(line)
		}
	}
}

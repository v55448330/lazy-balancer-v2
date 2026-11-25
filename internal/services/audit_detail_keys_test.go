package services

// 审计明细键化守卫（方案 C 第 2/3 步，2026-11-25 用户批准）：
//   ① 写点必须带键：明细段的键以字符串字面量传入，且必须在 i18n 目录登记
//      （未登记的键会让母本渲染成键名，前端也只能 fail-visible）；
//   ② 明细写入不得直传中文字面量（必须由段构造或已键化变量承载）；
//   ③ 跨栈渲染对等：同一批「键 + 参数」在 Go 母本与前端渲染的结果一致，
//      夹具 web/tests/fixtures/auditDetailParity.json 由两侧共用。

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/i18n"
)

// auditDetailKeyArgIndex 返回「键在实参中的下标」——明细段构造与系统审计的
// 键位置不同，按函数名登记。
var auditDetailKeyArgIndex = map[string]int{
	"AuditTextPart":         0,
	"AuditTextDetail":       0,
	"recordSystemAudit":     2,
	"recordSystemAuditOnce": 2,
}

// 启动迁移系统审计的键化判据是「零未键化」：recordSystemAudit /
// recordSystemAuditOnce 的明细键必须是字符串字面量并在 i18n 目录登记。这批事件
// 发生在审计库就绪前的启动迁移阶段，历史形态是整段 fmt 拼出的中文诊断句
// （detail / dedupeDetail 变量）——变量无法对账登记，英文界面也只能落到中文
// 原文，故一律按未键化报红（含逐条点名），不设存量基线。

func scanAuditDetailKeySites(t *testing.T) (sites int, problems []string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
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
			index, tracked := auditDetailKeyArgIndex[name]
			if !tracked || len(call.Args) <= index {
				return true
			}
			// 豁免：键由「已登记事实」携带的形态——importWarning 等结构体的
			// key 字段（事实产出点登记键，消费点原样透传）。
			if sel, ok := call.Args[index].(*ast.SelectorExpr); ok && sel.Sel.Name == "key" {
				return true
			}
			sites++
			lit, ok := call.Args[index].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				if name == "recordSystemAudit" || name == "recordSystemAuditOnce" {
					// 启动审计零未键化：键必须是字面量，变量（detail/dedupeDetail
					// 之类的整段拼串）无法对账登记，英文界面必落中文原文。
					problems = append(problems, rel+":"+strconv.Itoa(fset.Position(call.Pos()).Line)+": "+name+" 的明细键必须是字符串字面量（启动审计不得传整段纯文本变量）")
					return true
				}
				if _, ok := call.Args[index].(*ast.Ident); ok {
					// 豁免：私有构造器把「键」作为参数接收（brandingReloadDetail 的
					// field(key,…)、AuditTextDetail 的包装）——字面量在调用点传入，
					// 由本守卫对调用点的元数扫描不到。这类构造器在包内私有，新增
					// 调用点同样只从字面量取键（审计覆盖面靠调用点守卫兜住）。
					return true
				}
				problems = append(problems, rel+":"+strconv.Itoa(fset.Position(call.Pos()).Line)+": "+name+" 的键不是字符串字面量")
				return true
			}
			key, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				problems = append(problems, rel+": 键字面量无法解析: "+lit.Value)
				return true
			}
			if !strings.HasPrefix(key, "audit.") {
				problems = append(problems, rel+": 明细段键必须以 audit. 起头: "+key)
				return true
			}
			if i18n.T(key) == key {
				problems = append(problems, rel+": 明细段键未在 i18n 目录登记: "+key)
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk internal: %v", walkErr)
	}
	if sites < 300 {
		t.Fatalf("明细段写点只扫到 %d 处（扫描面异常，守卫会假绿）", sites)
	}
	return sites, problems
}

func TestAuditDetailKeys_literalAndRegistered(t *testing.T) {
	sites, problems := scanAuditDetailKeySites(t)
	if len(problems) > 0 {
		t.Fatalf("明细段键守卫失败（%d 处问题）:\n%s", len(problems), strings.Join(problems, "\n"))
	}
	t.Logf("扫描明细段写点 %d 处，全部为已登记的 audit. 字面量键", sites)
}

// TestAuditDetailWrites_noRawChineseLiteral 明细写入必须经段构造：RecordAuditLog/
// recordAudit 的明细实参不得是中文字面量（直传中文 = 未键化，英文界面必然露中文）。
func TestAuditDetailWrites_noRawChineseLiteral(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	hasHan := func(s string) bool {
		return strings.ContainsFunc(s, func(r rune) bool { return r >= 0x4E00 && r <= 0x9FFF })
	}
	argIndex := map[string]int{"RecordAuditLog": 3, "recordAudit": 3}
	var problems []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
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
			index, tracked := argIndex[name]
			if !tracked || len(call.Args) <= index {
				return true
			}
			if lit, ok := call.Args[index].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if text, uerr := strconv.Unquote(lit.Value); uerr == nil && hasHan(text) {
					problems = append(problems, rel+":"+strconv.Itoa(fset.Position(call.Pos()).Line)+": 明细直传中文字面量: "+text)
				}
			}
			return true
		})
		return nil
	})
	if len(problems) > 0 {
		t.Fatalf("明细写入不得直传中文（请改用 AuditTextDetail/AuditRawDetail）:\n%s", strings.Join(problems, "\n"))
	}
}

type auditDetailParityCase struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Params any    `json:"params"`
	ZH     string `json:"zh"`
}

// TestAuditDetail_renderParityFixture 跨栈渲染对等：夹具的 params 直接落成
// detail_params 的 JSON 形态，Go 侧按段渲染的母本必须与夹具 zh 逐字相等；
// 前端 auditDetailParity.spec.ts 用同一夹具断言英文与槽位对账。
func TestAuditDetail_renderParityFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "tests", "fixtures", "auditDetailParity.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var cases []auditDetailParityCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("fixture 为空——对等守卫会空转")
	}
	for _, c := range cases {
		got := renderDetailForTest(t, c.Key, c.Params)
		if got != c.ZH {
			t.Errorf("%s: 母本渲染=%q, 夹具 zh=%q", c.Name, got, c.ZH)
		}
		for _, segment := range strings.Split(c.Key, AuditDetailKeySeparator) {
			if i18n.T(segment) == segment {
				t.Errorf("%s: 段键未登记: %s", c.Name, segment)
			}
		}
	}
}

// renderDetailForTest 用落库形态（段键 + 参数数组）复现前端渲染，验证母本一致。
func renderDetailForTest(t *testing.T, key string, raw any) string {
	t.Helper()
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("encode params: %v", err)
	}
	var decoded [][]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("params 不是二维数组: %v", err)
	}
	keys := strings.Split(key, AuditDetailKeySeparator)
	texts := make([]string, 0, len(keys))
	for index, segment := range keys {
		texts = append(texts, renderSegmentForTest(t, segment, decoded[index]))
	}
	return joinChineseParts(texts)
}

// renderSegmentForTest 按词条键渲染一段（槽位可能是字符串、嵌套段或段列表）。
func renderSegmentForTest(t *testing.T, key string, slots []any) string {
	t.Helper()
	template := i18n.T(key)
	if len(slots) == 0 {
		return template
	}
	args := make([]any, 0, len(slots))
	for _, slot := range slots {
		switch value := slot.(type) {
		case string:
			args = append(args, value)
		case map[string]any:
			nestedKey, _ := value["k"].(string)
			nestedSlots, _ := value["a"].([]any)
			args = append(args, renderSegmentForTest(t, nestedKey, nestedSlots))
		case []any:
			texts := make([]string, 0, len(value))
			for _, item := range value {
				segment, ok := item.(map[string]any)
				if !ok {
					continue
				}
				nestedKey, _ := segment["k"].(string)
				nestedSlots, _ := segment["a"].([]any)
				texts = append(texts, renderSegmentForTest(t, nestedKey, nestedSlots))
			}
			args = append(args, joinChineseParts(texts))
		default:
			args = append(args, value)
		}
	}
	return fillTemplateForTest(template, args)
}

// fillTemplateForTest 按前端 formatApiMessage 的口径填充槽位（动词无关：%s/%d/%v
// 都消费一个参数，%q 在两侧加引号，%% 输出字面百分号）——落库参数一律是字符串，
// 后端母本用 fmt 时 %d 会得到 %!d(string)，与前端渲染不等价。
func fillTemplateForTest(template string, params []any) string {
	var out strings.Builder
	next := 0
	for i := 0; i < len(template); i++ {
		ch := template[i]
		if ch != '%' || i+1 >= len(template) {
			out.WriteByte(ch)
			continue
		}
		code := template[i+1]
		switch code {
		case '%':
			out.WriteByte('%')
			i++
		case 's', 'd', 'v', 'q':
			if next >= len(params) {
				out.WriteByte('%')
				out.WriteByte(code)
				i++
				continue
			}
			text := fmt.Sprint(params[next])
			if code == 'q' {
				out.WriteString("\"" + text + "\"")
			} else {
				out.WriteString(text)
			}
			next++
			i++
		default:
			out.WriteByte(ch)
		}
	}
	return out.String()
}

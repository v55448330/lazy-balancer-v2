package services

// 结构守卫：生产代码中「INSERT INTO lb_rules (」
// 手写字面量唯一豁免=config_import_v1.go（v1 遗留转换器，窄清单语义已裁定
// 维持）；其余站点必须经 LbRuleInsertSQL 单源生成——新增列漏改某一处即
// 「保存成功但与快照/副本不同形」。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// handwrittenRuleInsertPattern 匹配「手写 lb_rules 全行写」的归一化形态。
// 原判定 strings.Contains(query, "INSERT INTO lb_rules (")
// 是字面量、单空格、必须同串——`INSERT INTO lb_rules\n(…`、`INSERT OR REPLACE INTO
// lb_rules`、`INSERT INTO "lb_rules"` 全部静默绕过单源门。归一化（空白折叠 +
// 去引号/方括号）后按表名边界判定；列清单不再是必要条件——无列清单的
// `INSERT INTO lb_rules VALUES (…)` 是隐式列序清单，同属单源禁区。
// `REPLACE INTO lb_rules`（SQLite 的 delete+insert 全行形态）同属第二份列清单。
var handwrittenRuleInsertPattern = regexp.MustCompile(`(?i)\b(?:insert(?:\s+or\s+(?:replace|ignore))?\s+into|replace\s+into)\s+lb_rules\b`)

// isHandwrittenRuleInsert 报告 SQL 文本是否是手写规则 INSERT。
func isHandwrittenRuleInsert(query string) bool {
	normalized := strings.Join(strings.Fields(query), " ")
	normalized = strings.NewReplacer(`"`, "", "`", "", "[", "", "]", "").Replace(normalized)
	return handwrittenRuleInsertPattern.MatchString(normalized)
}

// ruleInsertViolations 扫描 root 下全部生产 Go 文件（跳过 _test.go 与
// .git/vendor/node_modules/web）中手写 lb_rules INSERT 的站点：
//   - 函数体内字面量按「文件 → 允许函数集」豁免；
//   - 包级 var/const 字面量一律违规（包级 SQL 常量无函数归属，等同新增第二份
//     列清单）。
func ruleInsertViolations(root string, allowed map[string]map[string]bool) ([]string, error) {
	skipDirs := map[string]bool{".git": true, "vendor": true, "node_modules": true, "web": true}
	var violations []string
	inspectLiterals := func(fileSet *token.FileSet, node ast.Node, file, owner string) {
		if allowed[file][owner] {
			return
		}
		ast.Inspect(node, func(candidate ast.Node) bool {
			literal, ok := candidate.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			query, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil || !isHandwrittenRuleInsert(query) {
				return true
			}
			violations = append(violations, fileSet.Position(literal.Pos()).String()+" in "+owner)
			return true
		})
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && skipDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fileSet := token.NewFileSet()
		file, parseErr := parser.ParseFile(fileSet, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		for _, declaration := range file.Decls {
			switch node := declaration.(type) {
			case *ast.FuncDecl:
				if node.Body != nil {
					inspectLiterals(fileSet, node.Body, rel, node.Name.Name)
				}
			case *ast.GenDecl:
				inspectLiterals(fileSet, node, rel, "package-level declaration")
			}
		}
		return nil
	})
	return violations, err
}

func TestLbRuleInsertStatements_useSingleSource(t *testing.T) {
	// file → 允许的函数集（比整文件豁免更紧：事实源文件内也只允许生成器本体）。
	allowed := map[string]map[string]bool{
		"internal/handlers/config_import_v1.go":   {"ImportV1Config": true},
		"internal/services/rule_write_columns.go": {"LbRuleInsertSQL": true},
	}
	// 扫描根=仓库根：internal/ 之外的顶层包与 cmd/ 同样是单源门的覆盖面。
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("扫描根必须为仓库根（含 go.mod）: %v", err)
	}
	violations, err := ruleInsertViolations(root, allowed)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("手写规则 INSERT 列清单（必须经 LbRuleInsertSQL 单源）:\n%s", strings.Join(violations, "\n"))
	}
}

// 守卫判定必须先归一化再匹配——换行、多空格、带引号
// 表名、INSERT OR REPLACE/IGNORE 任一形态都不得逃逸（原字面量 Contains 对上述
// 形态静默漏检，新增手写 INSERT 只要换行即可绕过单源门）。
func TestHandwrittenRuleInsertMatcher_normalizesFormattingVariants(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{name: "canonical", query: "INSERT INTO lb_rules (caddy_id) VALUES (?)", want: true},
		{name: "newline before columns", query: "INSERT INTO lb_rules\n\t(caddy_id) VALUES (?)", want: true},
		{name: "extra spaces", query: "INSERT  INTO   lb_rules   (caddy_id) VALUES (?)", want: true},
		{name: "quoted table", query: `INSERT INTO "lb_rules" (caddy_id) VALUES (?)`, want: true},
		{name: "or replace", query: "INSERT OR REPLACE INTO lb_rules (caddy_id) VALUES (?)", want: true},
		{name: "or ignore lowercase", query: "insert or ignore into lb_rules(caddy_id) values (?)", want: true},
		{name: "plain replace into", query: "REPLACE INTO lb_rules (caddy_id) VALUES (?)", want: true},
		{name: "replace into quoted table", query: `REPLACE INTO "lb_rules" VALUES (?)`, want: true},
		{name: "other table", query: "INSERT INTO lb_rules_backup (caddy_id) VALUES (?)", want: false},
		{name: "plain select", query: "SELECT * FROM lb_rules WHERE id = ?", want: false},
		{name: "other insert", query: "INSERT INTO upstreams (rule_id) VALUES (?)", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isHandwrittenRuleInsert(test.query); got != test.want {
				t.Fatalf("isHandwrittenRuleInsert(%q)=%v, want %v", test.query, got, test.want)
			}
		})
	}
}

// 守卫自检矩阵（临时目录夹具）：覆盖形态必须逐项命中，豁免与扫描面必须精确。
//   - 包级 var/const 字面量：无函数归属，等同第二份列清单 → 违规；
//   - 允许函数内的同形态字面量（生成器本体）→ 不误报；
//   - `_test.go` 不在扫描面；
//   - 无列清单的 VALUES 形态（隐式列序）与带引号/方括号表名 → 命中。
func TestRuleInsertScan_coversPackageLevelAndValuesForm(t *testing.T) {
	root := t.TempDir()
	writeFixture := func(name, content string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir fixture: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	writeFixture("fixture.go", `package fixture

func LbRuleInsertSQL(column string) string {
	return "INSERT INTO lb_rules (" + column + ") VALUES (?)"
}

var packageLevelValues = "INSERT INTO lb_rules VALUES (1, 2)"

const quotedTable = "INSERT INTO \"lb_rules\" VALUES (3)"
`)
	writeFixture("fixture_test.go", `package fixture

var testOnly = "INSERT INTO lb_rules VALUES (9)"
`)

	violations, err := ruleInsertViolations(root, map[string]map[string]bool{"fixture.go": {"LbRuleInsertSQL": true}})
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	joined := strings.Join(violations, "\n")
	if len(violations) != 2 {
		t.Fatalf("违规数=%d, want 2（包级 VALUES + 引号表名）:\n%s", len(violations), joined)
	}
	if !strings.Contains(joined, "package-level") {
		t.Fatalf("包级声明违规必须标注归属:\n%s", joined)
	}
	if strings.Contains(joined, "LbRuleInsertSQL") {
		t.Fatalf("允许函数内的生成器字面量被误报:\n%s", joined)
	}
	if strings.Contains(joined, "fixture_test.go") {
		t.Fatalf("_test.go 不得进入扫描面:\n%s", joined)
	}

	// 带方括号的表名同样命中（归一化覆盖 SQLite 标识符引号形态）。
	if !isHandwrittenRuleInsert("INSERT INTO [lb_rules] VALUES (4)") {
		t.Fatal("方括号表名形态未命中")
	}
	if isHandwrittenRuleInsert("SELECT * FROM lb_rules WHERE id = ?") {
		t.Fatal("非 INSERT 语句误报")
	}
}

// UpdateRule 编辑保存的 SET 列清单必须与单源（lbRuleColumnSpecs）等价：
// specs 派生 INSERT/快照投影，编辑路径的 SET 列清单是第四份列清单——新增列
// 时只改 specs，编辑保存会静默不写该列（新建/复制/快照/集群应用均正常），
// 正是单源机制要防的形态。这里对 SET 列集合做双向集合等价断言。
func TestUpdateRuleSetColumns_matchSingleSource(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "handlers", "rules.go"))
	if err != nil {
		t.Fatalf("read rules.go: %v", err)
	}
	body := string(src)
	// SET 列清单已提取为 handlers 包级单源表（updateRuleSetColumns，init 冻结
	// 快照驱动 buildUpdateRuleSetClause 生成 SQL）——锚点对齐表声明，逐项提取
	// 复合字面量首列名；表内注释/多行 func 值表达式不含 `{"` 形态，无噪声命中。
	const anchor = "var updateRuleSetColumns = []updateRuleSetColumn{"
	start := strings.Index(body, anchor)
	if start < 0 {
		t.Fatalf("UpdateRule SET 单源表未命中（锚点被改名？）: %q", anchor)
	}
	window := body[start+len(anchor):]
	end := strings.Index(window, "\n}")
	if end < 0 {
		t.Fatalf("updateRuleSetColumns 表结束锚点未命中")
	}
	window = window[:end]

	written := map[string]bool{}
	for _, match := range regexp.MustCompile(`\{"([a-z_0-9]+)",`).FindAllStringSubmatch(window, -1) {
		written[match[1]] = true
	}
	// updated_at/updated_by 由 UpdateRule 终局守卫分支字面量追加（cert 在途
	// 409 守卫双分支）——锚点钉住该追加形态；两列若迁入单源表，此处同步改表提取。
	const tail = "updated_at = datetime('now'), updated_by = ?"
	if !strings.Contains(body, tail) {
		t.Fatalf("UpdateRule SET 尾部锚点未命中: %q", tail)
	}
	written["updated_at"] = true
	written["updated_by"] = true

	// 编辑不写主键/外键与创建审计列（id 自增、caddy_id 为 WHERE 键、
	// created_* 由创建路径落库）。
	excluded := map[string]bool{"id": true, "caddy_id": true, "created_by": true, "created_at": true}
	expected := map[string]bool{}
	for _, spec := range lbRuleColumnSpecs {
		if !excluded[spec.name] {
			expected[spec.name] = true
		}
	}
	for column := range expected {
		if !written[column] {
			t.Errorf("UpdateRule SET 清单缺少列 %q——编辑保存会静默不写该列（新建/复制/快照仍正常）", column)
		}
	}
	for column := range written {
		if !expected[column] {
			t.Errorf("UpdateRule SET 含规格外/不该更新的列 %q——写入单一事实源漂移", column)
		}
	}
}

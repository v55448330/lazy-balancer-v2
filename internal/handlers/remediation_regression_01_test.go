package handlers

// 备份导入通道（restoreTable）对 security_block_pages.content_type 加白名单门
// ——非法值归一默认 text/html; charset=utf-8（与 mode 枚举门同口径的
// 「导入侧值域收敛」），杜绝带外 CRLF/任意字符串落库渲染进响应头。

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestImportConfigBackup_normalizesInvalidBlockPageContentType(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// Given：备份内拦截页 content_type 为白名单外值（CRLF 注入形态）与合法值各一
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_block_pages": {
			{"id": 100, "name": "恶意类型页", "content": "x", "content_type": "text/html\r\nX-Injected: 1"},
			{"id": 101, "name": "合法 JSON 页", "content": "{}", "content_type": "application/json; charset=utf-8"},
		},
	})

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（非法类型应归一放行而非整包拒绝）", response.Code, response.Body.String())
	}

	// Then：非法值归一默认，合法值保留
	var evil, good string
	if err := db.DB.QueryRow(`SELECT COALESCE(content_type,'') FROM security_block_pages WHERE id=100`).Scan(&evil); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(content_type,'') FROM security_block_pages WHERE id=101`).Scan(&good); err != nil {
		t.Fatal(err)
	}
	if evil != "text/html; charset=utf-8" {
		t.Fatalf("非法 content_type=%q, want 归一 text/html; charset=utf-8", evil)
	}
	if good != "application/json; charset=utf-8" {
		t.Fatalf("合法 content_type=%q, want 原样保留 application/json; charset=utf-8", good)
	}
}

func TestUpdateSecurityPolicy_auditDeltaCoversTypeAndTrustDetection(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	router := newSecurityRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, trust_detection, ip_whitelist_enabled, ip_whitelist, geoip_mode)
		VALUES ('类型信任策略', 'off', 1, 'stage0', 1, 1, '["::1"]', 'off')`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()
	readDetail := func() string {
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatal(err)
		}
		return detail
	}

	// When：单独翻转 trust_detection（真实行为变化：直通↔保留检测）
	r := putJSON(t, router, fmt.Sprintf("/security/policies/%d", policyID), map[string]any{"trust_detection": false})
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", r.Code, r.Body.String())
	}

	// Then：delta 记录该列（不得落「（无字段变化）」虚假审计）
	d := readDetail()
	if !strings.Contains(d, "信任检测：true→false") {
		t.Fatalf("detail=%q, want 含 信任检测：true→false（delta 漏列=虚假审计）", d)
	}
	if strings.Contains(d, "无字段变化") {
		t.Fatalf("真实变更不得落「（无字段变化）」: %q", d)
	}
}

// UPDATE 列集合 ↔ delta 字段集合静态对照（防「加列忘加 delta」复发）：
// AST 枚举 add* 调用、完整 query += SET 字面量、delta* 实参与拦截页裸分支；
// 两集合必须全等（policy_type/trust_detection 为既有豁免转正项，断言它们
// 在场即锁住缺口），updated_by 操作者元数据按理由显式豁免。
func TestSecurityPolicyDeltaCoversAllUpdateColumns(t *testing.T) {
	// When：解析 security.go 中 UPDATE 写列与 delta 覆盖列
	updateCols, deltaCols := securityPolicyUpdateAndDeltaColumns(t)

	for _, col := range []string{"policy_type", "trust_detection"} {
		if !updateCols[col] {
			t.Fatalf("%s 不在 UPDATE 列集合（测试本身失效）", col)
		}
		if !deltaCols[col] {
			t.Fatalf("%s 在 UPDATE 但不在 delta 覆盖集——「加列忘加 delta」复发", col)
		}
	}
	// 在 UPDATE 列集内（防「删掉 delta 测试不报警」盲区）。
	for col := range updateCols {
		if !deltaCols[col] {
			t.Fatalf("UPDATE 列 %s 缺 delta 覆盖", col)
		}
	}
	for col := range deltaCols {
		if !updateCols[col] {
			t.Fatalf("delta 列 %s 不在 UPDATE 列集合（delta 被删或写列形态变更测试须同步）", col)
		}
	}
}

// delta 覆盖集合 = 同函数体内 delta* 调用实参里的 stored.<Field>；
// UPDATE 集合 = add* 首参列名 + query += 的完整 SET 字面量。AST 锚定调用
// 与赋值节点，不受缩进/嵌套括号影响；addJSON 等新 helper 也不会与
// deltaJSON 一起从两侧静默漏掉。updated_by 是每次写入都刷新的操作者
// 元数据，不属于用户配置值，故显式豁免 delta 对账。
func securityPolicyUpdateAndDeltaColumns(t *testing.T) (updateCols, deltaCols map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "security.go", nil, 0)
	if err != nil {
		t.Fatalf("parse security.go: %v", err)
	}
	var updateFn *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "UpdateSecurityPolicy" {
			updateFn = fn
			break
		}
	}
	if updateFn == nil || updateFn.Body == nil {
		t.Fatal("UpdateSecurityPolicy 函数体未找到")
	}

	updateCols = map[string]bool{}
	deltaCols = map[string]bool{}
	metadataExemptions := map[string]string{
		"updated_by": "操作者元数据每次更新统一写入，不是需要记入变更 delta 的配置值",
	}
	metadataSeen := map[string]int{}
	addUpdateColumn := func(column string) {
		if _, exempt := metadataExemptions[column]; exempt {
			metadataSeen[column]++
			return
		}
		updateCols[column] = true
	}
	var stringLiteral func(ast.Expr) (string, bool)
	stringLiteral = func(expr ast.Expr) (string, bool) {
		switch value := expr.(type) {
		case *ast.BasicLit:
			if value.Kind != token.STRING {
				return "", false
			}
			text, err := strconv.Unquote(value.Value)
			return text, err == nil
		case *ast.BinaryExpr:
			if value.Op != token.ADD {
				return "", false
			}
			left, lok := stringLiteral(value.X)
			right, rok := stringLiteral(value.Y)
			return left + right, lok && rok
		default:
			return "", false
		}
	}
	sprintfLiteral := func(expr ast.Expr) (string, bool) {
		call, ok := expr.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return "", false
		}
		function, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || function.Sel.Name != "Sprintf" {
			return "", false
		}
		pkg, ok := function.X.(*ast.Ident)
		if !ok || pkg.Name != "fmt" {
			return "", false
		}
		format, ok := stringLiteral(call.Args[0])
		if !ok {
			return "", false
		}
		values := make([]any, 0, len(call.Args)-1)
		for _, arg := range call.Args[1:] {
			value, ok := stringLiteral(arg)
			if !ok {
				return "", false
			}
			values = append(values, value)
		}
		return fmt.Sprintf(format, values...), true
	}
	columnName := regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
	columnAssignment := regexp.MustCompile(`([a-z_][a-z0-9_]*)\s*=`)
	whereClause := regexp.MustCompile(`(?i)\bWHERE\b`)
	storedDeltaField := func(expr ast.Expr) string {
		comparison, ok := expr.(*ast.BinaryExpr)
		if !ok || comparison.Op != token.NEQ {
			return ""
		}
		for _, sides := range [][2]ast.Expr{{comparison.X, comparison.Y}, {comparison.Y, comparison.X}} {
			star, ok := sides[0].(*ast.StarExpr)
			if !ok {
				continue
			}
			request, ok := star.X.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			requestBase, ok := request.X.(*ast.Ident)
			if !ok || requestBase.Name != "req" {
				continue
			}
			stored, ok := sides[1].(*ast.SelectorExpr)
			if !ok {
				continue
			}
			storedBase, ok := stored.X.(*ast.Ident)
			if ok && storedBase.Name == "stored" {
				return stored.Sel.Name
			}
		}
		return ""
	}

	ast.Inspect(updateFn.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.AssignStmt:
			if typed.Tok != token.ADD_ASSIGN || len(typed.Lhs) != 1 || len(typed.Rhs) != 1 {
				return true
			}
			lhs, ok := typed.Lhs[0].(*ast.Ident)
			if !ok || lhs.Name != "query" {
				return true
			}
			text, ok := stringLiteral(typed.Rhs[0])
			if !ok {
				text, ok = sprintfLiteral(typed.Rhs[0])
			}
			if !ok {
				// add* helper 内的 query += fmt.Sprintf(..., field) 不是具体列；
				// 具体列由下方每个 add* 调用点收集。
				return true
			}
			if where := whereClause.FindStringIndex(text); where != nil {
				text = text[:where[0]]
			}
			for _, match := range columnAssignment.FindAllStringSubmatch(text, -1) {
				addUpdateColumn(match[1])
			}
		case *ast.CallExpr:
			name, ok := typed.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case strings.HasPrefix(name.Name, "add"):
				if len(typed.Args) == 0 {
					t.Fatalf("%s 缺少列名首参 @ %s", name.Name, fset.Position(typed.Pos()))
				}
				column, ok := stringLiteral(typed.Args[0])
				if !ok || !columnName.MatchString(column) {
					t.Fatalf("%s 首参必须是列名字面量 @ %s", name.Name, fset.Position(typed.Pos()))
				}
				addUpdateColumn(column)
			case strings.HasPrefix(name.Name, "delta"):
				for _, arg := range typed.Args {
					ast.Inspect(arg, func(argNode ast.Node) bool {
						selector, ok := argNode.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						base, ok := selector.X.(*ast.Ident)
						if ok && base.Name == "stored" {
							deltaCols[fieldToColumn(selector.Sel.Name)] = true
						}
						return true
					})
				}
			}
		case *ast.IfStmt:
			ast.Inspect(typed.Cond, func(condNode ast.Node) bool {
				expr, ok := condNode.(ast.Expr)
				if field := storedDeltaField(expr); ok && field != "" {
					deltaCols[fieldToColumn(field)] = true
				}
				return true
			})
		}
		return true
	})
	for column, reason := range metadataExemptions {
		if metadataSeen[column] == 0 {
			t.Fatalf("豁免列 %s 已不在 UPDATE 字面量中，请删除腐化豁免（原理由：%s）", column, reason)
		}
	}
	if len(updateCols) < 20 || len(deltaCols) < 20 {
		t.Fatalf("UPDATE/delta 基线列数异常：%d/%d，want 均 >=20（AST 对账不得零命中）", len(updateCols), len(deltaCols))
	}
	return updateCols, deltaCols
}

func fieldToColumn(field string) string {
	field = strings.ReplaceAll(field, "GeoIP", "Geoip")
	field = strings.ReplaceAll(field, "CIDR", "Cidr")
	field = strings.ReplaceAll(field, "CRS", "Crs")
	field = strings.ReplaceAll(field, "RPS", "Rps")
	field = strings.ReplaceAll(field, "ACL", "Acl")
	field = strings.ReplaceAll(field, "WAF", "Waf")
	field = strings.ReplaceAll(field, "ID", "Id")
	field = strings.ReplaceAll(field, "IP", "Ip")
	var b strings.Builder
	for i, r := range field {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

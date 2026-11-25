package db

import (
	"bytes"
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// C-发现1: migrateAuditVocabulary 是「旧词条→当前标准」的唯一转换点，此前
// 无直接测试——映射表写错会在升级时把存量正确行改坏且无测试变红。本测试用
// 每条映射的旧值各造一行验证全量转换、联动条目的双条件边界与幂等性。

// openVocabularyTestAuditDB 建一个仅含 audit_log 表的临时审计库并挂到 AuditDB。
func openVocabularyTestAuditDB(t *testing.T) *sql.DB {
	t.Helper()
	auditDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit database: %v", err)
	}
	t.Cleanup(func() { _ = auditDB.Close() })
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100),
		action VARCHAR(50) NOT NULL,
		resource VARCHAR(100),
		detail TEXT, detail_key TEXT, detail_params TEXT,
		ip_address VARCHAR(45),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create audit_log table: %v", err)
	}
	oldAuditDB := AuditDB
	AuditDB = auditDB
	t.Cleanup(func() { AuditDB = oldAuditDB })
	return auditDB
}

func auditVocabularySnapshot(t *testing.T, auditDB *sql.DB) [][2]string {
	t.Helper()
	rows, err := auditDB.Query("SELECT action, resource FROM audit_log ORDER BY id")
	if err != nil {
		t.Fatalf("snapshot audit rows: %v", err)
	}
	defer rows.Close()
	var snapshot [][2]string
	for rows.Next() {
		var pair [2]string
		if err := rows.Scan(&pair[0], &pair[1]); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		snapshot = append(snapshot, pair)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit rows: %v", err)
	}
	return snapshot
}

func TestMigrateAuditVocabulary_convertsEveryLegacyEntry(t *testing.T) {
	// Given：每条映射的旧值各造一行。动作改名行用中性对象「留存对象」、对象改名
	// 行用中性动作「留存操作」（均不匹配任何映射的另一侧条件），联动行两侧都用
	// 旧值。另造三行负面对照：只匹配联动条件一侧的行与完全无关的行。
	auditDB := openVocabularyTestAuditDB(t)
	type expectation struct {
		action, resource string
	}
	expected := make([]expectation, 0, len(auditVocabularyRenames))
	insert := func(action, resource string) {
		t.Helper()
		if _, err := auditDB.Exec("INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('system', ?, ?, '', '')", action, resource); err != nil {
			t.Fatalf("seed audit row (%q,%q): %v", action, resource, err)
		}
	}
	for _, r := range auditVocabularyRenames {
		action, resource := r.oldAction, r.oldResource
		if action == "" {
			action = "留存操作"
		}
		if resource == "" {
			resource = "留存对象"
		}
		insert(action, resource)
		wantAction, wantResource := action, resource
		if r.newAction != "" {
			wantAction = r.newAction
		}
		if r.newResource != "" {
			wantResource = r.newResource
		}
		expected = append(expected, expectation{wantAction, wantResource})
	}
	// 负面对照：动作命中但对象不符的联动行、完全无关行，都必须原样保留。
	untouched := []expectation{
		{"重载", "负载规则"},
		{"重载失败", "负载规则"},
		{"清理证书指纹", "其他对象"},
		{"无关操作", "无关对象"},
	}
	for _, u := range untouched {
		insert(u.action, u.resource)
	}

	// When
	migrateAuditVocabulary()

	// Then：旧值行全部转换为新值，负面对照行原样保留
	got := auditVocabularySnapshot(t, auditDB)
	want := append(append([]expectation{}, expected...), untouched...)
	if len(got) != len(want) {
		t.Fatalf("audit rows=%d, want %d", len(got), len(want))
	}
	for i, pair := range got {
		if pair[0] != want[i].action || pair[1] != want[i].resource {
			t.Fatalf("row %d = (%q,%q), want (%q,%q)", i+1, pair[0], pair[1], want[i].action, want[i].resource)
		}
	}

	// And 幂等：重跑后全表快照不变（旧值已不存在，零命中）
	before := got
	migrateAuditVocabulary()
	after := auditVocabularySnapshot(t, auditDB)
	if len(after) != len(before) {
		t.Fatalf("second run row count=%d, want %d", len(after), len(before))
	}
	for i := range before {
		if after[i] != before[i] {
			t.Fatalf("second run changed row %d: (%q,%q) -> (%q,%q)（迁移须幂等）", i+1, before[i][0], before[i][1], after[i][0], after[i][1])
		}
	}
}

// 归一化此前每次启动无条件执行 30 条 UPDATE（多数零命中
// 仍走全表扫描/无索引 resource 列）。一次性 marker 置位后二次调用必须零写语句
// ——用 PRAGMA query_only 把「试图写」变成可见错误：若仍执行 UPDATE，会打出
// 「audit vocabulary migration failed」日志。
func TestMigrateAuditVocabulary_secondRunIssuesNoUpdate(t *testing.T) {
	// Given：一条链式旧词条，首次归一完成
	auditDB := openVocabularyTestAuditDB(t)
	if _, err := auditDB.Exec("INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('system', '重载', 'Caddy 配置', '', '')"); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	migrateAuditVocabulary()

	var fingerprint string
	if err := auditDB.QueryRow(`SELECT fingerprint FROM audit_migration_state WHERE name='audit_vocabulary_migrated'`).Scan(&fingerprint); err != nil {
		t.Fatalf("read migration marker: %v", err)
	}
	if fingerprint == "" {
		t.Fatalf("marker fingerprint must not be empty")
	}

	// When：把连接切成只读并二次调用
	auditDB.SetMaxOpenConns(1)
	auditDB.SetMaxIdleConns(1)
	if _, err := auditDB.Exec("PRAGMA query_only=1"); err != nil {
		t.Fatalf("set query_only: %v", err)
	}
	var logBuf bytes.Buffer
	oldOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(oldOut)
	migrateAuditVocabulary()

	// Then：零 UPDATE 尝试（否则只读连接报错并被记日志），数据保持归一终态
	if strings.Contains(logBuf.String(), "audit vocabulary migration failed") {
		t.Fatalf("second run attempted writes after marker was set: %s", logBuf.String())
	}
	if _, err := auditDB.Exec("PRAGMA query_only=0"); err != nil {
		t.Fatalf("reset query_only: %v", err)
	}
	got := auditVocabularySnapshot(t, auditDB)
	if len(got) != 1 || got[0] != [2]string{"重载", "Caddy服务"} {
		t.Fatalf("rows=%v, want normalized terminal state", got)
	}
}

// 归一表旧侧的成对字面量判定从 services 测试迁入本包
// （谓词导出已删除）。扫描 internal/ 全部非测试源码的审计写入口调用，action/
// resource 均为字面量且命中归一表旧侧即违规——动态传参不参与（其词条在调用方
// 字面量处已由 services 的词数门扫描）。归一表多为动作作用域条目（重载+
// Caddy配置→Caddy服务），必须成对判定。
// auditWritePoint 是一次审计写入口调用点的字面量对（动态传参不参与——其词条
// 在调用方字面量处由词数门扫描）。
type auditWritePoint struct {
	pos      string
	action   string
	resource string
}

// collectAuditWritePoints 以 AST 遍历 internal/ 非测试源码，收集审计写入口的
// action/resource 字面量参数。
//
// 为什么是 AST：这组契约是「每个审计写点都在用规范
// 词条」「迁移目标存在真实写点」。写点分散在 handlers/services/taskengine 且
// 动态传参不可穷举，行为测试无法覆盖；AST 绑定调用契约（函数名+参数位），不
// 依赖源码文本格式/反引号边界，纯重构不会假红——属 AGENTS.md「只测可观察契约
// …禁止断言源码文本」的登记豁免形态（本行即豁免声明）。迁移表自身所在文件
// （db/audit.go）不参与，避免自证。
func collectAuditWritePoints(t *testing.T) []auditWritePoint {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	// 写入口 → (action 参数下标, resource 参数下标)。
	argIndices := map[string][2]int{
		"RecordAuditLog":                    {1, 2},
		"recordAudit":                       {1, 2},
		"recordSystemAudit":                 {0, 1},
		"recordAuthenticationSecurityAudit": {1, 2},
	}
	literal := func(e ast.Expr) (string, bool) {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}
		if unquoted, err := strconv.Unquote(lit.Value); err == nil {
			return unquoted, true
		}
		return strings.Trim(lit.Value, "\""), true
	}

	points := make([]auditWritePoint, 0)
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if rel == filepath.Join("db", "audit.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			return nil
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
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
			indices, ok := argIndices[name]
			if !ok || indices[1] >= len(call.Args) {
				return true
			}
			action, ok := literal(call.Args[indices[0]])
			if !ok || action == "" {
				return true
			}
			resource, ok := literal(call.Args[indices[1]])
			if !ok || resource == "" {
				return true
			}
			points = append(points, auditWritePoint{
				pos:      fset.Position(call.Pos()).String(),
				action:   action,
				resource: resource,
			})
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk internal: %v", walkErr)
	}
	return points
}

// collectProductionStringLiterals 以 AST 收集 internal/ 非测试源码中的全部字符串
// 字面量（注释天然不参与——AST 不含注释；也不依赖反引号边界/换行/文件归属）。
// 用于「迁移目标必须存在写点」：新值可能经包装函数/映射表间接进入审计写点
// （如 RecordAuditLog("system","校验阻断",resource,…) 的 resource 是动态值、
// ACME配置 经 auditConfigResource 映射），逐个写入口取字面量参数会漏报，
// 所以此契约要求「值在非测试源码中以字面量存在」即可——这是登记的
// AST 形态豁免，替代原实现的全文件字符串包含（注释/日志假绿、纯文本重构假红）。
func collectProductionStringLiterals(t *testing.T) map[string]bool {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	literals := make(map[string]bool)
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if rel == filepath.Join("db", "audit.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			return nil
		}
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if unquoted, err := strconv.Unquote(lit.Value); err == nil {
				literals[unquoted] = true
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk internal: %v", walkErr)
	}
	return literals
}

func TestAuditWritePointsUseCanonicalVocabulary(t *testing.T) {
	isRetired := func(action, resource string) bool {
		for _, r := range auditVocabularyRenames {
			if r.oldAction != "" && r.oldAction != action {
				continue
			}
			if r.oldResource != "" && r.oldResource != resource {
				continue
			}
			return true
		}
		return false
	}
	var violations []string
	for _, point := range collectAuditWritePoints(t) {
		if isRetired(point.action, point.resource) {
			violations = append(violations, point.pos+" ("+strconv.Quote(point.action)+","+strconv.Quote(point.resource)+") 命中归一表旧侧，请改用规范名")
		}
	}
	if len(violations) != 0 {
		t.Fatalf("审计写点使用归一表旧词条:\n%s", strings.Join(violations, "\n"))
	}
}

func TestMigrateAuditVocabulary_convergesChainedRenameInOnePass(t *testing.T) {
	// Given 链式组合行：("重载","Caddy 配置") 须先经对象改名
	// 条目变 ("重载","Caddy配置")、再经联动条目变 ("重载","Caddy服务")——单趟循环
	// 下联动条目已越过，需两次启动才收敛；不动点循环要求单次调用即归一终态。
	auditDB := openVocabularyTestAuditDB(t)
	if _, err := auditDB.Exec("INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('system', '重载', 'Caddy 配置', '', ''), ('system', '重载失败', 'Caddy 配置', '', '')"); err != nil {
		t.Fatalf("seed chained rows: %v", err)
	}

	// When：单次调用
	migrateAuditVocabulary()

	// Then：链式组合一次收敛到终态
	got := auditVocabularySnapshot(t, auditDB)
	want := [][2]string{{"重载", "Caddy服务"}, {"重载失败", "Caddy服务"}}
	if len(got) != len(want) {
		t.Fatalf("audit rows=%d, want %d", len(got), len(want))
	}
	for i, pair := range got {
		if pair != want[i] {
			t.Fatalf("row %d = (%q,%q), want (%q,%q)（链式改名须单次启动收敛）", i+1, pair[0], pair[1], want[i][0], want[i][1])
		}
	}
}

// TestMigrateAuditVocabulary_newValuesHaveWritePoints 防「迁移目标与写点漂移」：
// 每条映射的新值必须在 internal/ 非测试源码中以字面量存在（写点可能经包装
// 函数/映射表间接引用，见 collectProductionStringLiterals 注释），否则迁移会把
// 存量行归并到一个永不产生新事件的幽灵词条。原实现读文件做子串包含
// （注释/日志假绿、文本重构假红），改为 AST 字面量集合。
func TestMigrateAuditVocabulary_newValuesHaveWritePoints(t *testing.T) {
	literals := collectProductionStringLiterals(t)
	seen := map[string]bool{}
	for _, r := range auditVocabularyRenames {
		for _, newValue := range []string{r.newAction, r.newResource} {
			if newValue == "" || seen[newValue] {
				continue
			}
			seen[newValue] = true
			if !literals[newValue] {
				t.Errorf("迁移目标 %q 在 internal/ 非测试源码中无任何字面量使用——迁移会归并到幽灵词条", newValue)
			}
		}
	}
}

// 失败复位：首趟某条 UPDATE 失败、后续趟恢复且已无改动时必须落 marker——
// 否则每次重启都为一次瞬时失败永久重跑全表归一。注入口用一次性触发器：
// RAISE(FAIL) 保留触发器内的哨兵删除（RAISE(ABORT) 会连哨兵一起回滚）。
func TestMigrateAuditVocabulary_marksAfterFailureRecovers(t *testing.T) {
	auditDB := openVocabularyTestAuditDB(t)
	oldRenames := auditVocabularyRenames
	auditVocabularyRenames = []struct {
		oldAction, newAction     string
		oldResource, newResource string
	}{
		{"旧动作甲", "新动作甲", "", ""},
		{"旧动作乙", "新动作乙", "", ""},
	}
	t.Cleanup(func() { auditVocabularyRenames = oldRenames })
	if _, err := auditDB.Exec(`CREATE TABLE fail_once (id INTEGER PRIMARY KEY);
		INSERT INTO fail_once (id) VALUES (1);
		CREATE TRIGGER fail_once_update BEFORE UPDATE ON audit_log
			WHEN OLD.action = '旧动作甲' AND EXISTS (SELECT 1 FROM fail_once)
		BEGIN
			DELETE FROM fail_once;
			SELECT RAISE(FAIL, 'injected one-time failure');
		END;
		INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES
			('system','旧动作甲','留存对象','',''),
			('system','旧动作乙','留存对象','','')`); err != nil {
		t.Fatalf("seed failure injection: %v", err)
	}

	migrateAuditVocabulary()

	// Then 失败已恢复：marker 落位，两行均归一。
	var fingerprint string
	if err := auditDB.QueryRow(`SELECT fingerprint FROM audit_migration_state WHERE name=?`, auditVocabularyMarkerName).Scan(&fingerprint); err != nil {
		t.Fatalf("marker missing after failure recovered: %v", err)
	}
	if fingerprint != auditVocabularyFingerprint() {
		t.Fatalf("marker fingerprint=%q, want current table fingerprint", fingerprint)
	}
	got := auditVocabularySnapshot(t, auditDB)
	want := [][2]string{{"新动作甲", "留存对象"}, {"新动作乙", "留存对象"}}
	if len(got) != len(want) {
		t.Fatalf("audit rows=%d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d = (%q,%q), want (%q,%q)", i+1, got[i][0], got[i][1], want[i][0], want[i][1])
		}
	}
}

// 失败未恢复（同一趟零改动且仍有失败）：不得落 marker，下次启动继续重试。
func TestMigrateAuditVocabulary_keepsMarkerUnsetWhileFailurePersists(t *testing.T) {
	auditDB := openVocabularyTestAuditDB(t)
	oldRenames := auditVocabularyRenames
	auditVocabularyRenames = []struct {
		oldAction, newAction     string
		oldResource, newResource string
	}{
		{"旧动作丙", "新动作丙", "", ""},
	}
	t.Cleanup(func() { auditVocabularyRenames = oldRenames })
	if _, err := auditDB.Exec(`CREATE TRIGGER fail_always BEFORE UPDATE ON audit_log
			WHEN OLD.action = '旧动作丙'
		BEGIN
			SELECT RAISE(ABORT, 'persistent failure');
		END;
		INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES
			('system','旧动作丙','留存对象','','')`); err != nil {
		t.Fatalf("seed persistent failure: %v", err)
	}

	migrateAuditVocabulary()

	var markers int
	if err := auditDB.QueryRow(`SELECT COUNT(*) FROM audit_migration_state WHERE name=?`, auditVocabularyMarkerName).Scan(&markers); err != nil {
		t.Fatalf("read marker table: %v", err)
	}
	if markers != 0 {
		t.Fatalf("marker rows=%d, want 0（失败未恢复不得置位）", markers)
	}
	got := auditVocabularySnapshot(t, auditDB)
	if len(got) != 1 || got[0] != [2]string{"旧动作丙", "留存对象"} {
		t.Fatalf("rows=%v, want unchanged legacy row", got)
	}
}

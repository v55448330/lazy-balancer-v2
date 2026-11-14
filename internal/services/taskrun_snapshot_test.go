package services

// 运行期任务写路径的库句柄单次快照守卫：
//   - taskrun.go 的每个函数只允许取一次 db.DB（`database := db.DB` 后判定与
//     使用同一句柄）——「先判 nil 再用 db.DB」的双读在两次读取之间被置 nil
//     （停止引擎/关库竞态）时直接 panic；
//   - 启动期哨兵自愈与首槽武装是主节点写面：从节点（is_master=0）启动不得改写
//     版本行（从端版本行是主端镜像，本地改写会被快照覆盖或制造假状态）。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// TestTaskRunReadsDBHandleOncePerFunction 单次快照不变量的唯一 AST 守卫
// （表驱动）：taskrun.go 每个函数体内 db.DB 至多一次；角色判定/started_at
// 读取两个关键函数必须恰一次（函数被删除/重命名同样红——守卫对象漂移不得
// 静默空转）。注释中的提及不构成 AST 节点，字符串字面量是 BasicLit 而非
// SelectorExpr，口径即「真实的句柄直读次数」。
func TestTaskRunReadsDBHandleOncePerFunction(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "taskrun.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 taskrun.go: %v", err)
	}
	countDBReads := func(body *ast.BlockStmt) int {
		n := 0
		ast.Inspect(body, func(node ast.Node) bool {
			if sel, ok := node.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "db" && sel.Sel.Name == "DB" {
					n++
				}
			}
			return true
		})
		return n
	}
	// 关键函数必须存在且恰一次快照（原命名版守卫的超集语义并入本表）。
	exactlyOnce := map[string]bool{"updateRunRole": false, "taskRunStartedAt": false}
	checked := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		checked++
		got := countDBReads(fn.Body)
		if got > 1 {
			t.Errorf("%s 内 db.DB 取值 %d 次（判定与使用必须共用 `database := db.DB` 的单次快照，双读在两次读取之间被置 nil 时会 panic）", fn.Name.Name, got)
		}
		if _, critical := exactlyOnce[fn.Name.Name]; critical {
			exactlyOnce[fn.Name.Name] = true
			if got != 1 {
				t.Errorf("%s 体内 db.DB 出现 %d 次（必须恰 1 次：单次快照，判定与使用共用同一句柄）", fn.Name.Name, got)
			}
		}
	}
	if checked == 0 {
		t.Fatal("taskrun.go 无可检查函数——守卫空洞")
	}
	for name, found := range exactlyOnce {
		if !found {
			t.Errorf("taskrun.go 缺少函数 %s——守卫对象漂移，请随重构更新守卫目标", name)
		}
	}
}

// Given 从节点（is_master=0）+ 导入哨兵版本行 + 空 next_update。
// When InitTaskEngine 启动。
// Then 哨兵行不被改写、首槽不被武装（主节点启动路径才做这两件事）。
func TestInitTaskEngine_slaveSkipsSentinelHealAndSlotArming(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })

	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		if _, err := db.DB.Exec(`DELETE FROM ` + table); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.Exec(`INSERT INTO `+table+` (id, version, auto_update, next_update) VALUES (1, ?, 0, '')`, SecurityVersionImportSentinel); err != nil {
			t.Fatalf("seed sentinel row: %v", err)
		}
	}

	InitTaskEngine("", t.TempDir()+"/app.log")

	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		var version, nextUpdate string
		var autoUpdate int
		if err := db.DB.QueryRow(`SELECT version, COALESCE(auto_update,0), COALESCE(next_update,'') FROM `+table+` WHERE id=1`).Scan(&version, &autoUpdate, &nextUpdate); err != nil {
			t.Fatal(err)
		}
		if version != SecurityVersionImportSentinel || autoUpdate != 0 {
			t.Fatalf("%s 被从节点启动路径改写（version=%q auto_update=%d）：从端版本行是主端镜像，本地改写会被快照覆盖", table, version, autoUpdate)
		}
		if nextUpdate != "" {
			t.Fatalf("%s 被从节点启动路径武装了首槽（next_update=%q）", table, nextUpdate)
		}
	}
}

package db

import (
	"strings"
	"testing"
)

func indexExists(t *testing.T, name string) bool {
	t.Helper()
	var n int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&n); err != nil {
		t.Fatalf("query index %s: %v", name, err)
	}
	return n > 0
}

// 迁移停止创建，存量库由迁移 DROP INDEX 回收。
func TestRunMigrations_dropsDeadNodesStatusIndex(t *testing.T) {
	// Given：存量库形态（历史版本创建的死索引仍在）。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status)`); err != nil {
		t.Fatalf("seed legacy index: %v", err)
	}
	if !indexExists(t, "idx_nodes_status") {
		t.Fatal("前置条件失败：死索引未建立")
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then：死索引被删除且不再被任何 DDL/重建路径创建。
	if indexExists(t, "idx_nodes_status") {
		t.Fatal("idx_nodes_status 死索引应在迁移后删除")
	}
}

// RunOverview 的「每任务最新行」查询（id IN (SELECT MAX(id) ... GROUP BY
// task_id)）必须走覆盖索引，不得全表扫描。只断言「索引存在」不足——列序写反
// 改为直接引用生产常量 db.TaskRunsLatestPerTaskQuery（taskengine.RunOverview
// 同一常量消费），不再从生产源文件按反引号切片文本。
func TestRunMigrations_createsTaskRunsLatestIndex(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if !indexExists(t, "idx_task_runs_task_latest") {
		t.Fatal("idx_task_runs_task_latest 必须存在（每任务最新行免全表扫描）")
	}

	plan := queryPlan(t, TaskRunsLatestPerTaskQuery)
	if !strings.Contains(plan, "USING COVERING INDEX idx_task_runs_task_latest") {
		t.Fatalf("RunOverview 查询计划未使用覆盖索引（索引列序/查询形态漂移）:\n%s", plan)
	}
	if strings.Contains(plan, "SCAN task_runs\n") || strings.HasSuffix(plan, "SCAN task_runs") {
		t.Fatalf("RunOverview 查询仍含全表 SCAN task_runs:\n%s", plan)
	}
}

// queryPlan 执行 EXPLAIN QUERY PLAN 并把 detail 列拼成单串。
func queryPlan(t *testing.T, query string) string {
	t.Helper()
	rows, err := DB.Query("EXPLAIN QUERY PLAN " + query)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		lines = append(lines, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate plan rows: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("EXPLAIN QUERY PLAN 无输出")
	}
	return strings.Join(lines, "\n")
}

// 任务监控的证书任务动态行按 COALESCE(updated_at,created_at) DESC 取前 101 行
// （5s 轮询）：排序键是表达式，必须由同形表达式索引承载——没有索引时每轮都要
// 物化 + 全排序，cert_jobs 行数随规则×域名线性增长且无保留期清理。
func TestRunMigrations_createsCertJobsMonitorOrderingIndex(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if !indexExists(t, "idx_cert_jobs_updated_fallback") {
		t.Fatal("idx_cert_jobs_updated_fallback 必须存在（证书任务动态行免全排序）")
	}

	plan := queryPlanWithArgs(t, CertJobsMonitorRowsQuery, 1, 101)
	if !strings.Contains(plan, "idx_cert_jobs_updated_fallback") {
		t.Fatalf("证书任务动态行查询未使用排序索引（表达式漂移）:\n%s", plan)
	}
	if strings.Contains(plan, "TEMP B-TREE FOR ORDER BY") {
		t.Fatalf("证书任务动态行查询仍需临时 B 树排序（索引表达式与 ORDER BY 不一致）:\n%s", plan)
	}
}

// 拦截页引用计数的 stage1/stage3 OR 谓词必须命中两个列索引；只断言存在
// 不足以发现列名或查询形状漂移，故同时钉 EXPLAIN 的 MULTI-INDEX OR 计划。
func TestRunMigrations_createsBlockPageReferenceIndexes(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	for _, name := range []string{"idx_lb_rules_block_page_stage1", "idx_lb_rules_block_page_stage3"} {
		if !indexExists(t, name) {
			t.Errorf("%s 必须存在（拦截页引用计数免全表扫描）", name)
		}
	}

	plan := queryPlanWithArgs(t, `SELECT caddy_id FROM lb_rules WHERE block_page_stage1_id=? OR block_page_stage3_id=?`, 1, 1)
	for _, name := range []string{"idx_lb_rules_block_page_stage1", "idx_lb_rules_block_page_stage3"} {
		if !strings.Contains(plan, name) {
			t.Errorf("拦截页引用查询未使用 %s:\n%s", name, plan)
		}
	}
	if strings.Contains(plan, "SCAN lb_rules") {
		t.Fatalf("拦截页引用查询仍全表扫描:\n%s", plan)
	}
}

// queryPlanWithArgs 执行带绑定参数的 EXPLAIN QUERY PLAN 并把 detail 列拼成单串。
func queryPlanWithArgs(t *testing.T, query string, args ...any) string {
	t.Helper()
	rows, err := DB.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		lines = append(lines, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate plan rows: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("EXPLAIN QUERY PLAN 无输出")
	}
	return strings.Join(lines, "\n")
}

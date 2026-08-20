package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R47 C-发现1: migrateAuditVocabulary 是「旧词条→当前标准」的唯一转换点，此前
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
		detail TEXT,
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

// TestMigrateAuditVocabulary_newValuesHaveWritePoints 防「迁移目标与写点漂移」：
// 每条映射的新值必须作为字面量出现在 internal/ 非测试源码中（即存在真实审计
// 写点），否则迁移会把存量行归并到一个永不产生新事件的幽灵词条。迁移表自身
// 所在文件（db/audit.go）不参与匹配，避免自证。
func TestMigrateAuditVocabulary_newValuesHaveWritePoints(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	var sources []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if rel == filepath.Join("db", "audit.go") {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read %s: %v", path, readErr)
			return nil
		}
		sources = append(sources, string(content))
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	seen := map[string]bool{}
	for _, r := range auditVocabularyRenames {
		for _, newValue := range []string{r.newAction, r.newResource} {
			if newValue == "" || seen[newValue] {
				continue
			}
			seen[newValue] = true
			found := false
			for _, source := range sources {
				if strings.Contains(source, `"`+newValue+`"`) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("迁移目标 %q 在 internal/ 非测试源码中无任何字面量写点——迁移会归并到幽灵词条", newValue)
			}
		}
	}
}

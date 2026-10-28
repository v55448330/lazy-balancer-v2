package handlers

// 锁内复核 upstreams/path_rules → lb_rules 引用：备份未携带规则表时规则保持
// live（初检按锁外 live 视图放行），初检→加锁窗口内删除被引用规则会让写入落成
// 悬挂行。锁内按事务视图重验，命中即 400 点名表/行/规则 ID。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func seedLiveRuleForReferenceRecheck(t *testing.T, ruleID string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES (?,?,'http','ref.example.test',8443,1)`, ruleID, ruleID); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
}

func TestRevalidateImportRuleReferencesCatchesWindowDeletion(t *testing.T) {
	newBackupTestHandlers(t)
	seedLiveRuleForReferenceRecheck(t, "lb_ref")
	// 选中 rules 分类但备份未携带 lb_rules → 规则表保持 live。
	sectionTables, _, ok := configBackupSectionTables([]string{"rules"})
	if !ok {
		t.Fatal("rules 分类必须存在")
	}
	backup := &configBackup{Tables: map[string][]map[string]any{
		"upstreams":  {{"rule_id": "lb_ref", "host": "10.0.0.1", "port": 80, "weight": 1, "enabled": 1}},
		"path_rules": {{"rule_id": "lb_ref", "path": "/api", "match_type": "prefix"}},
	}}

	check := func(t *testing.T) error {
		t.Helper()
		tx, err := db.DB.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		return revalidateImportLiveDependencies(context.Background(), tx, backup, sectionTables)
	}

	// 形状 1（回归）：被引用规则在事务视图内存在 → 放行。
	if err := check(t); err != nil {
		t.Fatalf("规则存在时不应被拒: %v", err)
	}

	// 形状 2：模拟初检→加锁窗口内删除被引用规则 → 400 点名表/行/规则 ID。
	if _, err := db.DB.Exec(`DELETE FROM lb_rules WHERE caddy_id='lb_ref'`); err != nil {
		t.Fatalf("simulate window deletion: %v", err)
	}
	err := check(t)
	if err == nil {
		t.Fatal("窗口内删除被引用规则必须拒绝")
	}
	if !strings.Contains(err.Error(), "upstreams") || !strings.Contains(err.Error(), "第 1 行") || !strings.Contains(err.Error(), "lb_ref") {
		t.Fatalf("err=%q, want 点名 upstreams/行号/规则 ID", err.Error())
	}
}

func TestImportConfigBackup_lockRecheckRejectsUpstreamReferenceAfterWindowDeletion(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	seedLiveRuleForReferenceRecheck(t, "lb_window")
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed current admin: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// Given 备份携带引用 live 规则的 upstreams 行（不含 lb_rules）。
	body := buildBackup(t, backupFixtureOptions{
		Sections: []string{"rules"},
		Tables: map[string][]map[string]any{
			"upstreams": {{"rule_id": "lb_window", "host": "10.0.0.9", "port": 8080, "weight": 1, "enabled": 1}},
		},
		EmptyConfigIfNil: true,
	})
	oldHook := configImportBeforeLock
	configImportBeforeLock = func() {
		// 初检已按锁外 live 视图放行；窗口内删除被引用规则。
		if _, err := db.DB.Exec(`DELETE FROM lb_rules WHERE caddy_id='lb_window'`); err != nil {
			t.Errorf("simulate window deletion: %v", err)
		}
	}
	t.Cleanup(func() { configImportBeforeLock = oldHook })

	// When
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	// Then 400 点名实时数据变化与规则 ID，且不落悬挂行。
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（锁内引用复核）", recorder.Code, recorder.Body.String())
	}
	response := recorder.Body.String()
	if !strings.Contains(response, "实时数据已变化") || !strings.Contains(response, "lb_window") {
		t.Fatalf("body=%s, want 点名实时数据变化与规则 ID", response)
	}
	var dangling int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM upstreams WHERE rule_id='lb_window'`).Scan(&dangling); err != nil {
		t.Fatal(err)
	}
	if dangling != 0 {
		t.Fatalf("窗口内删除规则后仍写入 %d 条悬挂 upstreams", dangling)
	}
}

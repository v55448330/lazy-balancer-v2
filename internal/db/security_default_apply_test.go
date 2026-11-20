package db

import (
	"encoding/json"
	"testing"
)

// ApplyDefaultSecurityPolicies（用户裁定 2026-11-20 第五轮）：默认策略改为
// 按需创建——启动不再自动播种；面板「默认策略」按钮驱动 apply，逐项
// created/exists/rebuilt，脏引用（策略引用的地址列表已删）删除重建。
func TestApplyDefaultSecurityPolicies_firstRunCreatesEmptyLists(t *testing.T) {
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
	items, err := ApplyDefaultSecurityPolicies()
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(items) != 10 {
		t.Fatalf("items=%d want 10 (2 lists + 8 policies)", len(items))
	}
	for _, it := range items {
		if it.Status != "created" {
			t.Fatalf("first run %q status=%q want created", it.Name, it.Status)
		}
	}
	// 地址列表必须空条目（用户裁定：只建列表与引用关系，不填条目）
	for _, name := range []string{"信任名单地址列表", "手动黑名单地址列表"} {
		var entries string
		if err := database.QueryRow(`SELECT entries FROM security_ip_lists WHERE name=? AND system=0`, name).Scan(&entries); err != nil {
			t.Fatalf("read list %s: %v", name, err)
		}
		var arr []any
		if err := json.Unmarshal([]byte(entries), &arr); err != nil || len(arr) != 0 {
			t.Fatalf("list %s entries=%q want empty JSON array", name, entries)
		}
	}
	// 引用一致：信任名单策略 → 信任名单地址列表 id
	var trustListID int64
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='信任名单地址列表'`).Scan(&trustListID); err != nil {
		t.Fatalf("trust list: %v", err)
	}
	var wlRefs string
	if err := database.QueryRow(`SELECT ip_whitelist_refs FROM security_policies WHERE name='信任名单'`).Scan(&wlRefs); err != nil {
		t.Fatalf("trust policy: %v", err)
	}
	if want := "[" + jsonInt(trustListID) + "]"; wlRefs != want {
		t.Fatalf("trust policy refs=%s want %s", wlRefs, want)
	}
}

func TestApplyDefaultSecurityPolicies_secondRunAllExists(t *testing.T) {
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
	if _, err := ApplyDefaultSecurityPolicies(); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	items, err := ApplyDefaultSecurityPolicies()
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if len(items) != 10 {
		t.Fatalf("items=%d want 10", len(items))
	}
	for _, it := range items {
		if it.Status != "exists" {
			t.Fatalf("second run %q status=%q want exists", it.Name, it.Status)
		}
	}
	// 策略计数不膨胀
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE name IN ('信任名单','威胁情报拦截','手动黑名单','自动封禁联动','地域拦截','基础 CC 防护','WAF 请求防护','WAF 响应检测')`).Scan(&n); err != nil || n != 8 {
		t.Fatalf("policies=%d want 8 (err=%v)", n, err)
	}
}

func TestApplyDefaultSecurityPolicies_dirtyRefRebuilds(t *testing.T) {
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
	if _, err := ApplyDefaultSecurityPolicies(); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// 脏数据：删除被引用的信任名单地址列表（模拟创建一半失败/用户删表）
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE name='信任名单地址列表'`); err != nil {
		t.Fatalf("delete trust list: %v", err)
	}
	items, err := ApplyDefaultSecurityPolicies()
	if err != nil {
		t.Fatalf("recovery apply: %v", err)
	}
	byName := map[string]string{}
	for _, it := range items {
		byName[it.Name] = it.Status
	}
	if byName["信任名单地址列表"] != "created" {
		t.Fatalf("recreated list status=%q want created", byName["信任名单地址列表"])
	}
	if byName["信任名单"] != "rebuilt" {
		t.Fatalf("dirty policy status=%q want rebuilt", byName["信任名单"])
	}
	// 重建后引用指向新列表 id
	var newListID int64
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='信任名单地址列表'`).Scan(&newListID); err != nil {
		t.Fatalf("new trust list: %v", err)
	}
	var wlRefs string
	if err := database.QueryRow(`SELECT ip_whitelist_refs FROM security_policies WHERE name='信任名单'`).Scan(&wlRefs); err != nil {
		t.Fatalf("trust policy: %v", err)
	}
	if want := "[" + jsonInt(newListID) + "]"; wlRefs != want {
		t.Fatalf("rebuilt refs=%s want %s", wlRefs, want)
	}
}

func jsonInt(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

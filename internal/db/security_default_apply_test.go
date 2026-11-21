package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
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
	items, err := ApplyDefaultSecurityPolicies(0)
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
	if _, err := ApplyDefaultSecurityPolicies(0); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	items, err := ApplyDefaultSecurityPolicies(0)
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
	if _, err := ApplyDefaultSecurityPolicies(0); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// 脏数据：删除被引用的信任名单地址列表（模拟创建一半失败/用户删表）
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE name='信任名单地址列表'`); err != nil {
		t.Fatalf("delete trust list: %v", err)
	}
	items, err := ApplyDefaultSecurityPolicies(0)
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

// 重建路径必须迁移规则绑定（2026-11-21 用户实测：绑定悬空——删策略重建后
// 绑定仍指向旧 id，渲染层静默跳过，安全链不生成）；apply 同时清理全部悬空
// 绑定（指向已不存在策略的历史行）。
func TestApplyDefaultSecurityPolicies_rebuildMigratesBindings(t *testing.T) {
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
	if _, err := ApplyDefaultSecurityPolicies(0); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	var oldPolicyID int64
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='信任名单'`).Scan(&oldPolicyID); err != nil {
		t.Fatalf("old policy: %v", err)
	}
	// 用户已绑定该策略到一条 http 规则
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_bind_test','bind-test','http','bind.test',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id,rank) VALUES ('lb_bind_test',?,3)`, oldPolicyID); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	// 历史悬空绑定（指向已删除的策略 id）
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_bind_test',99999)`); err != nil {
		t.Fatalf("seed dangling binding: %v", err)
	}
	// 弄脏引用 → 重建
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE name='信任名单地址列表'`); err != nil {
		t.Fatalf("delete trust list: %v", err)
	}
	items, err := ApplyDefaultSecurityPolicies(0)
	if err != nil {
		t.Fatalf("recovery apply: %v", err)
	}
	_ = items
	var newPolicyID int64
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='信任名单'`).Scan(&newPolicyID); err != nil {
		t.Fatalf("new policy: %v", err)
	}
	if newPolicyID == oldPolicyID {
		t.Fatalf("expected rebuild to produce new id")
	}
	// 绑定已迁移到新 id 且 rank 保留
	var rank int
	if err := database.QueryRow(`SELECT rank FROM security_policy_bindings WHERE rule_caddy_id='lb_bind_test' AND policy_id=?`, newPolicyID).Scan(&rank); err != nil {
		t.Fatalf("binding not migrated to new policy id: %v", err)
	}
	if rank != 3 {
		t.Fatalf("migrated binding rank=%d want 3", rank)
	}
	// 悬空绑定被清理
	var dangling int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings b WHERE NOT EXISTS (SELECT 1 FROM security_policies p WHERE p.id=b.policy_id)`).Scan(&dangling); err != nil {
		t.Fatalf("count dangling: %v", err)
	}
	if dangling != 0 {
		t.Fatalf("dangling bindings=%d want 0", dangling)
	}
}

// 重新创建（reset=true）：全部策略删除重建（恢复默认字段值），绑定迁移；
// 地址列表不动（保留用户条目），reset 后全策略 status=rebuilt。
func TestApplyDefaultSecurityPolicies_resetRecreates(t *testing.T) {
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
	if _, err := ApplyDefaultSecurityPolicies(0); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// 用户数据：列表条目 + 策略字段改动 + 绑定
	if _, err := database.Exec(`UPDATE security_ip_lists SET entries='[{"value":"203.0.113.9"}]' WHERE name='手动黑名单地址列表'`); err != nil {
		t.Fatalf("seed list entry: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_policies SET description='用户改过的描述', block_page_id=0 WHERE name='基础 CC 防护'`); err != nil {
		t.Fatalf("modify policy: %v", err)
	}
	var ccID int64
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='基础 CC 防护'`).Scan(&ccID); err != nil {
		t.Fatalf("cc policy: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_reset','reset-test','http','reset.test',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_reset',?)`, ccID); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	items, err := ApplyDefaultSecurityPoliciesReset(0)
	if err != nil {
		t.Fatalf("reset apply: %v", err)
	}
	for _, it := range items {
		if it.Kind == "policy" && it.Status != "rebuilt" {
			t.Fatalf("reset policy %q status=%q want rebuilt", it.Name, it.Status)
		}
	}
	// 策略字段恢复默认（描述还原、滑块页回归 9005），新 id 且绑定迁移
	var desc string
	var pageID int
	var newID int64
	var bindN int
	if err := database.QueryRow(`SELECT id, description, block_page_id FROM security_policies WHERE name='基础 CC 防护'`).Scan(&newID, &desc, &pageID); err != nil {
		t.Fatalf("re-read cc policy: %v", err)
	}
	if strings.Contains(desc, "用户改过") {
		t.Fatalf("reset 未恢复默认描述: %s", desc)
	}
	if pageID != 9005 {
		t.Fatalf("reset block_page_id=%d want 9005", pageID)
	}
	if newID == ccID {
		t.Fatalf("expected new id after reset")
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_reset' AND policy_id=?`, newID).Scan(&bindN); err != nil || bindN != 1 {
		t.Fatalf("binding not migrated after reset (n=%d err=%v)", bindN, err)
	}
	// 地址列表保留用户条目
	var entries string
	if err := database.QueryRow(`SELECT entries FROM security_ip_lists WHERE name='手动黑名单地址列表'`).Scan(&entries); err != nil {
		t.Fatalf("re-read list: %v", err)
	}
	if !strings.Contains(entries, "203.0.113.9") {
		t.Fatalf("reset must not touch address lists (entries=%s)", entries)
	}
}

// 目录 JSON 契约：数组字段恒为 []（null 会让前端展开/取长崩渲染——
// 2026-11-20 用户实测 TypeError: system_list_refs is not iterable）。
func TestGetDefaultSecurityCatalog_noNullArrays(t *testing.T) {
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
	raw, err := json.Marshal(mustDefaultCatalog(t))
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}
	for _, nullField := range []string{`"list_refs":null`, `"system_list_refs":null`} {
		if strings.Contains(string(raw), nullField) {
			t.Fatalf("catalog JSON contains %s——空集须序列化为 [] 而非 null", nullField)
		}
	}
	var cat DefaultSecurityCatalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range cat.Policies {
		if p.ListRefs == nil || p.SystemListRefs == nil {
			t.Fatalf("policy %q refs 为 nil——须空切片", p.Name)
		}
	}
}

// 目录须带实时状态（missing/exists/dirty）与策略内容行——预览态行尾标签
// 「未创建」与展开详情的数据源（2026-11-20 第六轮用户裁定）。
func TestGetDefaultSecurityCatalog_liveStatusAndContent(t *testing.T) {
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
	// 空库：全 missing，且策略内容行非空
	cat := mustDefaultCatalog(t)
	for _, l := range cat.Lists {
		if l.Status != "missing" {
			t.Fatalf("fresh list %s status=%q want missing", l.Name, l.Status)
		}
	}
	for _, p := range cat.Policies {
		if p.Status != "missing" {
			t.Fatalf("fresh policy %s status=%q want missing", p.Name, p.Status)
		}
		if strings.TrimSpace(p.Content) == "" {
			t.Fatalf("policy %s content 为空——展开详情的策略内容行必须有数据", p.Name)
		}
	}
	// apply 后：全 exists；删被引用列表：策略 dirty、列表 missing
	if _, err := ApplyDefaultSecurityPolicies(0); err != nil {
		t.Fatalf("apply: %v", err)
	}
	cat = mustDefaultCatalog(t)
	for _, p := range cat.Policies {
		if p.Status != "exists" {
			t.Fatalf("applied policy %s status=%q want exists", p.Name, p.Status)
		}
	}
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE name='信任名单地址列表'`); err != nil {
		t.Fatalf("delete list: %v", err)
	}
	cat = mustDefaultCatalog(t)
	if findListStatus(cat, "信任名单地址列表") != "missing" {
		t.Fatalf("deleted list status want missing")
	}
	if findPolicyStatus(cat, "信任名单") != "dirty" {
		t.Fatalf("dangling-ref policy status want dirty")
	}
}

func mustDefaultCatalog(t *testing.T) DefaultSecurityCatalog {
	t.Helper()
	cat, err := GetDefaultSecurityCatalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	return cat
}

func findListStatus(cat DefaultSecurityCatalog, name string) string {
	for _, l := range cat.Lists {
		if l.Name == name {
			return l.Status
		}
	}
	return ""
}

func findPolicyStatus(cat DefaultSecurityCatalog, name string) string {
	for _, p := range cat.Policies {
		if p.Name == name {
			return p.Status
		}
	}
	return ""
}

func jsonInt(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ── audit152 SECH-152-03：默认策略身份守卫（按名匹配→按名+is_default_policy）──

// applyDefaultPoliciesFixture 建库并跑迁移，返回 *sql.DB 位置。
func applyDefaultPoliciesFixture(t *testing.T) {
	t.Helper()
	if _, err := DB.Exec("INSERT OR IGNORE INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
}

// 用户自建同名策略不是默认策略：apply 不得删除/复用/改写它，而是照常创建
// 默认策略行；reset 只删 is_default_policy=1 行。
func TestApplyDefaultSecurityPolicies_userSameNamePolicyNotTouched(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)

	if _, err := database.Exec(`INSERT INTO security_policies (name,description,mode,policy_type) VALUES ('信任名单','用户自建同名策略','blocking','stage1')`); err != nil {
		t.Fatalf("seed user policy: %v", err)
	}
	var userID int64
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='信任名单'`).Scan(&userID); err != nil {
		t.Fatalf("read user policy: %v", err)
	}
	// 目录：同名非默认行不得冒充 exists。
	if status := findPolicyStatus(mustDefaultCatalog(t), "信任名单"); status != "missing" {
		t.Fatalf("catalog status of user same-name policy=%q want missing", status)
	}

	items, err := ApplyDefaultSecurityPolicies(0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	statusByName := map[string]string{}
	for _, it := range items {
		if it.Kind == "policy" {
			statusByName[it.Name] = it.Status
		}
	}
	if statusByName["信任名单"] != "created" {
		t.Fatalf("default policy status=%q want created（同名用户行不是默认策略）", statusByName["信任名单"])
	}
	var desc string
	if err := database.QueryRow(`SELECT description FROM security_policies WHERE id=?`, userID).Scan(&desc); err != nil || desc != "用户自建同名策略" {
		t.Fatalf("apply 改写了用户同名策略: desc=%q err=%v", desc, err)
	}
	var total, defaultRows int
	if err := database.QueryRow(`SELECT COUNT(*), COALESCE(SUM(is_default_policy),0) FROM security_policies WHERE name='信任名单'`).Scan(&total, &defaultRows); err != nil {
		t.Fatalf("count 信任名单: %v", err)
	}
	if total != 2 || defaultRows != 1 {
		t.Fatalf("信任名单 rows=%d default=%d want 2/1（同名用户行 + 默认行）", total, defaultRows)
	}

	// reset 只重建默认行，用户行 id/描述不变。
	if _, err := ApplyDefaultSecurityPoliciesReset(0); err != nil {
		t.Fatalf("reset: %v", err)
	}
	var stillDesc string
	if err := database.QueryRow(`SELECT description FROM security_policies WHERE id=?`, userID).Scan(&stillDesc); err != nil || stillDesc != "用户自建同名策略" {
		t.Fatalf("reset 删/改了用户同名策略: desc=%q err=%v", stillDesc, err)
	}
	var defCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE name='信任名单' AND is_default_policy=1`).Scan(&defCount); err != nil || defCount != 1 {
		t.Fatalf("reset 后默认行=%d err=%v want 1", defCount, err)
	}
}

// 默认策略被用户禁用后：apply 不改写（status=disabled，目录同口径），
// reset 重建恢复（enabled=1）。
func TestApplyDefaultSecurityPolicies_disabledPolicyUntouchedApplyResetRestores(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	if _, err := ApplyDefaultSecurityPolicies(0); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	var id int64
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='地域拦截'`).Scan(&id); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_policies SET enabled=0, description='用户改过' WHERE id=?`, id); err != nil {
		t.Fatalf("disable policy: %v", err)
	}
	if status := findPolicyStatus(mustDefaultCatalog(t), "地域拦截"); status != "disabled" {
		t.Fatalf("catalog status=%q want disabled", status)
	}
	items, err := ApplyDefaultSecurityPolicies(0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var gotID int64
	var gotEnabled int
	var gotDesc string
	if err := database.QueryRow(`SELECT id, enabled, description FROM security_policies WHERE name='地域拦截'`).Scan(&gotID, &gotEnabled, &gotDesc); err != nil {
		t.Fatalf("re-read policy: %v", err)
	}
	if gotID != id || gotEnabled != 0 || gotDesc != "用户改过" {
		t.Fatalf("apply 改写了被禁用的默认策略: id=%d enabled=%d desc=%q", gotID, gotEnabled, gotDesc)
	}
	found := false
	for _, it := range items {
		if it.Kind == "policy" && it.Name == "地域拦截" {
			found = true
			if it.Status != "disabled" {
				t.Fatalf("apply item status=%q want disabled", it.Status)
			}
		}
	}
	if !found {
		t.Fatal("apply 结果缺少 地域拦截 项")
	}
	// reset 恢复启用与默认字段
	if _, err := ApplyDefaultSecurityPoliciesReset(0); err != nil {
		t.Fatalf("reset: %v", err)
	}
	var newID int64
	var newEnabled int
	var newDesc string
	if err := database.QueryRow(`SELECT id, enabled, description FROM security_policies WHERE name='地域拦截'`).Scan(&newID, &newEnabled, &newDesc); err != nil {
		t.Fatalf("re-read after reset: %v", err)
	}
	if newID == id || newEnabled != 1 || newDesc == "用户改过" {
		t.Fatalf("reset 未恢复默认策略: id=%d enabled=%d desc=%q", newID, newEnabled, newDesc)
	}
}

// 单事务贯穿列表+策略+绑定迁移+悬空清理：中途失败必须整体回滚（不得留下
// 半批默认列表/策略）。
func TestApplyDefaultSecurityPolicies_atomicOnMidApplyFailure(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	if _, err := database.Exec(`CREATE TRIGGER fail_default_policy BEFORE INSERT ON security_policies
		WHEN NEW.name='手动黑名单' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	if _, err := ApplyDefaultSecurityPolicies(0); err == nil {
		t.Fatal("apply 中途失败必须返回错误")
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM security_ip_lists WHERE system=0`,
		`SELECT COUNT(*) FROM security_policies`,
	} {
		var n int
		if err := database.QueryRow(query).Scan(&n); err != nil {
			t.Fatalf("count after failed apply: %v", err)
		}
		if n != 0 {
			t.Fatalf("%s=%d, want 0（失败必须整体回滚）", query, n)
		}
	}
	if _, err := database.Exec(`DROP TRIGGER fail_default_policy`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if _, err := ApplyDefaultSecurityPolicies(0); err != nil {
		t.Fatalf("retry apply: %v", err)
	}
}

// 并发两次 apply 不得产生重复默认行（单事务 + 写锁互斥）。
func TestApplyDefaultSecurityPolicies_concurrentNoDuplicates(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = ApplyDefaultSecurityPolicies(0)
		}(i)
	}
	wg.Wait()
	_ = errs // 一个可能因 SQLITE_BUSY 失败——不得因此产生部分/重复行
	var lists, policies, defaultPolicies int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='信任名单地址列表'`).Scan(&lists); err != nil {
		t.Fatalf("count lists: %v", err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies`).Scan(&policies); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE is_default_policy=1`).Scan(&defaultPolicies); err != nil {
		t.Fatalf("count default policies: %v", err)
	}
	if lists != 1 || policies != 8 || defaultPolicies != 8 {
		t.Fatalf("lists=%d policies=%d defaults=%d want 1/8/8 (errs=%v)", lists, policies, defaultPolicies, errs)
	}
}

// policyRefsValid：空串/空白 refs 视为合法空集（与渲染端
// parseIPListRefsChecked TrimSpace→空 同口径）；畸形 JSON 非法；DB 错上抛。
func TestPolicyRefsValid_blankRefsAreLegalEmpty(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	var pid int64
	if _, err := database.Exec(`INSERT INTO security_policies (name,ip_whitelist_refs,ip_acl_list_refs) VALUES ('blank-refs','  ','')`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='blank-refs'`).Scan(&pid); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	valid, err := policyRefsValid(DB, pid)
	if err != nil || !valid {
		t.Fatalf("blank refs valid=%v err=%v want true/nil", valid, err)
	}
	if _, err := database.Exec(`UPDATE security_policies SET ip_acl_list_refs='{}' WHERE id=?`, pid); err != nil {
		t.Fatalf("make malformed: %v", err)
	}
	valid, err = policyRefsValid(DB, pid)
	if err != nil || valid {
		t.Fatalf("malformed refs valid=%v err=%v want false/nil", valid, err)
	}
	// 不存在的行可判定为非法，不当 DB 错上抛。
	if valid, err := policyRefsValid(DB, 999999); err != nil || valid {
		t.Fatalf("absent policy valid=%v err=%v want false/nil", valid, err)
	}
}

// 存量默认策略（is_default_policy 列引入前创建）按「[默认规则] 描述前缀 +
// 种子名」回填标记；用户同名但无前缀行不标记。
func TestBackfillDefaultPolicyMarkers_marksOnlySeedDescPrefix(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	if _, err := database.Exec(`INSERT INTO security_policies (name,description,is_default_policy) VALUES ('信任名单','[默认规则] 引用「信任名单地址列表」','0')`); err != nil {
		t.Fatalf("seed legacy default: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (name,description,is_default_policy) VALUES ('威胁情报拦截','用户自建','0')`); err != nil {
		t.Fatalf("seed user policy: %v", err)
	}
	if err := backfillDefaultPolicyMarkers(); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	var legacyMarked, userMarked int
	if err := database.QueryRow(`SELECT is_default_policy FROM security_policies WHERE name='信任名单'`).Scan(&legacyMarked); err != nil {
		t.Fatalf("read legacy: %v", err)
	}
	if err := database.QueryRow(`SELECT is_default_policy FROM security_policies WHERE name='威胁情报拦截'`).Scan(&userMarked); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if legacyMarked != 1 || userMarked != 0 {
		t.Fatalf("legacy=%d user=%d want 1/0", legacyMarked, userMarked)
	}
}

// 种子契约（SVC-152-02/03/07）：CRS 组剔除基础设施组 49/59、组数文案与列表
// 一致；CC 种子启用会话异常检测；sys: 引用取单源名单名。
func TestDefaultPolicySeeds_contract(t *testing.T) {
	threatNames := ThreatSystemLists()
	threatRefs := ThreatSystemListRefKeys()
	if len(threatRefs) != len(threatNames) {
		t.Fatalf("threat refs=%d names=%d", len(threatRefs), len(threatNames))
	}
	for i, ref := range threatRefs {
		if want := "sys:" + threatNames[i].Name; ref != want {
			t.Fatalf("threat ref[%d]=%q want %q", i, ref, want)
		}
	}
	var threatSeed, ccSeed, reqCRS, respCRS *defaultPolicySeed
	for i := range defaultPolicySeeds {
		sd := &defaultPolicySeeds[i]
		switch sd.name {
		case "威胁情报拦截":
			threatSeed = sd
		case "基础 CC 防护":
			ccSeed = sd
		case "WAF 请求防护":
			reqCRS = sd
		case "WAF 响应检测":
			respCRS = sd
		}
	}
	if threatSeed == nil || ccSeed == nil || reqCRS == nil || respCRS == nil {
		t.Fatal("默认策略种子缺失")
	}
	if strings.Join(threatSeed.ipACLRefKeys, ",") != strings.Join(threatRefs, ",") {
		t.Fatalf("威胁情报策略 refs=%v want 单源 %v", threatSeed.ipACLRefKeys, threatRefs)
	}
	for _, ref := range threatSeed.ipACLRefKeys {
		if !strings.HasPrefix(ref, "sys:") {
			t.Fatalf("威胁情报引用缺 sys: 前缀: %q", ref)
		}
	}
	autobanRef := "sys:" + AutobanPresetListName
	foundAutoban := false
	for _, sd := range defaultPolicySeeds {
		for _, ref := range sd.ipACLRefKeys {
			if ref == autobanRef {
				foundAutoban = true
			}
		}
	}
	if !foundAutoban {
		t.Fatalf("自动封禁联动策略缺少单源引用 %q", autobanRef)
	}
	if ccSeed.ccSessionAnomaly != 1 {
		t.Fatalf("基础 CC 防护 ccSessionAnomaly=%d want 1（文案宣称多 UA 触发）", ccSeed.ccSessionAnomaly)
	}
	if ccSeed.ccSessionUAThreshold != DefaultCCSessionUAThreshold {
		t.Fatalf("CC UA threshold=%d want %d", ccSeed.ccSessionUAThreshold, DefaultCCSessionUAThreshold)
	}
	for _, sd := range []*defaultPolicySeed{reqCRS, respCRS} {
		var groups []string
		if err := json.Unmarshal([]byte(sd.crsGroups), &groups); err != nil {
			t.Fatalf("%s crs groups: %v", sd.name, err)
		}
		for _, g := range groups {
			if g == "49" || g == "59" {
				t.Fatalf("%s 选组含基础设施组 %s（渲染/写侧已剥离，种子不得再宣称）", sd.name, g)
			}
		}
	}
	var reqGroups, respGroups []string
	if err := json.Unmarshal([]byte(reqCRS.crsGroups), &reqGroups); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(respCRS.crsGroups), &respGroups); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("CRS 请求方向 %d 组", len(reqGroups)); !strings.Contains(reqCRS.content, want) {
		t.Fatalf("请求方向文案未与组数对齐: %q want 含 %q", reqCRS.content, want)
	}
	if want := fmt.Sprintf("响应方向 %d 组", len(respGroups)); !strings.Contains(respCRS.content, want) {
		t.Fatalf("响应方向文案未与组数对齐: %q want 含 %q", respCRS.content, want)
	}
}

// global_config.cc_* 五列是零消费退役列：fresh 库不得补建，存量库启动删除。
func TestGlobalConfigCCColumns_retired(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	for _, column := range []string{"cc_detect_enabled", "cc_rps_limit", "cc_rps_window", "cc_4xx_ratio", "cc_session_anomaly"} {
		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name=?`, column).Scan(&n); err != nil {
			t.Fatalf("pragma %s: %v", column, err)
		}
		if n != 0 {
			t.Fatalf("退役列 global_config.%s 仍存在", column)
		}
	}
	// 存量库形态：人工补回列后启动迁移必须删除。
	if _, err := database.Exec(`ALTER TABLE global_config ADD COLUMN cc_rps_limit INTEGER NOT NULL DEFAULT 40`); err != nil {
		t.Fatalf("simulate legacy column: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='cc_rps_limit'`).Scan(&n); err != nil {
		t.Fatalf("pragma: %v", err)
	}
	if n != 0 {
		t.Fatal("存量 global_config.cc_rps_limit 未按 deadColumnDrops 删除")
	}
}

// 旧备份恢复形态（行存在但 is_default_policy=0、描述带种子前缀）：apply
// 事务内先补标——按 exists 复用而非重复创建同名默认策略。
func TestApplyDefaultSecurityPolicies_legacyRowHealedInTx(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	// 直接构造「列已有、标记为 0、描述为种子前缀」的默认行（备份恢复形态）。
	if _, err := database.Exec(`INSERT INTO security_policies (name,description,mode,policy_type) VALUES ('信任名单','[默认规则] 引用「信任名单地址列表」，名单内 IP 跳过全部安全阶段','off','stage0')`); err != nil {
		t.Fatalf("seed legacy default: %v", err)
	}
	items, err := ApplyDefaultSecurityPolicies(0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	for _, it := range items {
		if it.Kind == "policy" && it.Name == "信任名单" {
			if it.Status != "exists" {
				t.Fatalf("legacy default status=%q want exists（同事务补标后复用）", it.Status)
			}
		}
	}
	var total, marked int
	if err := database.QueryRow(`SELECT COUNT(*), COALESCE(SUM(is_default_policy),0) FROM security_policies WHERE name='信任名单'`).Scan(&total, &marked); err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 1 || marked != 1 {
		t.Fatalf("rows=%d marked=%d want 1/1（不得重复创建）", total, marked)
	}
}

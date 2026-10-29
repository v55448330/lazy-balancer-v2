package services

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func seedIPList(t *testing.T, name, entriesJSON string) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES (?, ?)`, name, entriesJSON)
	if err != nil {
		t.Fatalf("seed ip list %s: %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestExpandPolicyIPRefs_mergeDedupInlineFirst(t *testing.T) {
	p := &models.SecurityPolicy{
		IPACLList:       `["1.2.3.4","10.0.0.0/8"]`,
		IPACLListRefs:   `[1]`,
		IPWhitelist:     json.RawMessage(`["198.51.100.1"]`),
		IPWhitelistRefs: `[2]`,
	}
	lists := map[int64][]string{
		1: {"10.0.0.0/8", "192.0.2.1"},
		2: {"198.51.100.1", "203.0.113.0/24"},
	}
	exp := expandPolicyIPRefs(p, lists)

	// 合并即聚合——输出为聚合规范形（排序、兄弟归并、覆盖剔除），
	// 匹配集合与旧 inline-first 去重口径逐点等价（1.2.3.4 与 10/8、192.0.2.1
	// 互不覆盖，条数不变仅排序变化）。
	wantACL := []string{"1.2.3.4/32", "10.0.0.0/8", "192.0.2.1/32"}
	if !reflect.DeepEqual(exp.ACLList, wantACL) {
		t.Fatalf("ACLList=%v, want %v (aggregated canonical order)", exp.ACLList, wantACL)
	}
	wantWL := []string{"198.51.100.1/32", "203.0.113.0/24"}
	if !reflect.DeepEqual(exp.Whitelist, wantWL) {
		t.Fatalf("Whitelist=%v, want %v", exp.Whitelist, wantWL)
	}
}

func TestExpandPolicyIPRefs_missingAndMalformedRefsSkipped(t *testing.T) {
	base := &models.SecurityPolicy{IPACLList: `["1.2.3.4"]`}
	cases := []struct {
		name string
		refs string
	}{
		{"missing id in map", "[99]"},
		{"malformed json", "not-json"},
		{"wrong element type", `["1"]`},
		{"empty refs", "[]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := *base
			p.IPACLListRefs = tc.refs
			exp := expandPolicyIPRefs(&p, map[int64][]string{})
			if len(exp.ACLList) != 1 || exp.ACLList[0] != "1.2.3.4/32" {
				t.Fatalf("ACLList=%v, want inline-only [1.2.3.4]", exp.ACLList)
			}
		})
	}
}

func TestExpandPolicyIPRefs_nilMapFallsBackToInline(t *testing.T) {
	p := &models.SecurityPolicy{
		IPACLList:       `["1.2.3.4"]`,
		IPACLListRefs:   "[1]",
		IPWhitelist:     json.RawMessage(`[]`),
		IPWhitelistRefs: "[1]",
	}
	exp := expandPolicyIPRefs(p, nil)
	if len(exp.ACLList) != 1 || exp.ACLList[0] != "1.2.3.4/32" {
		t.Fatalf("ACLList=%v, want inline-only", exp.ACLList)
	}
	if len(exp.Whitelist) != 0 {
		t.Fatalf("Whitelist=%v, want empty", exp.Whitelist)
	}
}

func TestLoadIPListEntriesByID_valuesOnlyAndMissingSkipped(t *testing.T) {
	newClusterTestService(t)
	idA := seedIPList(t, "list-a", `[{"value":"10.0.0.0/8","remark":"内网"},{"value":"192.0.2.1","remark":""}]`)
	idB := seedIPList(t, "list-b", `not-json`)
	seedIPList(t, "list-c", `[]`)

	got, err := LoadIPListEntriesByID([]int64{idA, idB, 9999})
	if err != nil {
		t.Fatalf("LoadIPListEntriesByID: %v", err)
	}
	entries, ok := got[idA]
	if !ok || len(entries) != 2 || entries[0] != "10.0.0.0/8" || entries[1] != "192.0.2.1" {
		t.Fatalf("list-a entries=%v, want [10.0.0.0/8 192.0.2.1]", entries)
	}
	if _, ok := got[idB]; ok {
		t.Fatal("malformed entries row should be skipped")
	}
	if _, ok := got[int64(9999)]; ok {
		t.Fatal("missing id should be absent")
	}
	empty, err := LoadIPListEntriesByID(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty ids: got %v err=%v, want empty map", empty, err)
	}
}

func TestResolvePolicyIPListRefs_logsDanglingRefs(t *testing.T) {
	newClusterTestService(t)
	p := &models.SecurityPolicy{Name: "悬空引用留痕策略", IPACLList: `["1.2.3.4"]`, IPACLListRefs: `[999]`}
	var logs bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldOutput) })

	resolvePolicyIPListRefs([]*models.SecurityPolicy{p}, nil)
	if !strings.Contains(logs.String(), `引用的 IP 列表(id=999)不存在`) {
		t.Fatalf("dangling ref must be visible in logs: %q", logs.String())
	}
	if p.IPRefMissing {
		t.Fatal("dangling refs retain documented inline-only behavior, not IPRefMissing")
	}
	if got := mergedACLList(p); len(got) != 1 || got[0] != "1.2.3.4/32" {
		t.Fatalf("merged ACL=%v, want inline preserved", got)
	}
}

func TestResolvePolicyIPListRefs_malformedCustomListFailsClosed(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "corrupt-custom", `not-json`)
	p := &models.SecurityPolicy{Name: "畸形名单策略", IPACLList: `["1.2.3.4"]`, IPACLListRefs: fmtListIDs(listID)}

	resolvePolicyIPListRefs([]*models.SecurityPolicy{p}, nil)
	if !p.IPRefMissing {
		t.Fatal("malformed custom entries must mark IPRefMissing and skip narrowed rendering")
	}
	_, failed, _ := loadIPListEntriesVia(db.DB, []int64{listID})
	if !failed[listID] {
		t.Fatalf("malformed custom list must be failedIDs: %v", failed)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE resource='安全策略' AND action='渲染跳过' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read render-skip audit: %v", err)
	}
	if !strings.Contains(detail, "IP 列表(id=") || strings.Contains(detail, "威胁库列表") || strings.Contains(detail, "<nil>") {
		t.Fatalf("failure detail must be kind-neutral and include a real cause: %q", detail)
	}
}

func TestBuildCorazaDirectives_mergedEmission_inlinePlusListEntries(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "merged-src", `[{"value":"10.0.0.0/8","remark":""},{"value":"192.0.2.0/24","remark":""}]`)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_acl_list_refs, enabled) VALUES ('merged', 'off', 'deny', '["1.2.3.4"]', 1, ?, 1)`, fmtListIDs(listID))
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_ip_merged', ?)`, policyID); err != nil {
		t.Fatal(err)
	}

	policy := GetSecurityPolicyForRule("lb_ip_merged")
	if policy == nil {
		t.Fatal("expected bound policy to load")
	}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	// v2.3.x：inline + 列表条目合并进同一 @ipListFast 投影文件（聚合排序）
	if got := readRenderedIPList(t, directives, "-acl"); got != "1.2.3.4/32\n10.0.0.0/8\n192.0.2.0/24\n" {
		t.Fatalf("deny 名单文件须含 inline + list 聚合条目: %q", got)
	}
}

func TestBuildCorazaDirectives_refsOnlyPolicyStillEmits(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "refs-only", `[{"value":"203.0.113.0/24","remark":""}]`)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_acl_list_refs, enabled) VALUES ('refsonly', 'off', 'deny', '[]', 1, ?, 1)`, fmtListIDs(listID))
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_ip_refsonly', ?)`, policyID); err != nil {
		t.Fatal(err)
	}

	policy := GetSecurityPolicyForRule("lb_ip_refsonly")
	if policy == nil {
		t.Fatal("expected bound policy to load")
	}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	if got := readRenderedIPList(t, directives, "-acl"); got != "203.0.113.0/24\n" {
		t.Fatalf("refs-only policy must emit list entries via file: %q", got)
	}
	if !strings.Contains(directives, "SecRuleEngine On") {
		t.Fatalf("refs-only policy must still turn the engine on:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_unresolvedPolicyFallsBackToInline(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:          "off",
		IPACLMode:     "deny",
		IPACLList:     `["1.2.3.4"]`,
		IPACLEnabled:  true,
		IPACLListRefs: "[42]",
	}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	// 未解析引用（refs 指向不存在的列表）回退 inline-only——名单文件恰含 inline 条目
	if got := readRenderedIPList(t, directives, "-acl"); got != "1.2.3.4/32\n" {
		t.Fatalf("inline entries must survive (file=%q), 未解析引用不得追加内容", got)
	}
}

func TestBuildCorazaDirectives_whitelistRefsMergedIntoTrustRule(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "trust-src", `[{"value":"198.51.100.7","remark":""}]`)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, anomaly_threshold, ip_whitelist, ip_whitelist_refs, enabled) VALUES ('trustrefs', 'blocking', 5, '["198.51.100.9"]', ?, 1)`, fmtListIDs(listID))
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_ip_trustrefs', ?)`, policyID); err != nil {
		t.Fatal(err)
	}

	policy := GetSecurityPolicyForRule("lb_ip_trustrefs")
	if policy == nil {
		t.Fatal("expected bound policy to load")
	}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	if !strings.Contains(directives, "id:3,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly") {
		t.Fatalf("trust rule must be emitted (DetectionOnly, 2026-09-15 裁定):\n%s", directives)
	}
	// inline ∪ 引用聚合进同一信任名单文件（排序规范形）
	if got := readRenderedIPList(t, directives, "-trust"); got != "198.51.100.7/32\n198.51.100.9/32\n" {
		t.Fatalf("trust 名单文件须含 inline + list 聚合条目: %q", got)
	}
}

func TestSecurityPolicyHasIPControl_refsOnlyTruthTable(t *testing.T) {
	cases := []struct {
		name string
		p    *models.SecurityPolicy
		want bool
	}{
		{"ACL refs only, enabled", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: "[]", IPACLListRefs: "[3]"}, true},
		{"ACL refs only, toggle off", &models.SecurityPolicy{IPACLMode: "deny", IPACLList: "[]", IPACLListRefs: "[3]"}, false},
		{"whitelist refs only, enabled", &models.SecurityPolicy{IPWhitelistEnabled: true, IPWhitelistRefs: "[3]", MergedWhitelist: []string{"198.51.100.7"}}, true},
		{"whitelist refs only, enabled but unresolved", &models.SecurityPolicy{IPWhitelistEnabled: true, IPWhitelistRefs: "[3]"}, false},
		{"whitelist refs only, toggle off", &models.SecurityPolicy{IPWhitelistRefs: "[3]"}, false},
		// 始终发射收敛（2026-10-15）：ACL 开启即恒发射（allow+空名单
		// 表示拒绝全部）；信任名单（默认 flag 非 opt-in）维持内容门控。
		{"malformed ACL refs", &models.SecurityPolicy{IPACLEnabled: true, IPACLList: "[]", IPACLListRefs: "bad"}, true},
		{"no refs no inline", &models.SecurityPolicy{IPACLEnabled: true, IPACLList: "[]"}, true},
		{"allow mode enabled, empty", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: "[]"}, true},
		{"trust enabled, empty", &models.SecurityPolicy{IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`[]`)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SecurityPolicyHasIPControl(tc.p); got != tc.want {
				t.Fatalf("SecurityPolicyHasIPControl = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildIPPrecheckDirectives_mergedDenyUnion(t *testing.T) {
	newClusterTestService(t)
	listA := seedIPList(t, "deny-a", `[{"value":"10.0.0.0/8","remark":""}]`)
	listB := seedIPList(t, "deny-b", `[{"value":"192.0.2.0/24","remark":""}]`)
	p1 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["1.2.3.4"]`, IPACLListRefs: fmtListIDs(listA)}
	p2 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `[]`, IPACLListRefs: fmtListIDs(listB)}
	resolvePolicyIPListRefs([]*models.SecurityPolicy{p1, p2}, nil)

	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}, 0, "lb_test"))
	if !strings.Contains(directives, "id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END") {
		t.Fatalf("deny union rule missing:\n%s", directives)
	}
	union := readRenderedIPList(t, directives, "u-deny")
	for _, want := range []string{"1.2.3.4/32", "10.0.0.0/8", "192.0.2.0/24"} {
		if !strings.Contains(union, want) {
			t.Fatalf("deny union file must contain %s: %q", want, union)
		}
	}
}

func TestBuildIPPrecheckDirectives_mergedAllowIntersection(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "allow-a", `[{"value":"203.0.113.5","remark":""}]`)
	p1 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["198.51.100.1","203.0.113.5"]`}
	p2 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `[]`, IPACLListRefs: fmtListIDs(listID)}
	resolvePolicyIPListRefs([]*models.SecurityPolicy{p1, p2}, nil)

	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}, 0, "lb_test"))
	if !strings.Contains(directives, "id:7,phase:1,deny,status:403,log,msg:'IP 白名单拒绝',skipAfter:SECURITY_RULES_END") {
		t.Fatalf("allow intersection rule missing:\n%s", directives)
	}
	// 合并集 [198.51.100.1 203.0.113.5] ∩ 合并集 [203.0.113.5] = [203.0.113.5]
	intersection := readRenderedIPList(t, directives, "u-allow")
	if intersection != "203.0.113.5/32\n" {
		t.Fatalf("intersection must be merged(allow list A) ∩ merged(allow list B) = [203.0.113.5/32]: %q", intersection)
	}
	if strings.Contains(intersection, "198.51.100.1") {
		t.Fatalf("198.51.100.1 only in one side must not survive the allow intersection: %q", intersection)
	}
}

func TestGetSecurityPoliciesForRule_resolvesRefsAcrossBatch(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "batch-src", `[{"value":"10.0.0.0/8","remark":""}]`)
	refsJSON := fmtListIDs(listID)
	for _, name := range []string{"batch-1", "batch-2"} {
		res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_acl_list_refs, enabled) VALUES (?, 'off', 'deny', '[]', 1, ?, 1)`, name, refsJSON)
		if err != nil {
			t.Fatalf("seed policy %s: %v", name, err)
		}
		policyID, _ := res.LastInsertId()
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_ip_batch', ?)`, policyID); err != nil {
			t.Fatal(err)
		}
	}

	policies := GetSecurityPoliciesForRule("lb_ip_batch")
	if len(policies) != 2 {
		t.Fatalf("policies=%d, want 2", len(policies))
	}
	for _, p := range policies {
		if len(p.MergedACLList) != 1 || p.MergedACLList[0] != "10.0.0.0/8" {
			t.Fatalf("policy %s MergedACLList=%v, want [10.0.0.0/8]", p.Name, p.MergedACLList)
		}
	}
}

func fmtListIDs(ids ...int64) string {
	raw, _ := json.Marshal(ids)
	return string(raw)
}

// loadIPListEntriesVia 迭代错误驱动桩 ----

// iplistIterFailConnector 让 security_ip_lists 查询「语句执行成功、迭代第一
// 步即失败」——只有循环后检查 rows.Err() 才能发现，否则表现为装载成功但
// 集合缺行（failedIDs 不置位，IPRefMissing 严格模式被绕过）。
type iplistIterFailConnector struct{}

func (iplistIterFailConnector) Connect(context.Context) (driver.Conn, error) {
	return iplistIterFailConn{}, nil
}
func (iplistIterFailConnector) Driver() driver.Driver { return iplistIterFailDriver{} }

type iplistIterFailDriver struct{}

func (iplistIterFailDriver) Open(string) (driver.Conn, error) { return iplistIterFailConn{}, nil }

type iplistIterFailConn struct{}

func (iplistIterFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (iplistIterFailConn) Close() error              { return nil }
func (iplistIterFailConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }
func (iplistIterFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "FROM security_ip_lists") {
		return iterFailRows{cols: []string{"id", "entries", "system", "name"}}, nil
	}
	return zeroColsRows{}, nil
}

type iterFailRows struct{ cols []string }

func (r iterFailRows) Columns() []string       { return r.cols }
func (iterFailRows) Close() error              { return nil }
func (iterFailRows) Next([]driver.Value) error { return errors.New("注入的列表迭代失败") }

type zeroColsRows struct{}

func (zeroColsRows) Columns() []string         { return []string{"c"} }
func (zeroColsRows) Close() error              { return nil }
func (zeroColsRows) Next([]driver.Value) error { return io.EOF }

// 迭代错误必须与查询失败同通道上抛，且整块 id 进 failedIDs
// （fail-closed）——修复前 rows.Err() 未检查，错误被静默吞掉。
func TestLoadIPListEntriesVia_iterationErrorMarksChunkFailed(t *testing.T) {
	broken := sql.OpenDB(iplistIterFailConnector{})
	t.Cleanup(func() { _ = broken.Close() })

	entries, failed, err := loadIPListEntriesVia(broken, []int64{7, 8})
	if err == nil {
		t.Fatal("迭代错误必须上抛错误通道（与查询失败同形）")
	}
	if !failed[7] || !failed[8] {
		t.Fatalf("迭代错误须整块 fail-closed 置位 failedIDs: failed=%v", failed)
	}
	if len(entries) != 0 {
		t.Fatalf("迭代失败轮不得残留部分条目: %v", entries)
	}
}

// 端到端形态：迭代错误下引用该列表的策略必须标记 IPRefMissing
// 跳过渲染（严格模式）——修复前拿到「静默缺内容的合并集」，ACL/信任面
// 静默收窄零留痕。
func TestResolvePolicyIPListRefs_iterationErrorFailsClosed(t *testing.T) {
	newClusterTestService(t)
	p := &models.SecurityPolicy{Name: "iterfail-acl", IPACLEnabled: true, IPACLMode: "deny", IPACLList: "[]", IPACLListRefs: "[7]"}
	broken := sql.OpenDB(iplistIterFailConnector{})
	t.Cleanup(func() { _ = broken.Close() })

	resolvePolicyIPListRefs([]*models.SecurityPolicy{p}, broken)
	if !p.IPRefMissing {
		t.Fatal("迭代错误必须 fail-closed：引用该列表的策略须标记 IPRefMissing 跳过渲染")
	}
}

// 无引用形态（绝大多数策略）同样必须在加载路径一次展开并附加合并集：旧实现
// refIDs 为空即早退，MergedACLList/MergedWhitelist 恒为 nil，发射端每次调用
// mergedWhitelist/mergedACLList 都重跑 json.Unmarshal + aggregateIPEntries
// ——摄取侧按「规则×策略」逐次调用，接收侧信任并集聚合成本随事件吞吐放大。
func TestResolvePolicyIPListRefs_attachesInlineOnlyMergeWithoutRefs(t *testing.T) {
	newClusterTestService(t)
	p := &models.SecurityPolicy{
		ID:           1,
		Name:         "inline-only",
		IPACLEnabled: true,
		IPACLMode:    "deny",
		IPACLList:    `["198.51.100.7"]`,
		IPWhitelist:  json.RawMessage(`["203.0.113.1","203.0.113.0/24"]`),
	}

	resolvePolicyIPListRefs([]*models.SecurityPolicy{p}, nil)

	if p.MergedWhitelist == nil || p.MergedACLList == nil {
		t.Fatalf("无引用形态必须附加合并集（MergedWhitelist=%v MergedACLList=%v）", p.MergedWhitelist, p.MergedACLList)
	}
	// 合并即聚合：203.0.113.1 被 203.0.113.0/24 覆盖，同类兄弟归并。
	if want := []string{"203.0.113.0/24"}; !reflect.DeepEqual(p.MergedWhitelist, want) {
		t.Fatalf("MergedWhitelist=%v, want %v（与 mergedWhitelist 的 inline-only 回退逐字等价）", p.MergedWhitelist, want)
	}
	// 单地址条目在合并时按 /32 规范化（aggregateIPEntries 的 CIDR 归并）。
	if want := []string{"198.51.100.7/32"}; !reflect.DeepEqual(p.MergedACLList, want) {
		t.Fatalf("MergedACLList=%v, want %v", p.MergedACLList, want)
	}
	// 发射端取值零分配：已附加时 mergedWhitelist 直接返回（不得每次重跑解析+聚合）。
	if allocs := testing.AllocsPerRun(50, func() { _ = mergedWhitelist(p) }); allocs != 0 {
		t.Fatalf("mergedWhitelist 每次调用分配=%v, want 0（合并集已附加，不得重跑 json.Unmarshal+聚合）", allocs)
	}
	if allocs := testing.AllocsPerRun(50, func() { _ = mergedACLList(p) }); allocs != 0 {
		t.Fatalf("mergedACLList 每次调用分配=%v, want 0", allocs)
	}
}

// 畸形 refs 静默 fail-open ——

// 全形状：畸形（非 JSON / 错元素类型）/空/合法 + deny/allow 两种 ACL 语义。
// 畸形：留痕且仅保留 inline（行为不变）；空：零告警（未配置引用）；合法：
// refs 条目进入合并集（deny 与 allow 同口径）。
func TestIPListRefs_shapesWarnAndMerge(t *testing.T) {
	_, database := newClusterTestService(t)
	res, err := database.Exec(`INSERT INTO security_ip_lists (name, category, entries, system, created_at, updated_at)
		VALUES ('引用自定义列表', '常规', '[{"value":"203.0.113.0/24"}]', 0, datetime('now'), datetime('now'))`)
	if err != nil {
		t.Fatalf("seed list: %v", err)
	}
	listID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	refs := fmt.Sprintf("[%d]", listID)
	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })
	// 限流隔离：同包先序用例（如 TestExpandPolicyIPRefs_missingAndMalformedRefsSkipped
	// 用 `not-json`）已放行过同一归一化键（auditFailureThrottleKey 把数字统一
	// 成 #，不同策略 id 同键），60s 窗口会抑制本用例的 WARN 断言。推进注入
	// 时钟并清空窗口记录（仅测试缝隙，不改生产限流口径）。
	oldClock := auditFailureLogClock
	auditFailureLogClock = func() time.Time { return time.Now().Add(2 * time.Minute) }
	auditFailureLogMu.Lock()
	auditFailureLogTimes = map[string]time.Time{}
	auditFailureLogMu.Unlock()
	t.Cleanup(func() {
		auditFailureLogClock = oldClock
		auditFailureLogMu.Lock()
		auditFailureLogTimes = map[string]time.Time{}
		auditFailureLogMu.Unlock()
	})

	policies := []*models.SecurityPolicy{
		{ID: 8701, Name: "畸形 JSON", IPACLList: `["198.51.100.0/24"]`, IPACLListRefs: `not-json`},
		{ID: 8702, Name: "错元素类型", IPACLList: `["198.51.100.0/24"]`, IPACLListRefs: `["1"]`},
		{ID: 8703, Name: "空 refs", IPACLList: `["198.51.100.0/24"]`},
		{ID: 8704, Name: "deny 引用", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `[]`, IPACLListRefs: refs},
		{ID: 8705, Name: "allow 引用", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `[]`, IPACLListRefs: refs, IPWhitelistRefs: refs},
	}

	resolvePolicyIPListRefs(policies, nil)

	// 畸形形状：仅保留 inline（不升级 IPRefMissing——整条策略不被跳过）。
	for _, p := range policies[:2] {
		if p.IPRefMissing {
			t.Fatalf("策略 %q 不得因畸形 refs 置 IPRefMissing（放大会跳过 WAF/限流渲染）", p.Name)
		}
		if got := p.MergedACLList; len(got) != 1 || got[0] != "198.51.100.0/24" {
			t.Fatalf("策略 %q 畸形 refs 合并集=%v, want 仅 inline 198.51.100.0/24", p.Name, got)
		}
	}
	if !strings.Contains(logs.String(), "ip_acl_list_refs") || !strings.Contains(logs.String(), "解析失败") {
		t.Fatalf("畸形 refs 必须 WARN 留痕（同一 fail-open 方向的内联畸形已留痕）:\n%s", logs.String())
	}
	// 空形状：不告警。
	logs.Reset()
	resolvePolicyIPListRefs([]*models.SecurityPolicy{{ID: 8706, IPACLList: `["198.51.100.0/24"]`}}, nil)
	if strings.Contains(logs.String(), "解析失败") {
		t.Fatalf("空 refs（未配置引用）不得留痕:\n%s", logs.String())
	}
	// 合法形状：deny / allow 两语义都拿到引用条目；信任面同口径。
	for _, p := range policies[3:] {
		if p.IPRefMissing {
			t.Fatalf("策略 %q 合法 refs 不得置 IPRefMissing", p.Name)
		}
		if got := p.MergedACLList; len(got) != 1 || got[0] != "203.0.113.0/24" {
			t.Fatalf("策略 %q 合法 refs 合并集=%v, want 引用条目 203.0.113.0/24", p.Name, got)
		}
	}
	if got := policies[4].MergedWhitelist; len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("信任面合法 refs 合并集=%v, want 203.0.113.0/24", got)
	}
}

// 同一 tick 内相同来源列的展开结果去重 ——

// 多策略引用同一名单（相同来源列）共享一次性展开；不同 inline 的策略仍各自
// 得到独立合并集（去重不得跨输入串味）。
func TestIPListRefs_identicalColumnsShareExpansion(t *testing.T) {
	_, database := newClusterTestService(t)
	res, err := database.Exec(`INSERT INTO security_ip_lists (name, category, entries, system, created_at, updated_at)
		VALUES ('共享引用名单', '常规', '[{"value":"203.0.113.0/24"}]', 0, datetime('now'), datetime('now'))`)
	if err != nil {
		t.Fatal(err)
	}
	listID, _ := res.LastInsertId()
	refs := fmt.Sprintf("[%d]", listID)

	shared := []*models.SecurityPolicy{
		{ID: 8721, Name: "共享 A", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `[]`, IPACLListRefs: refs},
		{ID: 8722, Name: "共享 B", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `[]`, IPACLListRefs: refs},
		{ID: 8723, Name: "独有 inline", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.0/24"]`, IPACLListRefs: refs},
	}
	resolvePolicyIPListRefs(shared, nil)

	for _, p := range shared[:2] {
		if got := p.MergedACLList; len(got) != 1 || got[0] != "203.0.113.0/24" {
			t.Fatalf("策略 %q 共享展开=%v, want 203.0.113.0/24", p.Name, got)
		}
	}
	if got := shared[2].MergedACLList; len(got) != 2 || got[0] != "198.51.100.0/24" || got[1] != "203.0.113.0/24" {
		t.Fatalf("不同 inline 的策略不得复用他人展开: %v", got)
	}
}

// 文本代际的一次读取内只允许解析一遍：可解析率门与坏行剔除必须共用同一份
// 扫描结果。旧实现在同一批 vals 上分别调用「算比率」与「剔除坏行」，条目被
// 重复解析 2–3 遍（20 万条名单每次渲染多付 1–2 次全量 ParseIPEntry）。
func TestReadThreatIplistPath_parsesTextOncePerRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "threat-ustc.iplist")
	// 无 .fast 同名文件 → 走文本代际；2/3 行合法（≥ threatMinParseRatio）。
	writeTestFile(t, path, "203.0.113.0/24\n198.51.100.7\nnot-an-ip\n")

	threatTextScanRunsForTest.Store(0)
	vals, err := readThreatIplistPath(path)
	if err != nil {
		t.Fatalf("readThreatIplistPath: %v", err)
	}
	if want := []string{"203.0.113.0/24", "198.51.100.7"}; !reflect.DeepEqual(vals, want) {
		t.Fatalf("vals=%v, want %v（不可解析行必须剔除）", vals, want)
	}
	if got := threatTextScanRunsForTest.Load(); got != 3 {
		t.Fatalf("条目解析次数=%d, want 3（一次读取只解析一遍；重复解析说明比率门与坏行剔除各扫一次）", got)
	}
}

// 分批 IN 查询只允许一套实现：渲染装载与摘要存在性判定曾各持一份同构的
// 「切块 + 拼占位符 + 迭代错误捕获」，任一侧修正（如 rows.Err fail-closed）
// 都会单边漂移。两边现在只通过 forEachIPListChunk 分批。
func TestIPListChunking_singleImplementation(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var offenders []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatalf("读取 %s 失败: %v", name, readErr)
		}
		if n := strings.Count(string(data), "start += ipListChunkSize"); n > 0 {
			offenders = append(offenders, fmt.Sprintf("%s(%d)", name, n))
		}
	}
	if len(offenders) != 1 || offenders[0] != "securityiplists.go(1)" {
		t.Fatalf("分批 IN 查询的切块循环散落多份: %v——必须只在 forEachIPListChunk 内出现一次", offenders)
	}
}

// 跨块形态：ipListChunkSize 之外的 id 必须全部装载（分批边界不得漏行），
// 且块内迭代错误按块 fail-closed 并上抛首个错误——两条装载路径共用同一实现，
// 本用例同时覆盖渲染装载与摘要存在性判定。
func TestIPListChunking_crossChunkLoadsAndFailsClosed(t *testing.T) {
	_, database := newClusterTestService(t)
	oldChunk := ipListChunkSize
	ipListChunkSize = 2
	t.Cleanup(func() { ipListChunkSize = oldChunk })

	var ids []int64
	for i := 0; i < 5; i++ {
		res, err := database.Exec(`INSERT INTO security_ip_lists (name, category, entries, system, created_at, updated_at)
			VALUES (?, '常规', ?, 0, datetime('now'), datetime('now'))`, fmt.Sprintf("跨块列表%d", i), fmt.Sprintf(`[{"value":"203.0.113.%d"}]`, i+1))
		if err != nil {
			t.Fatalf("seed list: %v", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	entries, failed, err := loadIPListEntriesVia(database, ids)
	if err != nil {
		t.Fatalf("跨块装载失败: %v", err)
	}
	if len(failed) != 0 {
		t.Fatalf("跨块装载不得有失败块: %v", failed)
	}
	for _, id := range ids {
		if _, ok := entries[id]; !ok {
			t.Fatalf("列表 id=%d 未装载（分批边界漏行）", id)
		}
	}
	presence, failedPresence := loadIPListRefPresenceVia(database, ids)
	if len(failedPresence) != 0 {
		t.Fatalf("摘要存在性判定不得有失败块: %v", failedPresence)
	}
	for _, id := range ids {
		if !presence[id] {
			t.Fatalf("列表 id=%d 在摘要口径必须判为有生效条目", id)
		}
	}
}

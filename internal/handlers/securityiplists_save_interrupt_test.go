package handlers

// 整表保存（PUT /security/ip-lists/:id 携带 entries）新增条目=主动处置钉
//（用户裁定「手动加入任何名单=抹累犯前科+停计数」的整表编辑面）：
//   - new−old 新增差集逐 IP 同事务删除累犯行（identity 经 AutobanEntryIdentity
//     归一）+ AutobanForgetIPs 清计数桶/观察建议——适用所有名单，不只预置；
//   - 元数据-only（不带 entries）与无新增值（原样/仅移除）不触发处置。
// 逐条追加/创建并加入面由 securityiplists_autoban_interrupt_test.go 钉。

import (
	"fmt"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// seedSaveInterruptRecidivism 直插累犯行（identity 恒为归一形态，与 merge
// 记账键同形）。
func seedSaveInterruptRecidivism(t *testing.T, identities ...string) {
	t.Helper()
	for _, id := range identities {
		if _, err := db.DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES (?, 3, '2026-11-15 10:00:00', '24h')`, id); err != nil {
			t.Fatalf("seed recidivism %s: %v", id, err)
		}
	}
}

func countSaveInterruptRecidivism(t *testing.T, identity string) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity=?`, identity).Scan(&n); err != nil {
		t.Fatalf("count recidivism %s: %v", identity, err)
	}
	return n
}

// Given 自定义名单已有条目 A；IP B 有累犯行+计数桶+观察建议。
// When PUT 整表保存 entries=[A,B]（B 为新增）。
// Then 200；B 的累犯行删除、计数桶清零、建议剔除；A 与无关 IP 的记账保留。
func TestUpdateIPList_addedEntryInterruptsRecidivism(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.ResetAutobanCounters()
	const added = "45.33.32.77"
	services.AutobanSeedCounterForTest(added, 5, 3)
	services.AutobanSetSuggestionsForTest([]services.AutobanSuggestion{
		{IP: added, Count: 5},
		{IP: "198.51.100.9", Count: 2},
	})
	t.Cleanup(func() { services.AutobanSetSuggestionsForTest(nil) })
	seedSaveInterruptRecidivism(t, added, "203.0.113.1", "198.51.100.9")
	var listID int64
	if err := db.DB.QueryRow(`INSERT INTO security_ip_lists (name, description, category, entries, system) VALUES ('信任名单-整表', '', '自定义', '[{"value":"203.0.113.1"}]', 0) RETURNING id`).Scan(&listID); err != nil {
		t.Fatalf("create list: %v", err)
	}

	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{
		"entries": `[{"value":"203.0.113.1"},{"value":"45.33.32.77"}]`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if n := countSaveInterruptRecidivism(t, added); n != 0 {
		t.Fatalf("新增 IP 累犯行=%d, want 0（整表保存新增=主动处置，必须抹前科）", n)
	}
	if n := countSaveInterruptRecidivism(t, "203.0.113.1"); n != 1 {
		t.Fatalf("既有 IP 累犯行=%d, want 1（未新增不处置）", n)
	}
	if n := countSaveInterruptRecidivism(t, "198.51.100.9"); n != 1 {
		t.Fatalf("无关 IP 累犯行=%d, want 1", n)
	}
	if got := services.AutobanTrackedIPs(); got != 0 {
		t.Fatalf("tracked_ips=%d, want 0（新增必须清计数桶）", got)
	}
	suggestions := services.AutobanSuggestions()
	if len(suggestions) != 1 || suggestions[0].IP != "198.51.100.9" {
		t.Fatalf("建议列表=%+v, want 仅 198.51.100.9（新增 IP 剔除）", suggestions)
	}
}

// Given 预置名单已有条目 A；IP B 有累犯行+计数桶。
// When PUT 预置名单整表保存 entries=[A,B]。
// Then 与自定义名单同口径：B 的累犯行删除+计数桶清零（手动封禁中断累犯）。
func TestUpdateIPList_presetAddedEntryInterruptsRecidivism(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.ResetAutobanCounters()
	const added = "45.33.32.88"
	services.AutobanSeedCounterForTest(added, 4, 3)
	seedSaveInterruptRecidivism(t, added)
	seedAutobanListEntries(t, `[{"value":"203.0.113.1"}]`)

	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", autobanPresetID(t)), map[string]any{
		"entries": `[{"value":"203.0.113.1"},{"value":"45.33.32.88","remark":"事件处置"}]`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if n := countSaveInterruptRecidivism(t, added); n != 0 {
		t.Fatalf("预置名单新增 IP 累犯行=%d, want 0", n)
	}
	if got := services.AutobanTrackedIPs(); got != 0 {
		t.Fatalf("tracked_ips=%d, want 0", got)
	}
}

// Given IPv6 身份行（/64 归一记账）+同键计数桶。
// When PUT 整表保存新增大写完整形态 IPv6（2606:4700:ABCD:1234:0:0:0:5）。
// Then 累犯行按归一身份删除、计数桶清零（identity 经 AutobanEntryIdentity）。
func TestUpdateIPList_addedIPv6NormalizesIdentity(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.ResetAutobanCounters()
	const identity = "2606:4700:abcd:1234::"
	services.AutobanSeedCounterForTest(identity, 6, 3)
	seedSaveInterruptRecidivism(t, identity)
	var listID int64
	if err := db.DB.QueryRow(`INSERT INTO security_ip_lists (name, description, category, entries, system) VALUES ('黑名单-v6', '', '自定义', '[]', 0) RETURNING id`).Scan(&listID); err != nil {
		t.Fatalf("create list: %v", err)
	}

	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{
		"entries": `[{"value":"2606:4700:ABCD:1234:0:0:0:5"}]`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if n := countSaveInterruptRecidivism(t, identity); n != 0 {
		t.Fatalf("归一身份累犯行=%d, want 0（大写/完整形态必须归一命中）", n)
	}
	if got := services.AutobanTrackedIPs(); got != 0 {
		t.Fatalf("tracked_ips=%d, want 0（/64 归一键清桶）", got)
	}
}

// Given 名单条目 B 有累犯行+计数桶。
// When PUT 仅改描述（不带 entries，元数据-only）。
// Then 200；累犯行与计数桶保留（无处置发生）。
func TestUpdateIPList_metadataOnlyKeepsRecidivism(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.ResetAutobanCounters()
	const ip = "45.33.32.77"
	services.AutobanSeedCounterForTest(ip, 5, 3)
	seedSaveInterruptRecidivism(t, ip)
	var listID int64
	if err := db.DB.QueryRow(`INSERT INTO security_ip_lists (name, description, category, entries, system) VALUES ('名单-元数据', '', '自定义', '[{"value":"45.33.32.77"}]', 0) RETURNING id`).Scan(&listID); err != nil {
		t.Fatalf("create list: %v", err)
	}

	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{
		"description": "仅改描述",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if n := countSaveInterruptRecidivism(t, ip); n != 1 {
		t.Fatalf("元数据-only 后累犯行=%d, want 1（不得触发处置）", n)
	}
	if got := services.AutobanTrackedIPs(); got != 1 {
		t.Fatalf("tracked_ips=%d, want 1（元数据-only 不清桶）", got)
	}
}

// Given 名单条目 [A,B]，B 有累犯行+计数桶。
// When PUT 原样 [A,B]（零新增）→ PUT [A]（仅移除，无新增）。
// Then 两次均 200；B 的累犯行与计数桶保留（自定义名单移除≠处置，
// 无新增值不触发中断；预置名单移除的解封清桶另由差集钉测覆盖）。
// 序不可颠倒：移除后再存 [A,B] 是重新加入=新增处置，语义上应触发中断。
func TestUpdateIPList_noAddedEntriesKeepsRecidivism(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.ResetAutobanCounters()
	const ip = "45.33.32.77"
	services.AutobanSeedCounterForTest(ip, 5, 3)
	seedSaveInterruptRecidivism(t, ip)
	var listID int64
	if err := db.DB.QueryRow(`INSERT INTO security_ip_lists (name, description, category, entries, system) VALUES ('名单-无新增', '', '自定义', '[{"value":"203.0.113.1"},{"value":"45.33.32.77"}]', 0) RETURNING id`).Scan(&listID); err != nil {
		t.Fatalf("create list: %v", err)
	}

	for _, entries := range []string{`[{"value":"203.0.113.1"},{"value":"45.33.32.77"}]`, `[{"value":"203.0.113.1"}]`} {
		rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{"entries": entries})
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if n := countSaveInterruptRecidivism(t, ip); n != 1 {
			t.Fatalf("无新增保存后累犯行=%d, want 1（entries=%s）", n, entries)
		}
		if got := services.AutobanTrackedIPs(); got != 1 {
			t.Fatalf("tracked_ips=%d, want 1（entries=%s）", got, entries)
		}
	}
}

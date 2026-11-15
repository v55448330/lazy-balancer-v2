package handlers

// 加名单中断累犯钉（用户裁定：手动加入任何名单=主动处置，抹累犯前科+停当前计数）：
//   - AddIPToList 成功写入后：services.AutobanForgetIPs 清计数桶+建议剔除，
//     services.DeleteAutobanRecidivism 清该身份累犯行（autobanEntryIdentity 归一）；
//   - 加到 autoban 预置名单（手动封禁）同走此路径（避免双重处置）；
//   - 幂等 no-op 路径（added=false，无写入）不清前科/计数。

import (
	"fmt"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// Given 目标 IP 有计数桶（已达阈值）+观察建议+累犯行；加入自定义名单。
// When POST /security/ip-lists/:id/ips 成功。
// Then 计数桶清零、建议剔除该 IP、累犯行删除（信任/黑名单处置中断累犯）。
func TestAddIPToList_interruptsRecidivismAndCounters(t *testing.T) {
	router := newAutobanTestEnv(t)
	const ip = "45.33.32.77"
	// 全局计数桶跨用例共享：先重置既定基线，tracked_ips==0 断言才不受
	// 前置用例泄漏影响（shuffle 顺序无关）。
	services.ResetAutobanCounters()
	services.AutobanSeedCounterForTest(ip, 5, 3)
	services.AutobanSetSuggestionsForTest([]services.AutobanSuggestion{
		{IP: ip, Count: 5},
		{IP: "203.0.113.5", Count: 2},
	})
	t.Cleanup(func() { services.AutobanSetSuggestionsForTest(nil) })
	if _, err := db.DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES (?, 3, '2026-11-15 10:00:00', 'permanent')`, ip); err != nil {
		t.Fatalf("seed recidivism: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES ('198.51.100.9', 2, '2026-11-15 10:00:00', '24h')`); err != nil {
		t.Fatalf("seed other recidivism: %v", err)
	}
	var listID int64
	if err := db.DB.QueryRow(`INSERT INTO security_ip_lists (name, description, category, entries, system) VALUES ('信任名单-处置', '', '自定义', '[]', 0) RETURNING id`).Scan(&listID); err != nil {
		t.Fatalf("create list: %v", err)
	}

	rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", listID), map[string]any{"value": ip})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	if got := services.AutobanTrackedIPs(); got != 0 {
		t.Fatalf("tracked_ips=%d, want 0（加名单必须清计数桶）", got)
	}
	for _, s := range services.AutobanSuggestions() {
		if s.IP == ip {
			t.Fatalf("建议列表仍含已处置 IP %s", ip)
		}
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity=?`, ip).Scan(&n); err != nil {
		t.Fatalf("count recidivism: %v", err)
	}
	if n != 0 {
		t.Fatalf("累犯行未删除（%d 行）——手动处置必须抹前科", n)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity='198.51.100.9'`).Scan(&n); err != nil {
		t.Fatalf("count other: %v", err)
	}
	if n != 1 {
		t.Fatalf("无关累犯行必须保留, got %d", n)
	}
}

// Given 目标 IP 有累犯行；加入 autoban 预置名单（手动封禁）。
// When POST 成功。
// Then 手动封禁同样中断累犯（避免双重处置）：累犯行删除。
func TestAddIPToList_presetManualBanAlsoInterruptsRecidivism(t *testing.T) {
	router := newAutobanTestEnv(t)
	const ip = "45.33.32.78"
	if _, err := db.DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES (?, 2, '2026-11-15 10:00:00', '24h')`, ip); err != nil {
		t.Fatalf("seed recidivism: %v", err)
	}

	rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", autobanPresetID(t)), map[string]any{"value": ip})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity=?`, ip).Scan(&n); err != nil {
		t.Fatalf("count recidivism: %v", err)
	}
	if n != 0 {
		t.Fatalf("手动封禁必须同样抹累犯前科, got %d 行", n)
	}
}

// Given 目标 IP 已在名单生效（幂等 no-op，added=false）且有累犯行。
// When POST 同值。
// Then 200 added=false；无写入路径不清前科（处置未发生）。
func TestAddIPToList_idempotentNoopKeepsRecidivism(t *testing.T) {
	router := newAutobanTestEnv(t)
	const ip = "45.33.32.79"
	id := autobanPresetID(t)
	seedAutobanListEntries(t, fmt.Sprintf(`[{"value":%q,"remark":"手动封禁"}]`, ip))
	if _, err := db.DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES (?, 2, '2026-11-15 10:00:00', '24h')`, ip); err != nil {
		t.Fatalf("seed recidivism: %v", err)
	}

	rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", id), map[string]any{"value": ip})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity=?`, ip).Scan(&n); err != nil {
		t.Fatalf("count recidivism: %v", err)
	}
	if n != 1 {
		t.Fatalf("幂等 no-op 不得清前科, got %d 行", n)
	}
}

// Given 目标 IP 有计数桶+观察建议+累犯行；「创建并加入」路径
// （POST /security/ip-lists 带 entries 种子——快捷弹框无同侧名单时的主入口）。
// When 创建成功。
// Then 种子条目与 AddIPToList 同语义中断累犯：清桶+建议剔除+累犯行删除。
func TestCreateIPList_seedEntriesInterruptRecidivism(t *testing.T) {
	router := newAutobanTestEnv(t)
	const ip = "198.51.100.7"
	// 全局计数桶跨用例共享：先重置既定基线（同 AddIPToList 中断钉）。
	services.ResetAutobanCounters()
	services.AutobanSeedCounterForTest(ip, 5, 3)
	services.AutobanSetSuggestionsForTest([]services.AutobanSuggestion{{IP: ip, Count: 5}})
	t.Cleanup(func() { services.AutobanSetSuggestionsForTest(nil) })
	if _, err := db.DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES (?, 3, '2026-11-15 10:00:00', 'permanent')`, ip); err != nil {
		t.Fatalf("seed recidivism: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES ('45.33.32.90', 2, '2026-11-15 10:00:00', '24h')`); err != nil {
		t.Fatalf("seed other recidivism: %v", err)
	}

	rec := postJSON(t, router, "/security/ip-lists", map[string]any{
		"name": "信任名单-创建并加入", "category": "自定义",
		"entries": fmt.Sprintf(`[{"value":%q,"remark":"事件处置"}]`, ip),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	if got := services.AutobanTrackedIPs(); got != 0 {
		t.Fatalf("tracked_ips=%d, want 0（创建并加入必须清计数桶）", got)
	}
	for _, s := range services.AutobanSuggestions() {
		if s.IP == ip {
			t.Fatalf("建议列表仍含已处置 IP %s", ip)
		}
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity=?`, ip).Scan(&n); err != nil {
		t.Fatalf("count recidivism: %v", err)
	}
	if n != 0 {
		t.Fatalf("创建并加入必须抹累犯前科, got %d 行", n)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity='45.33.32.90'`).Scan(&n); err != nil {
		t.Fatalf("count other: %v", err)
	}
	if n != 1 {
		t.Fatalf("无关累犯行必须保留, got %d", n)
	}
}

// Given 创建名单不带种子条目（空 entries）。
// When 创建成功。
// Then 无处置发生：既有累犯行不受影响。
func TestCreateIPList_emptyEntriesKeepsRecidivism(t *testing.T) {
	router := newAutobanTestEnv(t)
	if _, err := db.DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES ('198.51.100.8', 2, '2026-11-15 10:00:00', '24h')`); err != nil {
		t.Fatalf("seed recidivism: %v", err)
	}

	rec := postJSON(t, router, "/security/ip-lists", map[string]any{
		"name": "空名单", "category": "自定义", "entries": "[]",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity='198.51.100.8'`).Scan(&n); err != nil {
		t.Fatalf("count recidivism: %v", err)
	}
	if n != 1 {
		t.Fatalf("空创建不得清前科, got %d 行", n)
	}
}

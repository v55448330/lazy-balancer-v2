package services

// 累犯记录查询/删除/物理衰减/行富化钉：
//   - ListAutobanRecidivism：hidePermanent/ip 子串筛选、分页 total、排序契约；
//   - 行富化：ban_status join 名单生效条目（限时/永久/未封禁三态）、
//     hits_24h/last_event_at 按身份键聚合 security_events（IPv6 /64 归一）；
//   - DeleteAutobanRecidivism：单条删除、幂等（不存在也成功）；
//   - RunAutobanCycle 每轮物理清理衰减行（last_ban_at < now-decay），
//     与读时衰减清零同窗口口径，防表无限增长。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// seedAutobanRecidivismRows 直填累犯行（绕 merge 写路径——查询/清理契约只
// 消费表形态，不依赖升级档位）。
func seedAutobanRecidivismRows(t *testing.T, rows ...[4]string) {
	t.Helper()
	for _, r := range rows {
		if _, err := db.GetDB().Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES (?, ?, ?, ?)`,
			r[0], r[1], r[2], r[3]); err != nil {
			t.Fatalf("seed recidivism %v: %v", r, err)
		}
	}
}

func recidivismIdentities(records []AutobanRecidivismRecord) []string {
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.Identity
	}
	return out
}

// Given 累犯表五行（含 permanent/并列计数/不同 IP 段）。
// When ListAutobanRecidivism 缺省筛选（hidePermanent=true）。
// Then permanent 行隐藏；total=筛选后总数；offense_count 降序、identity 升序。
func TestListAutobanRecidivism_hidePermanentDefault(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t,
		[4]string{"45.33.32.10", "2", "2026-11-14 09:00:00", "24h"},
		[4]string{"2606:4700:abcd:1234::", "3", "2026-11-15 10:00:00", "permanent"},
		[4]string{"45.33.32.11", "2", "2026-11-13 08:00:00", "24h"},
		[4]string{"198.51.100.7", "1", "2026-11-12 07:00:00", "1h"},
	)

	records, total, err := ListAutobanRecidivism(true, "", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 {
		t.Fatalf("total=%d, want 3（permanent 行不计入筛选后总数）", total)
	}
	want := []string{"45.33.32.10", "45.33.32.11", "198.51.100.7"}
	got := recidivismIdentities(records)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("identities=%v, want %v（offense_count 降序 + identity 升序）", got, want)
		}
	}
}

// Given 同上五行。
// When hidePermanent=false。
// Then permanent 行可见，total=全表行数。
func TestListAutobanRecidivism_showPermanent(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t,
		[4]string{"45.33.32.10", "2", "2026-11-14 09:00:00", "24h"},
		[4]string{"2606:4700:abcd:1234::", "3", "2026-11-15 10:00:00", "permanent"},
	)

	records, total, err := ListAutobanRecidivism(false, "", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 || len(records) != 2 {
		t.Fatalf("total=%d records=%d, want 2/2（hidePermanent=false 显示全部）", total, len(records))
	}
}

// Given 累犯表含相近 IP 段与通配符字面行。
// When ipFilter 子串筛选。
// Then 只命中 identity 含该子串的行；%/_ 按字面匹配不当通配符；total 同口径。
func TestListAutobanRecidivism_ipFilterSubstring(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t,
		[4]string{"45.33.32.10", "2", "2026-11-14 09:00:00", "24h"},
		[4]string{"45.33.32.11", "1", "2026-11-13 08:00:00", "1h"},
		[4]string{"145.33.32.100", "1", "2026-11-13 08:00:00", "1h"},
		[4]string{"198.51.100.7", "1", "2026-11-12 07:00:00", "1h"},
	)

	records, total, err := ListAutobanRecidivism(true, "45.33.32.1", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 {
		t.Fatalf("total=%d, want 3（子串 contains：45.33.32.10/45.33.32.11/145.33.32.100）", total)
	}
	want := map[string]bool{"45.33.32.10": true, "45.33.32.11": true, "145.33.32.100": true}
	for _, r := range records {
		if !want[r.Identity] {
			t.Fatalf("unexpected identity %q in filter result", r.Identity)
		}
	}

	// 通配符字面：% 不得匹配任意串（identity 无 % 行 → 空集）。
	_, total, err = ListAutobanRecidivism(true, "%", 1, 20)
	if err != nil {
		t.Fatalf("list wildcard: %v", err)
	}
	if total != 0 {
		t.Fatalf("total=%d, want 0（%% 按字面子串，不当通配符）", total)
	}
}

// Given 累犯表四行。
// When 分页 page=2/pageSize=2。
// Then 返回第二页两条，total=筛选后总数（不受分页截断）。
func TestListAutobanRecidivism_paginationTotal(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t,
		[4]string{"45.33.32.10", "2", "2026-11-14 09:00:00", "24h"},
		[4]string{"45.33.32.11", "2", "2026-11-13 08:00:00", "24h"},
		[4]string{"198.51.100.7", "1", "2026-11-12 07:00:00", "1h"},
		[4]string{"203.0.113.9", "1", "2026-11-11 06:00:00", "1h"},
	)

	records, total, err := ListAutobanRecidivism(true, "", 2, 2)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 4 {
		t.Fatalf("total=%d, want 4（total 是筛选后总数，不是本页行数）", total)
	}
	want := []string{"198.51.100.7", "203.0.113.9"}
	got := recidivismIdentities(records)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("page2=%v, want %v", got, want)
	}

	// 越界页：records 空切片（非 nil），total 不变。
	records, total, err = ListAutobanRecidivism(true, "", 9, 2)
	if err != nil {
		t.Fatalf("list overflow page: %v", err)
	}
	if total != 4 || records == nil || len(records) != 0 {
		t.Fatalf("overflow page: total=%d records=%v, want 4/非nil空切片", total, records)
	}
}

// Given 空表。
// When ListAutobanRecidivism。
// Then records 非 nil 空切片（JSON [] 契约）、total=0。
func TestListAutobanRecidivism_emptyArrayContract(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	records, total, err := ListAutobanRecidivism(true, "", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 0 || records == nil || len(records) != 0 {
		t.Fatalf("total=%d records=%v, want 0/非nil空切片", total, records)
	}
}

// Given 累犯表两行。
// When DeleteAutobanRecidivism 删其中一行。
// Then 该行消失、另一行不受影响。
func TestDeleteAutobanRecidivism_singleRow(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t,
		[4]string{"45.33.32.10", "2", "2026-11-14 09:00:00", "24h"},
		[4]string{"198.51.100.7", "1", "2026-11-12 07:00:00", "1h"},
	)

	if err := DeleteAutobanRecidivism("45.33.32.10"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var n int
	if err := db.GetDB().QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity='45.33.32.10'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("deleted identity still present (%d rows)", n)
	}
	if err := db.GetDB().QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity='198.51.100.7'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("other identity must survive, got %d rows", n)
	}
}

// Given 目标行不存在。
// When 重复 DeleteAutobanRecidivism。
// Then 幂等成功（不报错、表状态不变）。
func TestDeleteAutobanRecidivism_idempotent(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t, [4]string{"198.51.100.7", "1", "2026-11-12 07:00:00", "1h"})
	for i := range 2 {
		if err := DeleteAutobanRecidivism("203.0.113.99"); err != nil {
			t.Fatalf("call %d: %v（不存在的身份删除必须幂等成功）", i+1, err)
		}
	}
	var n int
	if err := db.GetDB().QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("table=%d rows, want 1（无关行不受影响）", n)
	}
}

// Given 累犯表三行：一行超出衰减窗口、两行窗口内（含恰在边界）。
// When RunAutobanCycle（dry-run 观察轮，无候选）。
// Then 超窗行被物理删除；窗口内行保留（含边界行——读时衰减判据 > decay）。
func TestRunAutobanCycle_prunesDecayedRecidivism(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "blocked,logged,challenge_issued,challenge_failed", true)
	seedAutobanRecidivismRows(t,
		[4]string{"45.33.32.10", "3", "2026-10-01 09:00:00", "permanent"}, // 45 天前：超窗
		[4]string{"45.33.32.11", "2", "2026-11-10 09:00:00", "24h"},       // 5 天前：窗口内
		[4]string{"198.51.100.7", "1", "2026-10-16 10:00:00", "1h"},       // 恰 30 天：边界保留
	)

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("cycle: %v", err)
	}

	rows, err := db.GetDB().Query(`SELECT identity FROM autoban_recidivism ORDER BY identity`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, id)
	}
	want := []string{"198.51.100.7", "45.33.32.11"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("remaining=%v, want %v（超窗行物理删除、边界行保留）", got, want)
	}
}

// Given 衰减窗口缝被覆写为 0（禁用衰减）。
// When RunAutobanCycle。
// Then 不做物理清理（与读时衰减同口径：decay<=0 不衰减）。
func TestRunAutobanCycle_decayDisabledSkipsPrune(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "blocked,logged,challenge_issued,challenge_failed", true)
	oldDecay := autobanRecidivismDecay
	autobanRecidivismDecay = 0
	t.Cleanup(func() { autobanRecidivismDecay = oldDecay })
	seedAutobanRecidivismRows(t, [4]string{"45.33.32.10", "3", "2020-01-01 00:00:00", "permanent"})

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	var n int
	if err := db.GetDB().QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("decay=0 不得物理清理，剩 %d 行", n)
	}
}

// seedRecidivismSecurityEvents 直填 metrics 安全事件行（富化聚合只消费
// client_ip/event_time 两列形态，不依赖采集链路）。
func seedRecidivismSecurityEvents(t *testing.T, rows ...[2]string) {
	t.Helper()
	for _, r := range rows {
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (client_ip, event_time) VALUES (?, ?)`, r[0], r[1]); err != nil {
			t.Fatalf("seed security event %v: %v", r, err)
		}
	}
}

func recidivismByIdentity(t *testing.T, records []AutobanRecidivismRecord, identity string) AutobanRecidivismRecord {
	t.Helper()
	for _, r := range records {
		if r.Identity == identity {
			return r
		}
	}
	t.Fatalf("identity %s 不在结果集 %v", identity, recidivismIdentities(records))
	return AutobanRecidivismRecord{}
}

// Given 名单三条目：限时（未到期）/永久（无到期）/已到期；累犯表对应三身份
// （含 IPv6 /64 CIDR 条目值与裸身份键的归一匹配）。
// When ListAutobanRecidivism。
// Then ban_status 三态：timed+到期时刻透传 / permanent+空到期 / none（到期
// 条目与生效面同口径不算封禁中）。
func TestListAutobanRecidivism_banStatusJoinsActiveEntries(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t,
		[4]string{"203.0.113.10", "2", "2026-11-15 08:00:00", "24h"},
		[4]string{"203.0.113.11", "3", "2026-11-15 09:00:00", "permanent"},
		[4]string{"203.0.113.12", "2", "2026-11-14 09:00:00", "1h"},
		[4]string{"2606:4700:abcd:1234::", "2", "2026-11-15 07:00:00", "24h"},
		[4]string{"203.0.113.13", "1", "2026-11-13 09:00:00", "1h"},
	)
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "203.0.113.10", ExpiresAt: "2026-11-15 12:30:00"},
		{Value: "203.0.113.11"},
		{Value: "203.0.113.12", ExpiresAt: "2026-11-15 09:00:00"},
		{Value: "2606:4700:abcd:1234::/64", ExpiresAt: "2026-11-16 10:00:00"},
	})

	records, _, err := ListAutobanRecidivism(false, "", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	timed := recidivismByIdentity(t, records, "203.0.113.10")
	if timed.BanStatus != "timed" || timed.BanExpiresAt != "2026-11-15 12:30:00" {
		t.Fatalf("限时封禁态失真: %+v", timed)
	}
	perm := recidivismByIdentity(t, records, "203.0.113.11")
	if perm.BanStatus != "permanent" || perm.BanExpiresAt != "" {
		t.Fatalf("永久封禁态失真: %+v", perm)
	}
	expired := recidivismByIdentity(t, records, "203.0.113.12")
	if expired.BanStatus != "none" || expired.BanExpiresAt != "" {
		t.Fatalf("已到期条目必须按未封禁呈现（与生效面同口径）: %+v", expired)
	}
	v6 := recidivismByIdentity(t, records, "2606:4700:abcd:1234::")
	if v6.BanStatus != "timed" || v6.BanExpiresAt != "2026-11-16 10:00:00" {
		t.Fatalf("IPv6 /64 CIDR 条目必须经身份归一匹配裸身份键: %+v", v6)
	}
	absent := recidivismByIdentity(t, records, "203.0.113.13")
	if absent.BanStatus != "none" {
		t.Fatalf("名单无条目必须未封禁: %+v", absent)
	}
}

// Given metrics 事件：IPv4 多行（含窗口边界行/窗外行/邻居 IP）+ IPv6 同 /64
// 两个漂移地址 + 另一 /64 段行。
// When ListAutobanRecidivism。
// Then hits_24h=近 24h COUNT（边界含、窗外不含、邻居不串）；IPv6 按 /64 归一
// 聚合（漂移地址计入本段、邻段不计）；last_event_at=窗口内 MAX(event_time)；
// 窗口内无事件的身份 hits=0/last_event_at 空。
func TestListAutobanRecidivism_hits24hAndLastEvent(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t,
		[4]string{"203.0.113.10", "2", "2026-11-15 08:00:00", "24h"},
		[4]string{"2606:4700:abcd:1234::", "2", "2026-11-15 07:00:00", "24h"},
		[4]string{"203.0.113.99", "1", "2026-11-12 09:00:00", "1h"},
	)
	seedRecidivismSecurityEvents(t,
		[2]string{"203.0.113.10", "2026-11-15 09:30:00"},
		[2]string{"203.0.113.10", "2026-11-14 10:00:00"},
		[2]string{"203.0.113.10", "2026-11-14 09:59:59"},
		[2]string{"203.0.113.11", "2026-11-15 09:00:00"},
		[2]string{"2606:4700:abcd:1234:5::1", "2026-11-15 08:00:00"},
		[2]string{"2606:4700:abcd:1234::99", "2026-11-15 09:45:00"},
		[2]string{"2606:4700:abcd:1235::1", "2026-11-15 09:00:00"},
	)

	records, _, err := ListAutobanRecidivism(false, "", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	v4 := recidivismByIdentity(t, records, "203.0.113.10")
	if v4.Hits24h != 2 || v4.LastEventAt != "2026-11-15 09:30:00" {
		t.Fatalf("IPv4 聚合失真（窗口边界含/窗外不含/邻居不串）: %+v", v4)
	}
	v6 := recidivismByIdentity(t, records, "2606:4700:abcd:1234::")
	if v6.Hits24h != 2 || v6.LastEventAt != "2026-11-15 09:45:00" {
		t.Fatalf("IPv6 /64 归一聚合失真（漂移地址计入本段、邻段不计）: %+v", v6)
	}
	quiet := recidivismByIdentity(t, records, "203.0.113.99")
	if quiet.Hits24h != 0 || quiet.LastEventAt != "" {
		t.Fatalf("窗口内无事件必须 hits=0/last_event_at 空: %+v", quiet)
	}
}

// Given 累犯表有行但 metrics 句柄缺失（指标库不可用形态）。
// When ListAutobanRecidivism。
// Then 聚合位降级零值（hits=0/last_event_at 空），名单 join 不受影响、
// 列表整体不报错（展示位容错，与状态卡统计位同族）。
func TestListAutobanRecidivism_metricsUnavailableDegrades(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t, [4]string{"203.0.113.10", "2", "2026-11-15 08:00:00", "24h"})
	seedPresetEntries(t, []models.IPListEntry{{Value: "203.0.113.10", ExpiresAt: "2026-11-15 12:00:00"}})
	oldMetrics := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = oldMetrics })

	records, total, err := ListAutobanRecidivism(false, "", 1, 20)
	if err != nil {
		t.Fatalf("metrics 缺失不得让列表失败: %v", err)
	}
	if total != 1 {
		t.Fatalf("total=%d, want 1", total)
	}
	r := recidivismByIdentity(t, records, "203.0.113.10")
	if r.Hits24h != 0 || r.LastEventAt != "" {
		t.Fatalf("metrics 缺失聚合位必须零值: %+v", r)
	}
	if r.BanStatus != "timed" || r.BanExpiresAt != "2026-11-15 12:00:00" {
		t.Fatalf("名单 join 不受 metrics 缺失影响: %+v", r)
	}
}

// Given 预置名单含限时/永久/已到期条目 + IPv6 /64 CIDR 条目。
// When AutobanIdentityActivelyBanned 判定各身份。
// Then 限时/永久=true；已到期/名单无条目=false；IPv6 CIDR 条目经身份归一
// 命中裸身份键（与 ban_status join 同口径）。
func TestAutobanIdentityActivelyBanned(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "203.0.113.10", ExpiresAt: "2026-11-15 12:30:00"},
		{Value: "203.0.113.11"},
		{Value: "203.0.113.12", ExpiresAt: "2026-11-15 09:00:00"},
		{Value: "2606:4700:abcd:1234::/64", ExpiresAt: "2026-11-16 10:00:00"},
	})
	cases := []struct {
		identity string
		want     bool
	}{
		{"203.0.113.10", true},           // 限时生效
		{"203.0.113.11", true},           // 永久
		{"203.0.113.12", false},          // 已到期
		{"203.0.113.99", false},          // 名单无条目
		{"2606:4700:abcd:1234::", true},  // IPv6 /64 CIDR 归一命中
		{"2606:4700:abcd:9999::", false}, // 邻段不串
	}
	for _, c := range cases {
		got, err := AutobanIdentityActivelyBanned(c.identity)
		if err != nil {
			t.Fatalf("identity %s: %v", c.identity, err)
		}
		if got != c.want {
			t.Fatalf("identity %s actively banned=%v, want %v", c.identity, got, c.want)
		}
	}
}

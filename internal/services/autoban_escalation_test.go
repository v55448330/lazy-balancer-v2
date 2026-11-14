package services

// 自动封禁身份键抽象与累犯渐进升级钉测：
//   - autobanIdentityKey 单源（常态=autobanNormalizeIP /64 归一），计数/merge/
//     解封清桶与累犯表键同形；
//   - autoban_recidivism 累犯表：off 固定时长；standard 首次 duration→二次
//     24h→三次+永久；aggressive 首次 duration→二次+永久；
//   - 衰减窗口：N 天无再犯 offense_count 降一级（防永久标签）；
//   - 写侧配置校验拒绝非法 Escalation。

import (
	"database/sql"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// ---- 身份键抽象 ----

// Given 身份键抽象。
// When 对 IPv6 隐私扩展地址/IPv4/不可解析串求身份键。
// Then 恒与 autobanNormalizeIP 同值（/64 归一单源复用）。
func TestAutobanIdentityKey_reusesNormalizeIP(t *testing.T) {
	for _, ip := range []string{
		"2606:4700:abcd:1234:1111:2222:3333:4444",
		"2606:4700:abcd:1234::9",
		"2001:db8::1",
		"45.33.32.10",
		"::ffff:45.33.32.10",
		"not-an-ip",
		"",
	} {
		if got, want := autobanIdentityKey(ip), autobanNormalizeIP(ip); got != want {
			t.Fatalf("autobanIdentityKey(%q)=%q, want autobanNormalizeIP=%q", ip, got, want)
		}
	}
}

// Given 同 /64 的多个隐私扩展地址经生产喂入门计数。
// When 评估候选并 merge。
// Then 计数桶键与累犯表行键同为归一身份（单源贯穿计数→执法→累犯记账）。
func TestAutobanIdentityKey_counterMergeRecidivismShareNormalizedKey(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "blocked", false)
	cfg := AutobanConfig{Enabled: true, Threshold: 2, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "standard"}
	for _, ip := range []string{"2606:4700:abcd:1234::1", "2606:4700:abcd:1234::2"} {
		autobanObserveEventScopedAt(cfg, ip, "blocked", "942100", autobanNow())
	}

	out, err := autobanMergeEntries(cfg, autobanCandidates(2, 5*time.Minute))
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out.Banned) != 1 || out.Banned[0] != "2606:4700:abcd:1234::/64" {
		t.Fatalf("封禁条目=%v, want /64 CIDR", out.Banned)
	}
	var count int
	var escalated string
	if err := db.GetDB().QueryRow(`SELECT offense_count, escalated_duration FROM autoban_recidivism WHERE identity=?`,
		"2606:4700:abcd:1234::").Scan(&count, &escalated); err != nil {
		t.Fatalf("累犯行缺失（身份键未与计数键同形）: %v", err)
	}
	if count != 1 || escalated != "1h" {
		t.Fatalf("累犯行=(%d,%q), want (1,1h)", count, escalated)
	}
}

// ---- 累犯表 schema ----

// Given 全新库。
// When Initialize 完成。
// Then autoban_recidivism 表四列形态就位（identity TEXT PK / offense_count
// INTEGER / last_ban_at TEXT / escalated_duration TEXT）。
func TestAutobanRecidivism_tableShape(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	rows, err := db.GetDB().Query(`PRAGMA table_info(autoban_recidivism)`)
	if err != nil {
		t.Fatalf("pragma table_info: %v", err)
	}
	defer rows.Close()
	type col struct {
		name, typ string
		pk        int
	}
	var cols []col
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan pragma row: %v", err)
		}
		cols = append(cols, col{name, typ, pk})
	}
	want := []col{
		{"identity", "TEXT", 1},
		{"offense_count", "INTEGER", 0},
		{"last_ban_at", "TEXT", 0},
		{"escalated_duration", "TEXT", 0},
	}
	if len(cols) != len(want) {
		t.Fatalf("autoban_recidivism 列=%+v, want %+v", cols, want)
	}
	for i, w := range want {
		if cols[i] != w {
			t.Fatalf("列 %d=%+v, want %+v", i, cols[i], w)
		}
	}
}

// ---- 渐进升级 ----

// escalationBan 一次真实新封（不推进时钟）：返回封禁条目的到期串（永久=空）。
func escalationBan(t *testing.T, cfg AutobanConfig, ip string) string {
	t.Helper()
	out, err := autobanMergeEntries(cfg, []AutobanSuggestion{{IP: ip, Count: 10}})
	if err != nil {
		t.Fatalf("merge ban: %v", err)
	}
	if len(out.Banned) != 1 {
		t.Fatalf("本轮未产生新封: banned=%v", out.Banned)
	}
	entry, ok := entryValues(presetEntries(t))[autobanBanValue(ip)]
	if !ok {
		t.Fatalf("封禁条目未落名单: %v", out.Banned)
	}
	return entry.ExpiresAt
}

// escalationSweepExpired 到期清理（与生产 Run 轮 merge(nil) 同链）。
func escalationSweepExpired(t *testing.T, cfg AutobanConfig) {
	t.Helper()
	if _, err := autobanMergeEntries(cfg, nil); err != nil {
		t.Fatalf("merge expiry sweep: %v", err)
	}
}

// escalationUnban 手动解封（删除即解封生产路径）：永久条目无到期清理点，
// 再犯只能经手动删除条目发生；AutobanForgetIPs 同步清计数桶。
func escalationUnban(t *testing.T, ip string) {
	t.Helper()
	value := autobanBanValue(ip)
	kept := make([]models.IPListEntry, 0)
	for _, e := range presetEntries(t) {
		if e.Value != value {
			kept = append(kept, e)
		}
	}
	seedPresetEntries(t, kept)
	AutobanForgetIPs([]string{value})
}

func readRecidivismRow(t *testing.T, identity string) (count int, lastBan, escalated string) {
	t.Helper()
	if err := db.GetDB().QueryRow(`SELECT offense_count, last_ban_at, escalated_duration FROM autoban_recidivism WHERE identity=?`,
		identity).Scan(&count, &lastBan, &escalated); err != nil {
		t.Fatalf("read recidivism %q: %v", identity, err)
	}
	return count, lastBan, escalated
}

// Given standard 升级、配置时长 1h。
// When 同一 IP 四次「封禁→到期→再犯」。
// Then 首次 1h、二次 24h、三次+永久；offense_count/last_ban_at 逐次记账。
func TestAutobanEscalation_standardSteps(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "standard"}
	const ip = "45.33.32.10"

	banStart := clock.Now()
	exp1 := escalationBan(t, cfg, ip)
	if got, want := exp1, banStart.Add(time.Hour).Format(autobanTimeLayout); got != want {
		t.Fatalf("首次到期=%q, want %q（配置时长 1h）", got, want)
	}
	count, lastBan, escalated := readRecidivismRow(t, ip)
	if count != 1 || escalated != "1h" {
		t.Fatalf("首次记账=(%d,%q), want (1,1h)", count, escalated)
	}
	if lastBan == "" {
		t.Fatal("首次封禁必须记录 last_ban_at")
	}
	firstBanAt := lastBan
	clock.Advance(time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)

	clock.Advance(time.Hour) // 距上次封禁约 2h（衰减窗口内）
	banStart = clock.Now()
	exp2 := escalationBan(t, cfg, ip)
	if got, want := exp2, banStart.Add(24*time.Hour).Format(autobanTimeLayout); got != want {
		t.Fatalf("二次到期=%q, want %q（升级 24h）", got, want)
	}
	count, lastBan, escalated = readRecidivismRow(t, ip)
	if count != 2 || escalated != "24h" {
		t.Fatalf("二次记账=(%d,%q), want (2,24h)", count, escalated)
	}
	if lastBan == firstBanAt {
		t.Fatal("二次封禁必须刷新 last_ban_at")
	}
	clock.Advance(24*time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)

	clock.Advance(time.Hour) // 距上次封禁约 25h（衰减窗口内）
	if exp3 := escalationBan(t, cfg, ip); exp3 != "" {
		t.Fatalf("三次封禁必须永久（无到期），得到 %q", exp3)
	}
	count, _, escalated = readRecidivismRow(t, ip)
	if count != 3 || escalated != "permanent" {
		t.Fatalf("三次记账=(%d,%q), want (3,permanent)", count, escalated)
	}

	clock.Advance(25 * time.Hour) // 窗口内再犯：永久条目经手动解封后重新达标
	escalationUnban(t, ip)
	if exp4 := escalationBan(t, cfg, ip); exp4 != "" {
		t.Fatalf("三次以上必须保持永久，得到 %q", exp4)
	}
	count, _, escalated = readRecidivismRow(t, ip)
	if count != 4 || escalated != "permanent" {
		t.Fatalf("四次记账=(%d,%q), want (4,permanent)", count, escalated)
	}
}

// Given aggressive 升级、配置时长 1h。
// When 同一 IP 两次「封禁→到期→再犯」。
// Then 首次 1h、二次+永久。
func TestAutobanEscalation_aggressiveSecondOffensePermanent(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "aggressive"}
	const ip = "45.33.32.11"

	banStart := clock.Now()
	if got, want := escalationBan(t, cfg, ip), banStart.Add(time.Hour).Format(autobanTimeLayout); got != want {
		t.Fatalf("首次到期=%q, want %q（配置时长 1h）", got, want)
	}
	clock.Advance(time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)
	clock.Advance(time.Hour)
	if exp := escalationBan(t, cfg, ip); exp != "" {
		t.Fatalf("aggressive 二次封禁必须永久，得到到期 %q", exp)
	}
	count, _, escalated := readRecidivismRow(t, ip)
	if count != 2 || escalated != "permanent" {
		t.Fatalf("二次记账=(%d,%q), want (2,permanent)", count, escalated)
	}
}

// Given off（默认）。
// When 同一 IP 三次「封禁→到期→再犯」。
// Then 每次都是固定配置时长（不升级）；累犯表零写入。
func TestAutobanEscalation_offKeepsFixedDuration(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked"}
	const ip = "45.33.32.12"

	for i := range 3 {
		banStart := clock.Now()
		exp := escalationBan(t, cfg, ip)
		if got, want := exp, banStart.Add(time.Hour).Format(autobanTimeLayout); got != want {
			t.Fatalf("第 %d 次到期=%q, want %q（off 固定时长不升级）", i+1, got, want)
		}
		clock.Advance(time.Hour + time.Minute)
		escalationSweepExpired(t, cfg)
		clock.Advance(time.Hour)
	}
	var rows int
	if err := db.GetDB().QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`).Scan(&rows); err != nil {
		t.Fatalf("count recidivism: %v", err)
	}
	if rows != 0 {
		t.Fatalf("off 不得写累犯表，得到 %d 行", rows)
	}
}

// Given standard 已把某 IP 记到三次（permanent）。
// When 距上次封禁超过衰减窗口（30 天）后再犯。
// Then 历史清零、按首次档重新起步（offense_count=1、配置时长）——永久标签
// 随守法时长脱落；随后窗口内再犯仍按正常阶梯升级（2 次=24h）。
func TestAutobanEscalation_decayWindowDowngrades(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "standard"}
	const ip = "45.33.32.13"

	// 三次累犯（每轮间隔约 2h，均在衰减窗口内）。
	escalationBan(t, cfg, ip)
	clock.Advance(time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)
	clock.Advance(time.Hour)
	escalationBan(t, cfg, ip)
	clock.Advance(24*time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)
	clock.Advance(time.Hour)
	escalationBan(t, cfg, ip)
	if count, _, escalated := readRecidivismRow(t, ip); count != 3 || escalated != "permanent" {
		t.Fatalf("前置记账=(%d,%q), want (3,permanent)", count, escalated)
	}

	// 31 天无再犯（>30 天窗口）→ 手动解封后再犯：历史清零，本次为第 1 次，
	// 按配置时长 1h 执法（不再背永久标签）。
	clock.Advance(31 * 24 * time.Hour)
	escalationUnban(t, ip)
	banStart := clock.Now()
	exp := escalationBan(t, cfg, ip)
	if got, want := exp, banStart.Add(time.Hour).Format(autobanTimeLayout); got != want {
		t.Fatalf("衰减后再犯到期=%q, want %q（历史清零按首次档 1h）", got, want)
	}
	if count, _, escalated := readRecidivismRow(t, ip); count != 1 || escalated != "1h" {
		t.Fatalf("衰减后再犯记账=(%d,%q), want (1,1h)", count, escalated)
	}

	// 窗口内再犯（约 2h 后）：正常阶梯升级，第 2 次=24h。
	clock.Advance(time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)
	clock.Advance(time.Hour)
	banStart = clock.Now()
	exp = escalationBan(t, cfg, ip)
	if got, want := exp, banStart.Add(24*time.Hour).Format(autobanTimeLayout); got != want {
		t.Fatalf("衰减后窗口内再犯到期=%q, want %q（第 2 次 24h）", got, want)
	}
	if count, _, escalated := readRecidivismRow(t, ip); count != 2 || escalated != "24h" {
		t.Fatalf("衰减后窗口内再犯记账=(%d,%q), want (2,24h)", count, escalated)
	}
}

// Given standard 已把某 IP 记到三次。
// When 距上次封禁恰在衰减窗口内（29 天）再犯。
// Then 不降级，仍按永久执法。
func TestAutobanEscalation_withinWindowNoDecay(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "standard"}
	const ip = "45.33.32.14"

	escalationBan(t, cfg, ip)
	clock.Advance(time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)
	clock.Advance(time.Hour)
	escalationBan(t, cfg, ip)
	clock.Advance(24*time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)
	clock.Advance(time.Hour)
	escalationBan(t, cfg, ip)

	clock.Advance(29 * 24 * time.Hour)
	escalationUnban(t, ip)
	if exp := escalationBan(t, cfg, ip); exp != "" {
		t.Fatalf("窗口内再犯不得降级，得到到期 %q", exp)
	}
	if count, _, _ := readRecidivismRow(t, ip); count != 4 {
		t.Fatalf("窗口内再犯记账=%d, want 4（不降级直接 +1）", count)
	}
}

// Given standard、衰减窗口可配（测试缩为 2 天）。
// When 二次累犯后超过 2 天无再犯。
// Then 历史清零、本次按首次档（配置时长 1h）执法——衰减窗口不是写死 30 天。
func TestAutobanEscalation_decayWindowConfigurable(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	oldDecay := autobanRecidivismDecay
	autobanRecidivismDecay = 2 * 24 * time.Hour
	t.Cleanup(func() { autobanRecidivismDecay = oldDecay })
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "standard"}
	const ip = "45.33.32.15"

	escalationBan(t, cfg, ip)
	clock.Advance(time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)
	clock.Advance(time.Hour)
	escalationBan(t, cfg, ip)
	if count, _, _ := readRecidivismRow(t, ip); count != 2 {
		t.Fatalf("前置记账=%d, want 2", count)
	}

	// 二次封禁为 24h 条目：到期清理后再隔 25h（总距上次封禁 49h>48h 窗口）
	// → 历史清零，本次按首次档 1h。
	clock.Advance(24*time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)
	clock.Advance(25 * time.Hour)
	banStart := clock.Now()
	exp := escalationBan(t, cfg, ip)
	if got, want := exp, banStart.Add(time.Hour).Format(autobanTimeLayout); got != want {
		t.Fatalf("降级后到期=%q, want %q（首次档 1h）", got, want)
	}
	if count, _, escalated := readRecidivismRow(t, ip); count != 1 || escalated != "1h" {
		t.Fatalf("降级后记账=(%d,%q), want (1,1h)", count, escalated)
	}
}

// Given 已在名单的 IP（封禁中）再次达标。
// When merge。
// Then 不重复封禁、不重复记累犯（累犯只计真实新封）。
func TestAutobanEscalation_inListDoesNotDoubleCount(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "standard"}
	const ip = "45.33.32.16"

	if _, err := autobanMergeEntries(cfg, []AutobanSuggestion{{IP: ip, Count: 10}}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	out, err := autobanMergeEntries(cfg, []AutobanSuggestion{{IP: ip, Count: 10}})
	if err != nil {
		t.Fatalf("re-merge: %v", err)
	}
	if len(out.Banned) != 0 {
		t.Fatalf("已在名单不得重复封禁: %v", out.Banned)
	}
	if count, _, _ := readRecidivismRow(t, ip); count != 1 {
		t.Fatalf("重复候选记账=%d, want 1（只计真实新封）", count)
	}
}

// ---- 写侧配置校验 ----

func TestAutobanConfig_escalationValidation(t *testing.T) {
	base := AutobanConfig{Enabled: true, Threshold: 10, WindowMinutes: 5, Duration: "1h", Scope: "blocked"}
	for _, e := range []string{"off", "standard", "aggressive"} {
		cfg := base
		cfg.Escalation = e
		if err := ValidateAutobanConfig(cfg); err != nil {
			t.Fatalf("Escalation=%q 必须合法: %v", e, err)
		}
	}
	for _, e := range []string{"", "bogus", "OFF", "Standard", "off,standard"} {
		cfg := base
		cfg.Escalation = e
		if err := ValidateAutobanConfig(cfg); err == nil {
			t.Fatalf("Escalation=%q 必须拒绝", e)
		}
	}
}

// ---- 消费/写侧接线 ----

// Given 全新库。
// When 读配置。
// Then Escalation 默认 off（现行行为不变）。
func TestAutobanConfig_defaultsEscalationOff(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg, err := GetAutobanConfig()
	if err != nil {
		t.Fatalf("GetAutobanConfig: %v", err)
	}
	if cfg.Escalation != "off" {
		t.Fatalf("默认 Escalation=%q, want off", cfg.Escalation)
	}
}

// Given 写侧保存 standard。
// When 回读。
// Then 值落库且回读一致（写侧通道承载第七列）。
func TestAutobanConfig_setAndReadEscalation(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 10, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "standard"}
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("SetAutobanConfig: %v", err)
	}
	got, err := GetAutobanConfig()
	if err != nil {
		t.Fatalf("GetAutobanConfig: %v", err)
	}
	if got.Escalation != "standard" {
		t.Fatalf("回读 Escalation=%q, want standard", got.Escalation)
	}
}

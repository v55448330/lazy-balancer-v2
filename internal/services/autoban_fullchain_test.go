package services

// A+C 自动封禁全链端到端钉测（阶段 5 集成）：
//
//	事件喂入 → IPv6 /64 归一 → NAT 检测 → 复合键会话封禁（本地态）
//	→ IP 级执法（名单 + 累犯记账）→ 到期解封 → 累犯渐进升级
//	→ 集群快照携带累犯表 → 从端 apply 收敛（整表替换 + 节哈希奇偶）。
//
// 会话封禁经交换文件契约执法（lbhuman 侧消费钉测在 lbhuman 包，跨模块
// 不引入其依赖树）；本测试钉面板侧全链与集群传播面。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// chainRunCycle 跑一轮生产 Run 体（角色门读库 is_master，喂入缝恒主）。
func chainRunCycle(t *testing.T) {
	t.Helper()
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
}

// Given NAT 精修 + standard 升级启用；同 /64 隐私扩展轮换地址喂入攻击指纹
// 与两个无辜指纹，另有一裸 IPv4 无指纹攻击源与一保留地址。
// When 逐轮 RunAutobanCycle（封禁→到期→再犯）并做集群快照/从端 apply。
// Then 全链各段契约同时成立（归一/NAT/复合键/会话本地态/IP 执法/累犯升级/
// 集群收敛）。
func TestAutobanFullChain_endToEndWithClusterSync(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	sessionPath := sessionBanTestFile(t)
	database := db.GetDB()

	cfg := AutobanConfig{
		Enabled: true, Threshold: 3, WindowMinutes: 5, Duration: "1h", Scope: "blocked",
		Escalation: AutobanEscalationStandard, NatDetection: true, NatFingerprintThreshold: 3,
	}
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}

	// 集群装配：主从同库夹具（快照源=应用目标），Caddy 打桩。
	cluster := NewClusterService(database, "")
	t.Cleanup(func() { unregisterClusterService(cluster) })
	caddyStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(caddyStub.Close)
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyStub.URL}, NewCaddyService(caddyStub.URL))
	ctx := context.Background()

	// ---- 段 1：喂入 → /64 归一 → NAT 检测 → 复合键 ----
	// 同 /64 三个隐私扩展地址轮换：攻击指纹 c:evil 集中，两个无辜指纹各 1。
	addrs := []string{
		"2606:4700:abcd:1234:1111:2222:3333:4444",
		"2606:4700:abcd:1234:aaaa:bbbb:cccc:dddd",
		"2606:4700:abcd:1234::9",
	}
	for range 4 {
		natFeed(cfg, addrs[0], "c:evil")
	}
	natFeed(cfg, addrs[1], "c:innocent1")
	natFeed(cfg, addrs[2], "c:innocent2")
	if !natIsNAT(t, "2606:4700:abcd:1234::") {
		t.Fatal("段1：同 /64 轮换地址必须锚定单 NAT 剖面并触发 NAT 态")
	}
	// NAT 态后攻击指纹独立复合桶达标（阈值 3）。
	for range 3 {
		natFeed(cfg, addrs[1], "c:evil")
	}
	compositeKey := autobanIdentityKey("2606:4700:abcd:1234::", "c:evil")
	if keys := natWindowKeys(t); keys[compositeKey] != 3 {
		t.Fatalf("段1：攻击复合桶计数=%d, want 3（/64×指纹独立计数）", keys[compositeKey])
	}

	// 裸 IPv4 无指纹攻击源（IP 级通道）+ 保留地址（硬排除）。
	plainIP := "45.33.32.200"
	for range 3 {
		natFeed(cfg, plainIP, "")
	}
	for _, reserved := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.10", "::1", "fe80::1"} {
		for range 3 {
			natFeed(cfg, reserved, "")
		}
	}

	// ---- 段 2：Run 轮 → 会话封禁（本地态）+ IP 级执法 + 累犯首次记账 ----
	chainRunCycle(t)

	// 会话封禁：复合键进交换文件（短 TTL），不落 IP 名单。
	sessionSnap := sessionBanTestSnapshot(t, sessionPath)
	if len(sessionSnap.Bans) != 1 || sessionSnap.Bans[0].Key != compositeKey {
		t.Fatalf("段2：会话封禁交换=%+v, want 单条 %s", sessionSnap, compositeKey)
	}
	if n := AutobanActiveSessionBanCount(); n != 1 {
		t.Fatalf("段2：会话封禁生效数=%d, want 1", n)
	}
	// IP 名单：仅裸 IPv4（复合键零落名单）；保留地址零计入。
	entries := entryValues(presetEntries(t))
	if _, ok := entries[plainIP]; !ok {
		t.Fatalf("段2：IP 级候选必须落名单, entries=%v", entries)
	}
	for value := range entries {
		if strings.Contains(value, "|") {
			t.Fatalf("段2：复合键不得落 IP 名单: %s", value)
		}
	}
	if len(entries) != 1 {
		t.Fatalf("段2：保留地址不得计入（名单应仅 1 条）, entries=%v", entries)
	}
	// 累犯首次记账：standard 首档=配置时长 1h。
	if count, _, escalated := readRecidivismRow(t, plainIP); count != 1 || escalated != "1h" {
		t.Fatalf("段2：累犯首次记账=(%d,%q), want (1,1h)", count, escalated)
	}
	if entry := entries[plainIP]; entry.ExpiresAt != clock.Now().Add(time.Hour).Format(autobanTimeLayout) {
		t.Fatalf("段2：首次封禁到期=%q, want 配置时长 1h", entry.ExpiresAt)
	}

	// ---- 段 3：集群快照携带累犯表 + 会话封禁本地态不进快照 ----
	if _, err := database.Exec("UPDATE global_config SET cluster_version=100 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	snap := snapshotAsMaster(t, cluster, database)
	if snap.AutobanRecidivism == nil {
		t.Fatal("段3：快照必须携带累犯表")
	}
	var carried []recidivismRow
	if err := json.Unmarshal(snap.AutobanRecidivism, &carried); err != nil {
		t.Fatalf("段3：解析累犯载荷: %v", err)
	}
	if len(carried) != 1 || carried[0].Identity != plainIP || carried[0].Offenses != 1 || carried[0].Escalated != "1h" {
		t.Fatalf("段3：累犯载荷=%+v, want 单行 %s/1/1h", carried, plainIP)
	}
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "c:evil") || strings.Contains(string(wire), "session_ban") {
		t.Fatal("段3：会话封禁本地态不得进集群快照")
	}

	// ---- 段 4：从端 apply 收敛（整表替换 + 节哈希奇偶）----
	// 从端本地漂移：多余累犯行 + 同身份计数漂移。
	if _, err := database.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES ('45.33.32.99', 9, '2026-11-01 00:00:00', 'permanent')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE autoban_recidivism SET offense_count=5 WHERE identity=?`, plainIP); err != nil {
		t.Fatal(err)
	}
	if err := syncService.applySnapshot(ctx, snap); err != nil {
		t.Fatalf("段4：apply: %v", err)
	}
	got := readRecidivismRows(t, database)
	if len(got) != 1 || got[0].Identity != plainIP || got[0].Offenses != 1 || got[0].Escalated != "1h" {
		t.Fatalf("段4：apply 后累犯表=%+v, want 单行 %s/1/1h（整表替换收敛）", got, plainIP)
	}
	localHashes, err := cluster.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatalf("段4：drift guard: %v", err)
	}
	if localHashes["security"] != snap.SectionHashes["security"] {
		t.Fatalf("段4：security 节哈希主从不一致 master=%s local=%s", snap.SectionHashes["security"], localHashes["security"])
	}

	// 同库夹具：apply 以从端形态完成；后续再犯轮回到主节点语境
	// （RunAutobanCycle 角色门读库 is_master）。
	if _, err := database.Exec("UPDATE global_config SET is_master=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	// ---- 段 5：到期解封 → 再犯 → 累犯升级（standard 二次=24h）----
	clock.Advance(time.Hour + time.Minute) // 越过首次 1h 封禁
	chainRunCycle(t)                       // 到期清理（sweep）
	if _, ok := entryValues(presetEntries(t))[plainIP]; ok {
		t.Fatal("段5：到期条目必须自动解封")
	}
	clock.Advance(time.Hour) // 距上次封禁约 2h（衰减窗口内）
	for range 3 {
		natFeed(cfg, plainIP, "")
	}
	chainRunCycle(t)
	if count, _, escalated := readRecidivismRow(t, plainIP); count != 2 || escalated != "24h" {
		t.Fatalf("段5：累犯二次记账=(%d,%q), want (2,24h)（standard 升级）", count, escalated)
	}
	if entry := entryValues(presetEntries(t))[plainIP]; entry.ExpiresAt != clock.Now().Add(24*time.Hour).Format(autobanTimeLayout) {
		t.Fatalf("段5：二次封禁到期=%q, want 升级 24h", entry.ExpiresAt)
	}

	// ---- 段 6：升级后的累犯表随集群传播（二次快照 → 从端收敛）----
	if _, err := database.Exec("UPDATE global_config SET cluster_version=101 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	snap2 := snapshotAsMaster(t, cluster, database)
	if err := syncService.applySnapshot(ctx, snap2); err != nil {
		t.Fatalf("段6：apply: %v", err)
	}
	got2 := readRecidivismRows(t, database)
	if len(got2) != 1 || got2[0].Offenses != 2 || got2[0].Escalated != "24h" {
		t.Fatalf("段6：升级累犯行必须随快照收敛, got %+v", got2)
	}
}

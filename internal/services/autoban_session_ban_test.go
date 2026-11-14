package services

// 自动封禁会话级执法通道钉测（NAT 态复合候选的执法出口）：
//   - 会话封禁存储：内存 map（键=归一 IP|指纹）、短 TTL 可配、到期自动解封；
//   - 复合候选达阈 → 写会话封禁（不落 IP 名单、不污染 IP 累犯）；
//   - 本地态：交换文件只含未到期条目，集群快照不携带会话封禁；
//   - 会话执法独立于 IP 名单收敛（无 IP 引用面也交换）；
//   - 手动解封（AutobanForgetIPs）随母身份清会话封禁；
//   - IP 级路径回归：无指纹候选仍落 IP 名单（L4 与 IP ACL 不受影响）。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// sessionBanTestFile 把会话封禁交换文件指到临时目录（写读同源）。
func sessionBanTestFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "autoban-session-bans.json")
	restore := SetAutobanSessionBanFileForTest(path)
	t.Cleanup(restore)
	return path
}

// sessionBanTestSnapshot 读交换文件并解码（缺席=空载荷）。
func sessionBanTestSnapshot(t *testing.T, path string) AutobanSessionBanSnapshot {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return AutobanSessionBanSnapshot{}
	}
	if err != nil {
		t.Fatalf("read session ban file: %v", err)
	}
	var snap AutobanSessionBanSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("parse session ban file: %v", err)
	}
	return snap
}

// sessionBanFeedToNAT 把同 IP 喂成 NAT 态（攻击指纹 c:evil 集中），
// 返回攻击会话的复合键。natThreshold=3。
func sessionBanFeedToNAT(t *testing.T, cfg AutobanConfig, ip string) string {
	t.Helper()
	for range 4 {
		natFeed(cfg, ip, "c:evil")
	}
	natFeed(cfg, ip, "c:a")
	natFeed(cfg, ip, "c:b")
	if !natIsNAT(t, ip) {
		t.Fatal("given: NAT 态未触发")
	}
	return autobanIdentityKey(ip, "c:evil")
}

// ---- 存储：TTL 到期自动解封 ----

// Given 会话封禁 TTL=5 分钟，写入一条复合键封禁。
// When 推进时钟越过 TTL 后读生效视图/交换文件。
// Then 到期条目自动消失（无需清理循环）；未到期条目保留。
func TestAutobanSessionBan_ttlExpiresEntries(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	path := sessionBanTestFile(t)
	oldTTL := autobanSessionBanTTL
	autobanSessionBanTTL = 5 * time.Minute
	t.Cleanup(func() { autobanSessionBanTTL = oldTTL })

	key := autobanIdentityKey("2001:db8:1::1", "c:evil")
	autobanBanSession(key)
	if n := AutobanActiveSessionBanCount(); n != 1 {
		t.Fatalf("封禁写入后生效数=%d, want 1", n)
	}
	if snap := sessionBanTestSnapshot(t, path); len(snap.Bans) != 1 || snap.Bans[0].Key != key {
		t.Fatalf("交换文件=%+v, want 单条 %s", snap, key)
	}

	clock.Advance(5 * time.Minute)
	if n := AutobanActiveSessionBanCount(); n != 0 {
		t.Fatalf("TTL 到期后生效数=%d, want 0（到期自动解封）", n)
	}
	if snap := sessionBanTestSnapshot(t, path); len(snap.Bans) != 0 {
		t.Fatalf("到期后交换文件必须收敛为空, got %+v", snap)
	}
}

// ---- 复合候选执法：会话封禁替代 IP 名单 ----

// Given NAT 态复合候选达标（攻击指纹）+ IP 级候选达标（另一 IP）。
// When RunAutobanCycle。
// Then 复合候选进会话封禁存储与交换文件（TTL=短时长可配），IP 名单只收
// IP 级候选；会话封禁不写 IP 累犯表；今日封禁统计不计会话封禁（IP 口径不变）。
func TestAutobanRunCycle_compositeCandidateBansSessionNotIPList(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	path := sessionBanTestFile(t)
	oldTTL := autobanSessionBanTTL
	autobanSessionBanTTL = 10 * time.Minute
	t.Cleanup(func() { autobanSessionBanTTL = oldTTL })
	cfg := natTestCfg(3)
	cfg.Escalation = AutobanEscalationStandard
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}

	attackIP := "45.33.32.106"
	key := sessionBanFeedToNAT(t, cfg, attackIP)
	for range 3 {
		natFeed(cfg, attackIP, "c:evil") // 复合桶达标
	}
	plainIP := "45.33.32.200"
	for range 3 {
		natFeed(cfg, plainIP, "") // IP 级达标（无指纹）
	}

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("cycle: %v", err)
	}

	// IP 名单只含 IP 级候选；复合键零落名单。
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].Value != plainIP {
		t.Fatalf("IP 名单=%+v, want 仅 %s（复合候选不落名单）", entries, plainIP)
	}
	// 会话封禁存储与交换文件含复合键（TTL=10m）。
	snap := sessionBanTestSnapshot(t, path)
	if len(snap.Bans) != 1 || snap.Bans[0].Key != key {
		t.Fatalf("交换文件=%+v, want 单条 %s", snap, key)
	}
	wantExp := autobanNow().Add(10 * time.Minute).UnixMilli()
	if snap.Bans[0].ExpiresAtMS != wantExp {
		t.Fatalf("expires_at_ms=%d, want %d（短 TTL 可配）", snap.Bans[0].ExpiresAtMS, wantExp)
	}
	if n := AutobanActiveSessionBanCount(); n != 1 {
		t.Fatalf("会话封禁生效数=%d, want 1", n)
	}
	// 不污染 IP 累犯：只有 IP 级新封记账一行。
	rows, err := db.GetDB().Query(`SELECT identity FROM autoban_recidivism`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var identities []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		identities = append(identities, id)
	}
	if len(identities) != 1 || identities[0] != plainIP {
		t.Fatalf("累犯表=%v, want 仅 [%s]（会话封禁不污染 IP 累犯）", identities, plainIP)
	}
	// 今日封禁统计保持 IP 口径（会话封禁不计入）。
	if n := AutobanBannedToday(); n != 1 {
		t.Fatalf("今日封禁=%d, want 1（IP 口径，不含会话封禁）", n)
	}
	// 会话执法可观测：任务日志摘要行点名会话封禁数；审计留痕（独立动作，
	// 不混入 IP「自动封禁」——今日封禁统计口径不变）。
	if log := autobanLogNow(t); !strings.Contains(log, "会话封禁 1") {
		t.Fatalf("摘要行必须点名会话封禁数, log=%s", log)
	}
	var sessionAudits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE username='system' AND action=? AND detail LIKE ?`,
		AutobanSessionAuditAction, "%"+key+"%").Scan(&sessionAudits); err != nil {
		t.Fatal(err)
	}
	if sessionAudits != 1 {
		t.Fatalf("会话封禁审计=%d, want 1（逐会话留痕）", sessionAudits)
	}
}

// Given 观察模式（dry_run）+ NAT 态复合候选达标。
// When RunAutobanCycle。
// Then 零会话封禁（观察模式不执法，与 IP 名单同语义）。
func TestAutobanRunCycle_dryRunDoesNotBanSessions(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	sessionBanTestFile(t)
	cfg := natTestCfg(3)
	cfg.DryRun = true
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}
	ip := "45.33.32.108"
	sessionBanFeedToNAT(t, cfg, ip)
	for range 3 {
		natFeed(cfg, ip, "c:evil")
	}
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if n := AutobanActiveSessionBanCount(); n != 0 {
		t.Fatalf("观察模式不得执法, 会话封禁=%d", n)
	}
}

// ---- 执法独立于 IP 名单收敛 ----

// Given 预置名单未被任何策略引用（无 IP 发射面），NAT 态复合候选达标。
// When RunAutobanCycle。
// Then 会话封禁照常写入并交换（会话执法走挑战链，不依赖 IP 名单引用面）；
// 不触发投影刷新/全量重载（IP 名单无变化）。
func TestAutobanRunCycle_sessionEnforcementIndependentOfIPListRefs(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	path := sessionBanTestFile(t)
	cfg := natTestCfg(3)
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}
	spy := installAutobanConvergeSpy(t, func() (IPListProjectionOutcome, error) { return ProjectionConverged, nil })

	ip := "45.33.32.109"
	key := sessionBanFeedToNAT(t, cfg, ip)
	for range 3 {
		natFeed(cfg, ip, "c:evil")
	}
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if snap := sessionBanTestSnapshot(t, path); len(snap.Bans) != 1 || snap.Bans[0].Key != key {
		t.Fatalf("无 IP 引用面也必须交换会话封禁, got %+v", snap)
	}
	if spy.refreshes != 0 || spy.reloads != 0 {
		t.Fatalf("纯会话封禁不得触发 IP 名单收敛: refreshes=%d reloads=%d", spy.refreshes, spy.reloads)
	}
}

// ---- 手动解封 ----

// Given 会话封禁在役（复合键）。
// When 手动解封母 IP（AutobanForgetIPs）。
// Then 该 IP 全部会话封禁随母身份清除并交换（删除即解封不被撤销）。
func TestAutobanForgetIPs_clearsSessionBans(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	path := sessionBanTestFile(t)
	ip := "45.33.32.110"
	autobanBanSession(autobanIdentityKey(ip, "c:evil"))
	autobanBanSession(autobanIdentityKey(ip, "c:other"))
	autobanBanSession(autobanIdentityKey("45.33.32.111", "c:keep"))

	AutobanForgetIPs([]string{ip})

	snap := sessionBanTestSnapshot(t, path)
	if len(snap.Bans) != 1 || snap.Bans[0].Key != autobanIdentityKey("45.33.32.111", "c:keep") {
		t.Fatalf("解封后交换文件=%+v, want 仅保留他 IP 会话", snap)
	}
}

// Given 自动封禁禁用收尾。
// When AutobanDisableFlush。
// Then 会话封禁全清并交换空载荷（禁用=执法通道关闭，与计数桶清空同语义）。
func TestAutobanDisableFlush_clearsSessionBans(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	path := sessionBanTestFile(t)
	setAutobanConfigRaw(t, true, 3, 5, "1h", "blocked", false)
	autobanBanSession(autobanIdentityKey("45.33.32.112", "c:evil"))

	AutobanDisableFlush()

	if n := AutobanActiveSessionBanCount(); n != 0 {
		t.Fatalf("禁用收尾后会话封禁=%d, want 0", n)
	}
	if snap := sessionBanTestSnapshot(t, path); len(snap.Bans) != 0 {
		t.Fatalf("禁用收尾必须交换空载荷, got %+v", snap)
	}
}

// ---- 本地态：不跨节点同步 ----

// Given 会话封禁在役。
// When 构建集群全量快照。
// Then 快照不携带会话封禁（本地短 TTL 态，跨节点同步是后续阶段）。
func TestAutobanSessionBan_notInClusterSnapshot(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	sessionBanTestFile(t)
	autobanBanSession(autobanIdentityKey("45.33.32.113", "c:evil"))

	cluster, database := newClusterTestService(t)
	snapshot, err := cluster.buildFullSnapshot(context.Background(), database)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "c:evil") || strings.Contains(string(raw), "session_ban") {
		t.Fatal("集群快照不得携带会话封禁（本地态不跨节点同步）")
	}
}

// ---- IP 级路径回归（L4/IP ACL 不受影响） ----

// Given NatDetection 关闭（默认 IP 级），无指纹候选达标。
// When RunAutobanCycle。
// Then 照常落 IP 名单（L4 与 IP ACL 消费的名单通道零变化），零会话封禁。
func TestAutobanRunCycle_ipLevelUnaffectedBySessionChannel(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	sessionBanTestFile(t)
	setAutobanConfigRaw(t, true, 3, 5, "1h", "blocked", false)
	for range 3 {
		autobanObserveEvent("45.33.32.120", "blocked", "942100")
	}
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if _, ok := entryValues(presetEntries(t))["45.33.32.120"]; !ok {
		t.Fatal("IP 级封禁必须照常落名单（L4/IP ACL 通道不受会话执法影响）")
	}
	if n := AutobanActiveSessionBanCount(); n != 0 {
		t.Fatalf("IP 级候选不得产生会话封禁, got %d", n)
	}
}

// ---- 存储边界 ----

// Given 会话封禁键上限收窄为 2。
// When 写入 3 条不同复合键。
// Then 超限丢新键（内存有界，与计数桶同族裁定），既有封禁不受影响。
func TestAutobanSessionBan_capacityDropsNewKeys(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	sessionBanTestFile(t)
	oldCap := autobanMaxSessionBans
	autobanMaxSessionBans = 2
	t.Cleanup(func() { autobanMaxSessionBans = oldCap })

	autobanBanSession(autobanIdentityKey("45.33.32.130", "c:a"))
	autobanBanSession(autobanIdentityKey("45.33.32.131", "c:b"))
	autobanBanSession(autobanIdentityKey("45.33.32.132", "c:c"))

	if n := AutobanActiveSessionBanCount(); n != 2 {
		t.Fatalf("超限后会话封禁数=%d, want 2（丢新键保既有）", n)
	}
}

// Given 非复合键（裸 IP）误入会话封禁入口。
// When autobanBanSession。
// Then 拒绝（会话封禁只认复合身份，IP 级封禁走名单通道）。
func TestAutobanSessionBan_rejectsNonCompositeKey(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	sessionBanTestFile(t)
	autobanBanSession("45.33.32.140")
	if n := AutobanActiveSessionBanCount(); n != 0 {
		t.Fatalf("裸 IP 不得进会话封禁存储, got %d", n)
	}
}

// 交换文件载荷形态回归：键含分隔符 | 的复合身份原样保留（插件侧按首个 |
// 拆归一 IP 与指纹），时间戳为 unix 毫秒（与插件时钟同单位）。
func TestAutobanSessionBan_snapshotShape(t *testing.T) {
	path := sessionBanTestFile(t)
	key := autobanIdentityKey("2001:db8:2::1", "u:abcdef0123456789")
	autobanBanSession(key)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Bans []struct {
			Key         string `json:"key"`
			ExpiresAtMS int64  `json:"expires_at_ms"`
		} `json:"bans"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("载荷必须是 {bans:[{key,expires_at_ms}]}: %v (%s)", err, raw)
	}
	if len(payload.Bans) != 1 || payload.Bans[0].Key != key {
		t.Fatalf("载荷=%s, want key=%s", raw, key)
	}
	if payload.Bans[0].ExpiresAtMS <= autobanNow().UnixMilli() {
		t.Fatalf("expires_at_ms=%d 必须在未来", payload.Bans[0].ExpiresAtMS)
	}
}

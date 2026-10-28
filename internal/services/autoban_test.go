package services

// 自动封禁核心行为钉：固定桶计数器（重置语义/上限保护）、摄取
// 提交点喂入门（主节点+启用+口径+WAF 事件）、名单 merge（清到期/保留手动/
// 已在名单过滤/超限挤最早到期）、重载节流（<60s 暂存合并）、EnabledFn
// fail-closed、配置校验与口径/窗口变更重置、投影层过期条目过滤。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// ---- 夹具 ----

// autobanTestClock 可注入时钟（重置语义/节流/到期窗口断言的时间轴）。
type autobanTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newAutobanTestClock(start string) *autobanTestClock {
	ts, _ := time.ParseInLocation("2006-01-02 15:04:05", start, time.UTC)
	return &autobanTestClock{now: ts}
}

func (c *autobanTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *autobanTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// installAutobanFixture：初始化临时库+接管全局时钟缝。LIFO 清理还原。
func installAutobanFixture(t *testing.T, start string) *autobanTestClock {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })

	clock := newAutobanTestClock(start)
	oldNow := autobanNow
	autobanNow = clock.Now
	t.Cleanup(func() { autobanNow = oldNow })

	// 默认主节点（喂入门默认通过——主节点门单独有负向钉测）。
	oldMaster := autobanIsMaster
	autobanIsMaster = func() bool { return true }
	t.Cleanup(func() { autobanIsMaster = oldMaster })

	resetAutobanStateForTest()
	t.Cleanup(resetAutobanStateForTest)
	return clock
}

func resetAutobanStateForTest() {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanWindows = make(map[string]*autobanCounter)
	autobanSuggestions = nil
	autobanReloadPending = false
	autobanLastReload = time.Time{}
	autobanCapWarned = false
	autobanFeedDegradedWarned = false
}

// setAutobanConfigRaw 直接写列（绕过 SetAutobanConfig 的重置副作用——
// 重置语义单独钉）。
func setAutobanConfigRaw(t *testing.T, enabled bool, threshold, windowMin int, duration, scope string, dryRun bool) {
	t.Helper()
	ei, di := 0, 0
	if enabled {
		ei = 1
	}
	if dryRun {
		di = 1
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=?, autoban_threshold=?, autoban_window_minutes=?, autoban_duration=?, autoban_scope=?, autoban_dry_run=? WHERE id=1`,
		ei, threshold, windowMin, duration, scope, di); err != nil {
		t.Fatalf("seed autoban config: %v", err)
	}
}

func presetListID(t *testing.T) int64 {
	t.Helper()
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, AutobanPresetListName).Scan(&id); err != nil {
		t.Fatalf("preset list missing: %v", err)
	}
	return id
}

func presetEntries(t *testing.T) []models.IPListEntry {
	t.Helper()
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, presetListID(t)).Scan(&raw); err != nil {
		t.Fatalf("read preset entries: %v", err)
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatalf("parse preset entries %q: %v", raw, err)
	}
	return entries
}

func entryValues(entries []models.IPListEntry) map[string]models.IPListEntry {
	m := make(map[string]models.IPListEntry, len(entries))
	for _, e := range entries {
		m[e.Value] = e
	}
	return m
}

// ---- 计数器：固定桶重置语义 ----

// Given 同一 IP 在窗口内多次命中。
// When 跨过窗口边界后再命中。
// Then 计数从新窗口起算（固定桶重置），不与旧窗口累计。
func TestAutobanCounter_fixedWindowResets(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 3, 5, "1h", "all", true)

	autobanObserveEvent("203.0.113.7", "blocked", "942100")
	autobanObserveEvent("203.0.113.7", "blocked", "942100")
	f.Advance(6 * time.Minute) // 越过 5 分钟窗口
	autobanObserveEvent("203.0.113.7", "blocked", "942100")

	autobanMu.Lock()
	w := autobanWindows["203.0.113.7"]
	autobanMu.Unlock()
	if w == nil || w.Count != 1 {
		t.Fatalf("跨窗口后计数应重置为 1，得到 %+v", w)
	}
}

// Given 计数器键达到上限。
// When 新键继续喂入。
// Then 新键丢弃并告警一次；既有键不受影响继续累计。
func TestAutobanCounter_capProtection(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", true)
	oldCap := autobanMaxTrackedIPs
	autobanMaxTrackedIPs = 3
	t.Cleanup(func() { autobanMaxTrackedIPs = oldCap })

	for i := range 3 {
		autobanObserveEvent(fmt.Sprintf("198.51.100.%d", i+1), "blocked", "942100")
	}
	autobanObserveEvent("203.0.113.99", "blocked", "942100") // 超限新键→丢弃
	autobanObserveEvent("198.51.100.1", "blocked", "942100") // 既有键→继续累计

	autobanMu.Lock()
	defer autobanMu.Unlock()
	if _, exists := autobanWindows["203.0.113.99"]; exists {
		t.Fatal("超限新键不得进入计数器")
	}
	if autobanWindows["198.51.100.1"].Count != 2 {
		t.Fatalf("既有键计数=%d, want 2（超限不挤占既有键）", autobanWindows["198.51.100.1"].Count)
	}
	if !autobanCapWarned {
		t.Fatal("超限丢弃必须置位告警标记（留痕）")
	}
}

func TestResetAutobanCounters_rearmsCapWarning(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	autobanMu.Lock()
	autobanCapWarned = true
	autobanWindows["203.0.113.1"] = &autobanCounter{Count: 3}
	autobanSuggestions = []AutobanSuggestion{{IP: "203.0.113.1", Count: 3}}
	autobanMu.Unlock()

	ResetAutobanCounters()

	autobanMu.Lock()
	defer autobanMu.Unlock()
	if autobanCapWarned {
		t.Fatal("计数口径重置后必须重新允许上限告警")
	}
	if len(autobanWindows) != 0 || len(autobanSuggestions) != 0 {
		t.Fatalf("计数桶/建议未清空: windows=%d suggestions=%d", len(autobanWindows), len(autobanSuggestions))
	}
}

// ---- 摄取喂入门：主节点+启用+口径+WAF 事件 ----

func TestAutobanObserve_gates(t *testing.T) {
	t.Run("非主节点不喂", func(t *testing.T) {
		installAutobanFixture(t, "2026-10-14 10:00:00")
		setAutobanConfigRaw(t, true, 1, 5, "1h", "all", true)
		oldMaster := autobanIsMaster
		autobanIsMaster = func() bool { return false }
		t.Cleanup(func() { autobanIsMaster = oldMaster })
		autobanObserveEvent("203.0.113.1", "blocked", "942100")
		autobanMu.Lock()
		n := len(autobanWindows)
		autobanMu.Unlock()
		if n != 0 {
			t.Fatalf("非主节点不得喂计数器，得到 %d 键", n)
		}
	})
	t.Run("未启用不喂", func(t *testing.T) {
		installAutobanFixture(t, "2026-10-14 10:00:00")
		setAutobanConfigRaw(t, false, 1, 5, "1h", "all", true)
		autobanObserveEvent("203.0.113.1", "blocked", "942100")
		autobanMu.Lock()
		n := len(autobanWindows)
		autobanMu.Unlock()
		if n != 0 {
			t.Fatalf("未启用不得喂计数器，得到 %d 键", n)
		}
	})
	t.Run("非WAF事件不喂", func(t *testing.T) {
		installAutobanFixture(t, "2026-10-14 10:00:00")
		setAutobanConfigRaw(t, true, 1, 5, "1h", "all", true)
		autobanObserveEvent("203.0.113.1", "blocked", "")
		autobanMu.Lock()
		n := len(autobanWindows)
		autobanMu.Unlock()
		if n != 0 {
			t.Fatalf("rule_triggered 为空（非 WAF 事件）不得喂计数器，得到 %d 键", n)
		}
	})
	t.Run("口径过滤blocked", func(t *testing.T) {
		installAutobanFixture(t, "2026-10-14 10:00:00")
		setAutobanConfigRaw(t, true, 1, 5, "1h", "blocked", true)
		autobanObserveEvent("203.0.113.1", "logged", "942100")
		autobanObserveEvent("203.0.113.2", "blocked", "942100")
		autobanMu.Lock()
		_, loggedFed := autobanWindows["203.0.113.1"]
		_, blockedFed := autobanWindows["203.0.113.2"]
		autobanMu.Unlock()
		if loggedFed {
			t.Fatal("scope=blocked 时 logged 事件不得喂入")
		}
		if !blockedFed {
			t.Fatal("scope=blocked 时 blocked 事件必须喂入")
		}
	})
	t.Run("口径过滤logged", func(t *testing.T) {
		installAutobanFixture(t, "2026-10-14 10:00:00")
		setAutobanConfigRaw(t, true, 1, 5, "1h", "logged", true)
		autobanObserveEvent("203.0.113.1", "blocked", "942100")
		autobanObserveEvent("203.0.113.2", "logged", "942100")
		autobanMu.Lock()
		_, blockedFed := autobanWindows["203.0.113.1"]
		_, loggedFed := autobanWindows["203.0.113.2"]
		autobanMu.Unlock()
		if blockedFed || !loggedFed {
			t.Fatalf("scope=logged 口径失真：blocked 喂入=%v logged 喂入=%v", blockedFed, loggedFed)
		}
	})
}

// Given 验证爬虫豁免与爬虫伪装拦截同时进入自动封禁喂入。
// When 按来源资格过滤。
// Then 只排除真实豁免段，伪装 deny 与普通 WAF 事件继续计数，畸形 ID 不误排除。
func TestAutobanObserve_crawlerSpoofRemainsEligible(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", true)

	autobanObserveBatch([]autobanFeedItem{
		{IP: "203.0.113.10", Action: "logged", RuleTriggered: "810016"},
		{IP: "203.0.113.11", Action: "blocked", RuleTriggered: "850001"},
		{IP: "203.0.113.12", Action: "blocked", RuleTriggered: "899999"},
		{IP: "203.0.113.13", Action: "blocked", RuleTriggered: "942100"},
		{IP: "203.0.113.14", Action: "blocked", RuleTriggered: "not-a-rule"},
	})

	autobanMu.Lock()
	defer autobanMu.Unlock()
	if autobanWindows["203.0.113.10"] != nil {
		t.Fatal("验证爬虫豁免事件不得进入自动封禁计数")
	}
	for _, ip := range []string{"203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14"} {
		if w := autobanWindows[ip]; w == nil || w.Count != 1 {
			t.Fatalf("%s 计数=%+v, want 1（伪装/普通/畸形 ID 不得误排除）", ip, w)
		}
	}
}

// 信任豁免门：TrustExempt 事件不得计数（信任 IP 在 DetectionOnly 下产生
// logged 事件；豁免失效＝信任名单被自动封禁，互斥安全语义失效），同批
// 非豁免事件照常计数。
func TestAutobanObserveBatch_trustExemptEventsDoNotCount(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "all", true)

	autobanObserveBatch([]autobanFeedItem{
		{IP: "203.0.113.20", Action: "logged", RuleTriggered: "942100", TrustExempt: true},
		{IP: "203.0.113.20", Action: "blocked", RuleTriggered: "942100"},
		{IP: "203.0.113.21", Action: "blocked", RuleTriggered: "942100", TrustExempt: true},
	})

	autobanMu.Lock()
	defer autobanMu.Unlock()
	w := autobanWindows["203.0.113.20"]
	if w == nil || w.Count != 1 || w.Reached {
		t.Fatalf("203.0.113.20 计数=%+v, want 1 且未达标（豁免事件不得计数）", w)
	}
	if _, ok := autobanWindows["203.0.113.21"]; ok {
		t.Fatal("信任豁免事件不得进入计数器（信任 IP 的 logged 事件不可触发封禁）")
	}
}

// 积压回放门：早于当前窗口的事件（摄取停摆恢复/轮转补采）不得按到达时间
// 计数——否则数小时前的积压一次性到达即瞬时达标、批量误封。
func TestAutobanObserveBatch_backlogOutsideWindowDoesNotCount(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "all", true)
	now := autobanNow()

	autobanObserveBatch([]autobanFeedItem{
		{IP: "203.0.113.30", Action: "blocked", RuleTriggered: "942100", At: now.Add(-6 * time.Minute)},
		{IP: "203.0.113.30", Action: "blocked", RuleTriggered: "942100", At: now.Add(-4 * time.Minute)},
		{IP: "203.0.113.31", Action: "blocked", RuleTriggered: "942100", At: now.Add(-4 * time.Minute)},
		{IP: "203.0.113.31", Action: "blocked", RuleTriggered: "942100", At: now},
	})

	autobanMu.Lock()
	defer autobanMu.Unlock()
	if w := autobanWindows["203.0.113.30"]; w == nil || w.Count != 1 || w.Reached {
		t.Fatalf("窗口外积压事件被计数：%+v, want Count=1 且未达标", w)
	}
	if w := autobanWindows["203.0.113.31"]; w == nil || w.Count != 2 || !w.Reached {
		t.Fatalf("窗口内事件必须计数并达标：%+v, want Count=2/Reached", w)
	}
}

// ---- 配置：校验 + 口径/窗口变更重置 ----

func TestAutobanConfig_validation(t *testing.T) {
	for _, d := range []string{"10m", "30m", "1h", "6h", "12h", "24h", "permanent"} {
		if !ValidAutobanDuration(d) {
			t.Errorf("ValidAutobanDuration(%q)=false, want true", d)
		}
	}
	for _, d := range []string{"", "5m", "2h", "forever", "1H"} {
		if ValidAutobanDuration(d) {
			t.Errorf("ValidAutobanDuration(%q)=true, want false", d)
		}
	}
	for _, s := range []string{"blocked", "logged", "all"} {
		if !ValidAutobanScope(s) {
			t.Errorf("ValidAutobanScope(%q)=false, want true", s)
		}
	}
	for _, s := range []string{"", "deny", "BLOCKED"} {
		if ValidAutobanScope(s) {
			t.Errorf("ValidAutobanScope(%q)=true, want false", s)
		}
	}
}

// Given 计数器已有键。
// When 窗口或口径配置变更。
// Then 计数器清空（口径/窗口变更重置语义）；仅改其他字段不清空。
func TestAutobanSetConfig_resetsCountersOnWindowOrScopeChange(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "all", true)
	autobanObserveEvent("203.0.113.1", "blocked", "942100")

	// 同值写（仅改阈值）→ 不清空
	if err := SetAutobanConfig(AutobanConfig{Enabled: true, Threshold: 50, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true}); err != nil {
		t.Fatalf("SetAutobanConfig: %v", err)
	}
	autobanMu.Lock()
	n := len(autobanWindows)
	autobanMu.Unlock()
	if n != 1 {
		t.Fatalf("未变更窗口/口径时计数器不得清空，得到 %d 键", n)
	}

	// 变更窗口 → 清空
	if err := SetAutobanConfig(AutobanConfig{Enabled: true, Threshold: 50, WindowMinutes: 10, Duration: "1h", Scope: "all", DryRun: true}); err != nil {
		t.Fatalf("SetAutobanConfig window: %v", err)
	}
	autobanMu.Lock()
	n = len(autobanWindows)
	autobanMu.Unlock()
	if n != 0 {
		t.Fatalf("窗口变更必须重置计数器，残留 %d 键", n)
	}

	// 变更口径 → 清空
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	if err := SetAutobanConfig(AutobanConfig{Enabled: true, Threshold: 50, WindowMinutes: 10, Duration: "1h", Scope: "blocked", DryRun: true}); err != nil {
		t.Fatalf("SetAutobanConfig scope: %v", err)
	}
	autobanMu.Lock()
	n = len(autobanWindows)
	autobanMu.Unlock()
	if n != 0 {
		t.Fatalf("口径变更必须重置计数器，残留 %d 键", n)
	}
}

// 仅改阈值：保留计数桶，但 Reached 标记必须按新阈值重算——否则调低阈值后
// 一个窗口内 /status「达阈值 M 个」与过期摘要仍按旧阈值（观察模式下用户
// 误以为调低无效）。
func TestAutobanSetConfig_recomputesReachedOnThresholdChange(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 5, 5, "1h", "all", true)
	for range 3 {
		autobanObserveEvent("203.0.113.9", "blocked", "942100")
	}
	if got := autobanReachedCount(); got != 0 {
		t.Fatalf("reached=%d, want 0（3 次 < 阈值 5）", got)
	}
	// 调低阈值到 2：既有计数桶不丢，Reached 立即按新阈值成立
	if err := SetAutobanConfig(AutobanConfig{Enabled: true, Threshold: 2, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true}); err != nil {
		t.Fatalf("SetAutobanConfig: %v", err)
	}
	if got := autobanReachedCount(); got != 1 {
		t.Fatalf("reached=%d, want 1（调低阈值后已达标 IP 必须立即计入）", got)
	}
	// 调高阈值到 10：同一计数桶回落到未达标
	if err := SetAutobanConfig(AutobanConfig{Enabled: true, Threshold: 10, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true}); err != nil {
		t.Fatalf("SetAutobanConfig raise: %v", err)
	}
	if got := autobanReachedCount(); got != 0 {
		t.Fatalf("reached=%d, want 0（调高阈值后不得继续多报）", got)
	}
}

func TestAutobanSetConfig_syncsEngineLoop(t *testing.T) {
	// Given：autoban 业务关闭、调度关闭。
	te := newWireTestEngine(t)
	setAutobanConfigRaw(t, false, 1, 5, "1h", "all", true)
	te.StopLoop(AutobanTaskID)
	loopOn := func() bool {
		meta, ok := te.Lookup(AutobanTaskID)
		if !ok {
			t.Fatal("autoban 未注册")
		}
		return meta.LoopOn
	}
	if loopOn() {
		t.Fatal("前置态错误：调度应关闭")
	}

	// When/Then：服务写侧启用立即开调度。
	if err := SetAutobanConfig(AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if !loopOn() {
		t.Error("SetAutobanConfig 启用后 LoopOn=false，业务与调度分叉")
	}
	// And：服务写侧禁用立即停调度。
	if err := SetAutobanConfig(AutobanConfig{Enabled: false, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if loopOn() {
		t.Error("SetAutobanConfig 禁用后 LoopOn=true，业务与调度分叉")
	}
}

func TestAutobanSetConfig_rejectsOutOfRange(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cases := []AutobanConfig{
		{Enabled: true, Threshold: 0, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true},
		{Enabled: true, Threshold: 10001, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true},
		{Enabled: true, Threshold: 100, WindowMinutes: 0, Duration: "1h", Scope: "all", DryRun: true},
		{Enabled: true, Threshold: 100, WindowMinutes: 61, Duration: "1h", Scope: "all", DryRun: true},
		{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "2h", Scope: "all", DryRun: true},
		{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "deny", DryRun: true},
	}
	for i, cfg := range cases {
		if err := SetAutobanConfig(cfg); err == nil {
			t.Errorf("case %d (%+v) 应校验拒绝", i, cfg)
		}
	}
}

// ---- EnabledFn：fail-closed ----

func TestAutobanEnabledFn(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, false, 100, 5, "1h", "all", true)
	if AutobanEnabled() {
		t.Fatal("autoban_enabled=0 时 AutobanEnabled() 应为 false")
	}
	setAutobanConfigRaw(t, true, 100, 5, "1h", "all", true)
	if !AutobanEnabled() {
		t.Fatal("autoban_enabled=1 时 AutobanEnabled() 应为 true")
	}
	swapBrokenDB(t)
	if AutobanEnabled() {
		t.Fatal("读库失败应 fail-closed（false）")
	}
}

// ---- 名单 merge ----

func seedPresetEntries(t *testing.T, entries []models.IPListEntry) {
	t.Helper()
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE id=?`, string(raw), presetListID(t)); err != nil {
		t.Fatalf("seed preset entries: %v", err)
	}
}

// Given 名单含「已到期自动条目/手动条目/未到期自动条目」；候选含「已在名单/
// 新 IP」。
// When 执行 merge。
// Then 到期条目清除、手动条目保留、已在名单 IP 不重复追加、新 IP 带到期时间追加。
func TestAutobanMerge_expiryManualAndNewEntries(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "198.51.100.1", Remark: autobanEntryRemark, CreatedAt: "2026-10-13 10:00:00", ExpiresAt: "2026-10-14 09:00:00"}, // 已到期
		{Value: "198.51.100.2", Remark: "事件处置", CreatedAt: "2026-10-13 10:00:00"},                                               // 手动条目
		{Value: "198.51.100.3", Remark: autobanEntryRemark, CreatedAt: "2026-10-14 09:30:00", ExpiresAt: "2026-10-14 10:30:00"}, // 未到期
	})

	out, err := autobanMergeEntries(AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: false},
		[]AutobanSuggestion{
			{IP: "198.51.100.3", Count: 10},  // 已在名单→跳过
			{IP: "203.0.113.10", Count: 120}, // 新封
			{IP: "203.0.113.11", Count: 101}, // 新封
		})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	entries := entryValues(presetEntries(t))
	if _, exists := entries["198.51.100.1"]; exists {
		t.Fatal("到期条目必须清除")
	}
	if e, exists := entries["198.51.100.2"]; !exists || e.Remark != "事件处置" {
		t.Fatalf("手动条目必须原样保留，得到 %+v", e)
	}
	newEntry, exists := entries["203.0.113.10"]
	if !exists {
		t.Fatal("新 IP 必须追加")
	}
	if newEntry.Remark != autobanEntryRemark {
		t.Fatalf("新封条目 remark=%q, want %q", newEntry.Remark, autobanEntryRemark)
	}
	exp, perr := time.ParseInLocation("2006-01-02 15:04:05", newEntry.ExpiresAt, time.UTC)
	if perr != nil {
		t.Fatalf("新封条目 expires_at=%q 不可解析", newEntry.ExpiresAt)
	}
	want := f.Now().Add(time.Hour)
	if d := exp.Sub(want); d > time.Second || d < -time.Second {
		t.Fatalf("expires_at=%s, want ≈%s", newEntry.ExpiresAt, want)
	}
	if newEntry.CreatedAt == "" {
		t.Fatal("新封条目必须带 created_at")
	}
	if !out.Changed {
		t.Fatal("有清除+新增时 Changed 必须为 true")
	}
	if len(out.Banned) != 2 || len(out.Expired) != 1 {
		t.Fatalf("merge 计数失真：banned=%v expired=%v", out.Banned, out.Expired)
	}
}

// 删除即解封（2026-10-15 用户裁定）：无抑制窗口——名单条目被手动删除后，
// 同一 IP 重新达标必须重新封禁（钉住「不存在抑制过滤」的 merge 语义）。

// Given 名单含某 IP 的自动条目（封禁中）。
// When 手动删除该条目（remove-ip/弹框删除的等价形态：条目移除、无任何残留），
// 且该 IP 再次跨阈值进入候选。
// Then merge 重新封禁该 IP（带新 created_at/expires_at）。
func TestAutobanMerge_reQualifiesAfterManualDelete(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: false}
	candidates := []AutobanSuggestion{{IP: "203.0.113.9", Count: 10}}

	// 封禁中：已在名单 → 不重复追加
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "203.0.113.9", Remark: autobanEntryRemark, CreatedAt: "2026-10-14 09:00:00", ExpiresAt: "2026-10-14 11:00:00"},
	})
	out, err := autobanMergeEntries(cfg, candidates)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out.Banned) != 0 || out.Changed {
		t.Fatalf("名单内 IP 不得重复封禁：banned=%v changed=%v", out.Banned, out.Changed)
	}

	// 手动删除条目（删除即解封，无抑制痕迹）
	seedPresetEntries(t, []models.IPListEntry{})

	// 重新达标 → 重新封禁
	out, err = autobanMergeEntries(cfg, candidates)
	if err != nil {
		t.Fatalf("re-merge: %v", err)
	}
	if len(out.Banned) != 1 || out.Banned[0] != "203.0.113.9" {
		t.Fatalf("删除后重新达标必须重新封禁，得到 banned=%v", out.Banned)
	}
	entry, exists := entryValues(presetEntries(t))["203.0.113.9"]
	if !exists || entry.CreatedAt != "2026-10-14 10:00:00" {
		t.Fatalf("重封条目=%+v, want 新 created_at=2026-10-14 10:00:00", entry)
	}
}

// Given 名单条目接近上限。
// When 新封导致超限。
// Then 优先挤出最早到期的自动条目；手动条目不挤出；仅剩永久自动条目可挤时
// 挤永久条目。
func TestAutobanMerge_evictsEarliestExpiringAutobanEntries(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	oldCap := AutobanListEntryCap
	t.Cleanup(func() { AutobanListEntryCap = oldCap })

	t.Run("最早到期自动条目先挤", func(t *testing.T) {
		AutobanListEntryCap = 4
		seedPresetEntries(t, []models.IPListEntry{
			{Value: "198.51.100.2", Remark: "事件处置"},                                               // 手动
			{Value: "198.51.100.3", Remark: autobanEntryRemark, ExpiresAt: "2026-10-14 12:00:00"}, // 自动，晚到期
			{Value: "198.51.100.4", Remark: autobanEntryRemark, ExpiresAt: "2026-10-14 11:00:00"}, // 自动，最早到期
			{Value: "198.51.100.6", Remark: autobanEntryRemark, CreatedAt: "2026-10-13 10:00:00"}, // 自动，永久
		})
		out, err := autobanMergeEntries(AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: false},
			[]AutobanSuggestion{{IP: "203.0.113.10", Count: 120}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		entries := entryValues(presetEntries(t))
		if len(entries) != AutobanListEntryCap {
			t.Fatalf("条目数=%d, want 恰好上限 %d", len(entries), AutobanListEntryCap)
		}
		if _, exists := entries["198.51.100.4"]; exists {
			t.Fatal("最早到期自动条目必须先被挤出")
		}
		if _, exists := entries["198.51.100.2"]; !exists {
			t.Fatal("手动条目不得挤出")
		}
		if _, exists := entries["203.0.113.10"]; !exists {
			t.Fatal("挤出一个后应容纳新封")
		}
		if out.Evicted != 1 {
			t.Fatalf("evicted=%d, want 1", out.Evicted)
		}
	})

	t.Run("仅剩永久自动条目时挤永久", func(t *testing.T) {
		AutobanListEntryCap = 2
		seedPresetEntries(t, []models.IPListEntry{
			{Value: "198.51.100.2", Remark: "事件处置"},                                               // 手动
			{Value: "198.51.100.7", Remark: autobanEntryRemark, CreatedAt: "2026-10-13 08:00:00"}, // 自动，永久
		})
		out, err := autobanMergeEntries(AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "permanent", Scope: "all", DryRun: false},
			[]AutobanSuggestion{{IP: "203.0.113.10", Count: 120}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		entries := entryValues(presetEntries(t))
		if len(entries) != AutobanListEntryCap {
			t.Fatalf("条目数=%d, want 恰好上限 %d", len(entries), AutobanListEntryCap)
		}
		if _, exists := entries["198.51.100.7"]; exists {
			t.Fatal("容量不足时永久自动条目必须被挤出（手动条目不挤）")
		}
		if _, exists := entries["203.0.113.10"]; !exists {
			t.Fatal("挤出永久条目后应容纳新封")
		}
		if out.Evicted != 1 {
			t.Fatalf("evicted=%d, want 1", out.Evicted)
		}
	})
}

// 容量挤出清桶（挤出=解封同语义，否则挤出→下轮重封轮转） ----

// Given 满容量名单（自动条目）+ 新达标候选触发挤出。
// When autobanMergeEntries 完成容量收敛。
// Then merge 结果必须携带被挤出条目的 IP 身份（EvictedIPs），供调用方
// 同步清计数桶与落容量收敛留痕。
func TestAutobanMerge_reportsEvictedIPs(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 2
	t.Cleanup(func() { AutobanListEntryCap = oldCap })
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "198.51.100.3", Remark: autobanEntryRemark, ExpiresAt: "2026-10-14 12:00:00"}, // 晚到期
		{Value: "198.51.100.4", Remark: autobanEntryRemark, ExpiresAt: "2026-10-14 11:00:00"}, // 最早到期→被挤
	})
	out, err := autobanMergeEntries(AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: false},
		[]AutobanSuggestion{{IP: "203.0.113.10", Count: 120}})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if out.Evicted != 1 {
		t.Fatalf("given: evicted=%d, want 1", out.Evicted)
	}
	if len(out.EvictedIPs) != 1 || out.EvictedIPs[0] != "198.51.100.4" {
		t.Fatalf("EvictedIPs=%v, want [198.51.100.4]（被挤出条目身份）", out.EvictedIPs)
	}
}

// Given 容量=1 的名单：受害者 IP 计数达标被封入名单。
// When 新 IP 达标触发容量收敛挤出受害者，随后零新事件再跑一轮。
// Then 受害者的计数桶必须随挤出同步清空——零新事件下不得再进候选重封
// （旧行为：挤出只计数不清桶 → 下轮旧计数仍 ≥ 阈值立即重封 →
// 「挤出→重封→再挤出」轮转，本钉测必红）。
func TestAutobanRunCycle_evictedIPBucketClearedNoRotation(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 3, 60, "1h", "all", false)
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 1
	t.Cleanup(func() { AutobanListEntryCap = oldCap })

	// 第一轮：受害者 3 次达标 → 封入名单（容量 1，恰好满）。
	for range 3 {
		autobanObserveEvent("198.51.100.4", "blocked", "942100")
	}
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("round1: %v", err)
	}
	if _, ok := entryValues(presetEntries(t))["198.51.100.4"]; !ok {
		t.Fatal("given: 受害者第一轮应被封入名单")
	}

	// 第二轮：新 IP 3 次达标 → 名单已满 → 挤出受害者、封入新 IP。
	for range 3 {
		autobanObserveEvent("203.0.113.10", "blocked", "942100")
	}
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("round2: %v", err)
	}
	entries := entryValues(presetEntries(t))
	if _, ok := entries["198.51.100.4"]; ok {
		t.Fatal("given: 受害者应被容量收敛挤出")
	}
	if _, ok := entries["203.0.113.10"]; !ok {
		t.Fatal("given: 新 IP 应在挤出后封入")
	}

	// 第三轮：零新事件。受害者桶已随挤出清空 → 不得重封（不重封则
	// 名单保持不变——无挤出无新封）。
	f.Advance(time.Minute)
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("round3: %v", err)
	}
	if _, ok := entryValues(presetEntries(t))["198.51.100.4"]; ok {
		t.Fatal("挤出未清桶：受害者零新事件被立即重封（挤出→重封轮转）")
	}
	if _, ok := entryValues(presetEntries(t))["203.0.113.10"]; !ok {
		t.Fatal("在封的新 IP 不得在零变化轮丢失")
	}
}

// ---- 容量收敛留痕携带挤出条目身份 ----

// Given 名单满 12 条自动条目、候选触发整批挤出（12 个）。
// When 正式模式跑一轮 RunAutobanCycle。
// Then 容量收敛 WARN 行与审计详情携带挤出条目身份，截断到前 10 个
// +「等 N 个」（N=总数），第 11/12 个不逐一点名。
func TestAutobanRunCycle_capacityConvergenceListsEvictedIdentities(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 1
	t.Cleanup(func() { AutobanListEntryCap = oldCap })
	var seeded []models.IPListEntry
	for i := 1; i <= 12; i++ {
		// 到期时间递增 → 挤出序即编号升序（确定性身份断言）。
		seeded = append(seeded, models.IPListEntry{
			Value:     fmt.Sprintf("198.51.100.%d", i),
			Remark:    autobanEntryRemark,
			ExpiresAt: fmt.Sprintf("2026-10-14 11:%02d:00", i),
		})
	}
	seedPresetEntries(t, seeded)
	autobanObserveEvent("203.0.113.10", "blocked", "942100")

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	log := readTaskLog(t, AutobanTaskID)
	if !strings.Contains(log, "容量收敛：挤出 12、丢弃 0") {
		t.Fatalf("WARN 行应有挤出计数:\n%s", log)
	}
	// 前 10 个逐一点名，第 11/12 个并入「等 12 个」。
	for _, want := range []string{"198.51.100.1", "198.51.100.10", "等 12 个"} {
		if !strings.Contains(log, want) {
			t.Fatalf("WARN 行缺挤出身份 %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "198.51.100.11") || strings.Contains(log, "198.51.100.12") {
		t.Fatalf("WARN 行挤出身份应截断到前 10 个（第 11/12 个不得点名）:\n%s", log)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='容量收敛'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "198.51.100.4") || !strings.Contains(detail, "等 12 个") {
		t.Fatalf("容量收敛审计详情应携带挤出条目身份（截断形态）: %q", detail)
	}
}

// 重载节流 ----

// Given 重载回调与节流时钟；生产调用方在 CaddyOpLock 临界区内请求重载
// （merge+重载同一临界区，注入回调为 InLock 变体）。
// When 首次请求/节流窗口内再请求/窗口过后 flush。
// Then 立即重载→暂存→合并执行；三态返回与暂存标记一致。
func TestAutobanReloadThrottle(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	reloads := 0
	oldFn := autobanReloader
	autobanReloader = func() error { reloads++; return nil }
	t.Cleanup(func() { autobanReloader = oldFn })

	CaddyOpLock.Lock()
	state := autobanRequestReloadLocked("test")
	CaddyOpLock.Unlock()
	if state != autobanReloadApplied || reloads != 1 {
		t.Fatalf("首次请求应立即重载，state=%d reloads=%d", state, reloads)
	}
	CaddyOpLock.Lock()
	state = autobanRequestReloadLocked("test") // <60s → 暂存
	CaddyOpLock.Unlock()
	if state != autobanReloadDeferred || reloads != 1 {
		t.Fatalf("节流窗口内不得立即重载，state=%d reloads=%d", state, reloads)
	}
	autobanMu.Lock()
	pending := autobanReloadPending
	autobanMu.Unlock()
	if !pending {
		t.Fatal("节流窗口内的重载请求必须置位暂存")
	}
	f.Advance(61 * time.Second)
	autobanFlushPendingReload(false)
	if reloads != 2 {
		t.Fatalf("窗口过后暂存重载应执行，reloads=%d", reloads)
	}
	autobanMu.Lock()
	pending = autobanReloadPending
	autobanMu.Unlock()
	if pending {
		t.Fatal("执行后暂存标记必须清除")
	}
}

// 重载失败必须留系统审计（来源=自动封禁名单，system 归因）
// +置暂存再武装——下一轮 flush 强制重试；重试成功后补落成功审计。
func TestAutobanReload_failureAuditsAndRearms(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	oldFn := autobanReloader
	autobanReloader = func() error { return errors.New("reload boom") }
	t.Cleanup(func() { autobanReloader = oldFn })

	CaddyOpLock.Lock()
	state := autobanRequestReloadLocked("test")
	CaddyOpLock.Unlock()
	if state != autobanReloadErrored {
		t.Fatalf("失败态 state=%d, want autobanReloadErrored", state)
	}
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载失败' AND resource='Caddy服务' AND username='system' AND detail LIKE '%自动封禁%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("重载失败审计行=%d, want 1（system 归因+来源自动封禁）", n)
	}
	autobanMu.Lock()
	pending := autobanReloadPending
	autobanMu.Unlock()
	if !pending {
		t.Fatal("失败后必须置暂存再武装（下一轮 flush 重试）")
	}

	// 再武装生效：回调恢复+节流窗外 → flush 成功，暂存清除，成功审计补落
	autobanReloader = func() error { return nil }
	f.Advance(61 * time.Second)
	autobanFlushPendingReload(false)
	autobanMu.Lock()
	pending = autobanReloadPending
	autobanMu.Unlock()
	if pending {
		t.Fatal("重试成功后暂存必须清除")
	}
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务' AND username='system' AND detail LIKE '%自动封禁%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("重载成功审计行=%d, want 1", n)
	}
}

// 摘要尾注三态——已重载/暂存/失败；无名单变化为空（不得恒称「已触发」）。
func TestAutobanReloadNote_triState(t *testing.T) {
	if got := reloadNote(false, autobanReloadApplied); got != "" {
		t.Fatalf("无变化尾注=%q, want 空", got)
	}
	if got := reloadNote(true, autobanReloadApplied); !strings.Contains(got, "已重载") {
		t.Fatalf("已重载尾注=%q", got)
	}
	if got := reloadNote(true, autobanReloadDeferred); !strings.Contains(got, "暂存") {
		t.Fatalf("暂存尾注=%q", got)
	}
	if got := reloadNote(true, autobanReloadErrored); !strings.Contains(got, "失败") {
		t.Fatalf("失败尾注=%q", got)
	}
}

// ---- Run 循环：观察模式与正式封禁 ----

func TestAutobanRunCycle_dryRunStoresSuggestionsOnly(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "all", true)
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.2", "blocked", "942100") // 1 次 < 阈值

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	sugg := AutobanSuggestions()
	if len(sugg) != 1 || sugg[0].IP != "203.0.113.1" || sugg[0].Count != 3 {
		t.Fatalf("观察建议=%+v, want [{203.0.113.1 3}]", sugg)
	}
	if entries := presetEntries(t); len(entries) != 0 {
		t.Fatalf("观察模式不得写名单，得到 %d 条", len(entries))
	}
}

func TestAutobanRunCycle_bansAndReloads(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "all", false)
	seedAutobanListReferencedByPolicy(t)
	reloads := 0
	oldFn := autobanReloader
	autobanReloader = func() error { reloads++; return nil }
	t.Cleanup(func() { autobanReloader = oldFn })
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.1", "blocked", "942100")

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].Value != "203.0.113.1" {
		t.Fatalf("达阈值 IP 必须落名单，得到 %+v", entries)
	}
	if reloads != 1 {
		t.Fatalf("名单变化后应触发重载，reloads=%d", reloads)
	}
}

func TestAutobanRunCycle_permanentBanHasNoExpiry(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "permanent", "all", false)
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].ExpiresAt != "" {
		t.Fatalf("permanent 封禁不得带 expires_at，得到 %+v", entries)
	}
}

// ---- 投影层：过期条目过滤 ----

func TestIPListProjection_filtersExpiredEntries(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	var id int64
	if err := db.DB.QueryRow(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('投影过期钉', '', ?) RETURNING id`,
		`[{"value":"198.51.100.1","remark":"已到期","expires_at":"2026-10-14 09:00:00"},{"value":"198.51.100.2","remark":"未到期","expires_at":"2026-10-14 11:00:00"},{"value":"198.51.100.3","remark":"无到期"}]`).Scan(&id); err != nil {
		t.Fatalf("seed list: %v", err)
	}
	got, err := LoadIPListEntriesByID([]int64{id})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	vals := got[id]
	if len(vals) != 2 || vals[0] != "198.51.100.2" || vals[1] != "198.51.100.3" {
		t.Fatalf("投影必须过滤已到期条目（保留未到期与无到期），得到 %v", vals)
	}
}

// ---- 摄取提交点批量喂入 ----

func TestAutobanObserveBatch_commitPointFeed(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "all", true)
	autobanObserveBatch([]autobanFeedItem{
		{IP: "203.0.113.1", Action: "blocked", RuleTriggered: "942100"},
		{IP: "203.0.113.1", Action: "logged", RuleTriggered: "942100"},
		{IP: "203.0.113.2", Action: "blocked", RuleTriggered: ""}, // 非 WAF→丢
	})
	autobanMu.Lock()
	w := autobanWindows["203.0.113.1"]
	_, second := autobanWindows["203.0.113.2"]
	autobanMu.Unlock()
	if w == nil || w.Count != 2 {
		t.Fatalf("批量喂入计数=%+v, want 同 IP 两事件累计 2", w)
	}
	if second {
		t.Fatal("非 WAF 事件不得入计数器")
	}
}

// ---- 计数器修剪：未跨阈值的过期桶不产生候选 ----

// 回归形状：过期且未跨阈值的桶照常修剪、不产生候选；已跨阈值
// 的过期桶必须产生候选（正向钉在 TestAutobanRunCycle_expiredBucketStillBans）。
func TestAutobanCandidates_pruneStaleBuckets(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "all", true)
	autobanObserveEvent("203.0.113.1", "blocked", "942100") // 1 次 < 阈值 2
	f.Advance(6 * time.Minute)
	cands := autobanCandidates(2, 5*time.Minute)
	if len(cands) != 0 {
		t.Fatalf("过期且未跨阈值的桶不得产生候选，得到 %v", cands)
	}
	autobanMu.Lock()
	_, stillThere := autobanWindows["203.0.113.1"]
	autobanMu.Unlock()
	if stillThere {
		t.Fatal("过期桶应被修剪")
	}
}

// 解封清桶 ----

// Given 删除 IP 与对照 IP 均达阈值并入名单（真实计数路径）；随后删除 IP 经
// handlers remove-ip/预置名单差集保存两路径共用的清桶入口解封，对照 IP 仅从
// 名单移除（不清桶=旧实现形态）。
// When 零新事件、越 2 个调度 tick（60s 周期，统计窗口 60min 未过期）后再评估。
// Then 删除 IP 不再进候选、不重封；对照 IP 桶仍在 → 重新封禁（证明断言对
// 「桶仍在」敏感——旧实现（无清桶）下删除 IP 与对照同形态，本钉测必红）。
func TestAutobanForgetIPs_deleteThenNoNewEventsNoReban(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 3, 60, "permanent", "all", false)
	cfg := AutobanConfig{Enabled: true, Threshold: 3, WindowMinutes: 60, Duration: "permanent", Scope: "all", DryRun: false}

	// 封禁：两 IP 各 3 次真实计数达标 → 候选 → merge 落名单。
	for range 3 {
		autobanObserveEventScoped(cfg, "203.0.113.9", "blocked", "944100")
		autobanObserveEventScoped(cfg, "198.51.100.7", "blocked", "944100")
	}
	cands := autobanCandidates(3, time.Hour)
	if len(cands) != 2 {
		t.Fatalf("given: 候选数=%d, want 2", len(cands))
	}
	if _, err := autobanMergeEntries(cfg, cands); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if _, ok := entryValues(presetEntries(t))["203.0.113.9"]; !ok {
		t.Fatal("given: 删除 IP 未落名单")
	}

	// 删除：handlers remove-ip 端点与预置名单差集保存路径解封时共用的
	// 计数清桶入口（两调用点接线由 handlers 侧扫描钉测锁定）。
	AutobanForgetIPs([]string{"203.0.113.9"})
	// 对照：仅移除名单条目、不清桶（=旧实现形态，留作必红对照）。
	seedPresetEntries(t, []models.IPListEntry{})
	if got := AutobanTrackedIPs(); got != 1 {
		t.Fatalf("given: 清桶后计数键=%d, want 1（对照桶保留）", got)
	}

	// 零新事件，越 2 个调度 tick。
	f.Advance(2 * time.Minute)

	next := autobanCandidates(3, time.Hour)
	seen := map[string]bool{}
	for _, c := range next {
		seen[c.IP] = true
	}
	if !seen["198.51.100.7"] {
		t.Fatal("对照桶未清除时必须仍产出候选（断言敏感性前提）")
	}
	if seen["203.0.113.9"] {
		t.Fatal("删除 IP 清桶后零新事件不得再进候选（旧行为：不清桶 → 此处命中 → 必红）")
	}
	out, err := autobanMergeEntries(cfg, next)
	if err != nil {
		t.Fatalf("re-merge: %v", err)
	}
	for _, ip := range out.Banned {
		if ip == "203.0.113.9" {
			t.Fatalf("删除 IP 不得在零新事件下重封，得到 banned=%v", out.Banned)
		}
	}
	if _, ok := entryValues(presetEntries(t))["198.51.100.7"]; !ok {
		t.Fatal("对照 IP（仅删名单未清桶）应在零新事件下被重封——旧实现形态钉")
	}
}

// ---- Status 辅助 ----

// 观察模式建议展示截断（2026-10-15 用户裁定）：/status 建议列表按 Count 降序
// Top 50——dry-run 洪峰下逐行渲染有界；审计/TaskLogf 走 candidates 全量，
// 不受展示截断影响。
func TestAutobanSuggestions_displayTruncatedToTop50(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	var seeds []AutobanSuggestion
	for i := 60; i >= 1; i-- {
		seeds = append(seeds, AutobanSuggestion{IP: fmt.Sprintf("10.0.0.%d", i), Count: i})
	}
	autobanSetSuggestions(seeds) // 喂入已降序——getter 仍负责降序+截断（防任意顺序依赖）

	got := AutobanSuggestions()
	if len(got) != 50 {
		t.Fatalf("建议展示条数=%d, want 50（Top 50 截断）", len(got))
	}
	if got[0].IP != "10.0.0.60" || got[0].Count != 60 {
		t.Fatalf("首行=%s/%d, want 10.0.0.60/60（按 Count 降序）", got[0].IP, got[0].Count)
	}
	if got[49].IP != "10.0.0.11" || got[49].Count != 11 {
		t.Fatalf("末行=%s/%d, want 10.0.0.11/11", got[49].IP, got[49].Count)
	}
}

// 建议窗口时间：WindowStart=窗口内首次命中、LastSeen=末次命中（feed 更新点
// 记录），候选/建议携带供前端展示「窗口内首末时间」。
func TestAutobanSuggestions_carryWindowFirstAndLastSeen(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "all", false)
	autobanObserveEvent("203.0.113.7", "blocked", "941100")
	f.Advance(2 * time.Minute)
	autobanObserveEvent("203.0.113.7", "blocked", "941100")

	cands := autobanCandidates(2, 5*time.Minute)
	if len(cands) != 1 {
		t.Fatalf("候选数=%d, want 1", len(cands))
	}
	first := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	last := time.Date(2026, 10, 14, 10, 2, 0, 0, time.UTC)
	if !cands[0].WindowStart.Equal(first) {
		t.Fatalf("WindowStart=%v, want %v（窗口内首次命中）", cands[0].WindowStart, first)
	}
	if !cands[0].LastSeen.Equal(last) {
		t.Fatalf("LastSeen=%v, want %v（末次命中）", cands[0].LastSeen, last)
	}
}

// 今日封禁=审计事件计数（2026-10-15 用户裁定）：删除条目（=解封）不回退今日
// 计数。数据源=audit_log「自动封禁」系统动作行（created_at UTC 墙钟串），
// 今日边界按配置时区零点换算 UTC 比较。
func TestAutobanBannedToday_countsAuditBansOfDay(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	// 钉 UTC（默认包级 init=CST+8）：今日边界=「2026-10-14 00:00:00」UTC，
	// 断言的 UTC 字面量与之严格对应。
	previous := CurrentLocation().String()
	if _, err := ConfigureLocation("UTC"); err != nil {
		t.Fatalf("configure UTC: %v", err)
	}
	t.Cleanup(func() { _, _ = ConfigureLocation(previous) })
	seedAudit := func(action, createdUTC string) {
		t.Helper()
		if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES ('system', ?, 'IP 地址列表', 'IP：x', '', ?)`,
			action, createdUTC); err != nil {
			t.Fatal(err)
		}
	}
	seedAudit(AutobanAuditAction, "2026-10-14 01:00:00") // 今日 UTC
	seedAudit(AutobanAuditAction, "2026-10-14 09:59:59") // 今日 UTC（边界内最后一秒）
	seedAudit(AutobanAuditAction, "2026-10-13 23:59:59") // 昨日不计
	seedAudit("更新", "2026-10-14 05:00:00")               // 非封禁动作不计
	//（created_at >= 今日零点为开放上界：生产写入恒为当下时刻，无未来行形态）

	seedPresetEntries(t, []models.IPListEntry{
		{Value: "203.0.113.1", Remark: autobanEntryRemark, CreatedAt: "2026-10-14 09:00:00", ExpiresAt: "2026-10-15 09:00:00"},
	})
	if n := AutobanBannedToday(); n != 2 {
		t.Fatalf("今日自动封禁数=%d, want 2（按审计事件计数：时区边界/昨日/非封禁均不混计）", n)
	}

	// 用户报告形状钉：封禁 → 删除条目（=解封）→ 今日封禁仍=原计数，不得清零。
	seedPresetEntries(t, []models.IPListEntry{})
	if n := AutobanBannedToday(); n != 2 {
		t.Fatalf("删除条目后今日封禁不得清零：=%d, want 2", n)
	}
}

// 非 UTC 时区用例：今日边界的时区换算必须真正参与判定。
// TestAutobanBannedToday_countsAuditBansOfDay 把时区钉为 UTC——此时
// autobanNow().In(loc) 与 .UTC() 都是恒等变换，删掉换算实现它仍全绿（覆盖
// 盲区）。本用例以 Asia/Shanghai（UTC+8）+ 时钟 2026-10-14 12:00:00Z（=当地
// 20:00）钉住「当地零点 = 2026-10-13 16:00:00Z」：15:59:59Z 属昨日不计、
// 16:00:00Z 恰为今日第一秒必计。
func TestAutobanBannedToday_usesConfiguredTimezoneDayBoundary(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 12:00:00")
	previous := CurrentLocation().String()
	if _, err := ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatalf("configure Asia/Shanghai: %v", err)
	}
	t.Cleanup(func() { _, _ = ConfigureLocation(previous) })
	seedAudit := func(createdUTC string) {
		t.Helper()
		if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES ('system', ?, 'IP 地址列表', 'IP：x', '', ?)`,
			AutobanAuditAction, createdUTC); err != nil {
			t.Fatal(err)
		}
	}
	seedAudit("2026-10-13 15:59:59") // 当地 2026-10-13 23:59:59（昨日）→ 不计
	seedAudit("2026-10-13 16:00:00") // 当地 2026-10-14 00:00:00（今日边界）→ 计
	seedAudit("2026-10-14 11:59:59") // 当地 2026-10-14 19:59:59（今日）→ 计

	if n := AutobanBannedToday(); n != 2 {
		t.Fatalf("今日自动封禁数=%d, want 2（按 Asia/Shanghai 当地零点换算 UTC 边界；不换算时全区 3 条都会计入）", n)
	}
}

// ---- wire 接线钉：Descriptor 标准七字段 + 调度唯一前提=业务启用 ----

// Given 引擎装配（InitTaskEngine），库内默认未启用（autoban_enabled=0）。
// When 查 autoban 元数据。
// Then 循环族 60s 间隔、主节点角色门、可手动触发；Descriptor 无 EnabledFn
// （启停语义全在调度开关+事件页业务开关，2026-10-14 用户裁定）；未启用时
// 启动不开调度（否则未启用部署首 tick 必落「未启用」失败行）。
func TestTaskEngineWire_AutobanDescriptor(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	te := InitTaskEngine("", t.TempDir()+"/app.log")

	m, ok := te.Lookup(AutobanTaskID)
	if !ok {
		t.Fatal("autoban 未注册")
	}
	if m.Kind != "periodic" {
		t.Fatalf("kind=%s, want periodic（固定间隔循环族）", m.Kind)
	}
	if m.IntervalSec != 60 {
		t.Fatalf("interval=%ds, want 60s", m.IntervalSec)
	}
	if !m.CanTrigger {
		t.Fatal("循环族应可手动触发")
	}
	if m.LoopOn {
		t.Fatal("默认未启用（autoban_enabled=0）时启动不得开调度（调度唯一前提=业务启用）")
	}
}

// Given 库内 autoban_enabled=1 后装配引擎。
// When 查 autoban 元数据。
// Then 启动即开调度（loop_on=true——与 PUT 保存联动同一前提）。
func TestTaskEngineWire_AutobanLoopMirrorsEnabledOnStartup(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	te := InitTaskEngine("", t.TempDir()+"/app.log")

	if m, _ := te.Lookup(AutobanTaskID); !m.LoopOn {
		t.Fatal("autoban_enabled=1 时启动应开调度（启用即按配置调度）")
	}
}

// ---- Run 体业务门（2026-10-14 用户裁定：该任务只能由「启用后按配置调度」）----

// Given 引擎装配+手动开调度（用户在任务列表开 loop）但业务未启用。
// When 该任务被调度执行一轮（te.Trigger 与 tick 投递同走 runNow→Run 体）。
// Then Run 体门拦下：错误含「未启用」；task_runs 落 failed 行（message 含
// 未启用）；tasks/autoban.log 含「手动调度」；loop 被重禁（LoopOn=false）——
// 未启用状态不得在调度面空转续跑。随后启用+重开调度，正常轮不被门拦。
func TestAutobanRunGate_ManualLoopWhileDisabledFailsAndStopsLoop(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	newTaskLogDir(t)
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	te := InitTaskEngine("", t.TempDir()+"/app.log")
	t.Cleanup(te.Stop)

	// 前置：手动开调度（任务列表 loop 开关）
	te.StartLoop(AutobanTaskID)
	if m, _ := te.Lookup(AutobanTaskID); !m.LoopOn {
		t.Fatal("前置：手动开调度应生效")
	}

	// 调度执行一轮（Trigger 与 tick 投递同体：runNow→Run 体门）
	err := te.Trigger(AutobanTaskID, "manual", "tester")
	if err == nil || !strings.Contains(err.Error(), "未启用") {
		t.Fatalf("Run 体门应拒绝未启用执行，err=%v", err)
	}
	if m, _ := te.Lookup(AutobanTaskID); m.LoopOn {
		t.Fatal("Run 体门应重禁调度（StopLoop），未启用不得续跑")
	}
	var status, msg string
	if err := db.DB.QueryRow(`SELECT status, COALESCE(message,'') FROM task_runs WHERE task_id='autoban' ORDER BY id DESC LIMIT 1`).Scan(&status, &msg); err != nil {
		t.Fatalf("task_runs 行缺失: %v", err)
	}
	if status != "failed" || !strings.Contains(msg, "未启用") {
		t.Fatalf("task_runs=(%s,%q), want failed+message 含未启用", status, msg)
	}
	if log := readTaskLog(t, AutobanTaskID); !strings.Contains(log, "手动调度") {
		t.Fatalf("任务日志应含「手动调度」行: %s", log)
	}

	// 回归形状：启用后重开调度 → 正常执行（观察模式默认开，门只拦未启用）
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	te.StartLoop(AutobanTaskID)
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("启用后正常轮不得被门拦: %v", err)
	}
}

// 未启用分支的日志文案按 trigger 二元化：auto 轮（周期 tick 投递）不得写
// 「手动调度」——任务日志按字面归因触发来源，auto 轮写「手动调度」会让
// 排障者误以为有人点了手动触发。
func TestAutobanRunGate_AutoTriggerWhileDisabledLogsAutoWording(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")

	err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"})
	if err == nil || !strings.Contains(err.Error(), "未启用") {
		t.Fatalf("Run 体门应拒绝未启用执行，err=%v", err)
	}
	log := readTaskLog(t, AutobanTaskID)
	if strings.Contains(log, "手动调度") {
		t.Fatalf("auto 轮日志不得写「手动调度」: %s", log)
	}
	if !strings.Contains(log, "定时调度") {
		t.Fatalf("auto 轮日志应含「定时调度」行: %s", log)
	}
}

// ---- 上限契约钉（2026-10-14 用户裁定：500→2000 设大值） ----

func TestAutobanListEntryCap_raisedTo2000(t *testing.T) {
	if AutobanListEntryCap != 2000 {
		t.Fatalf("AutobanListEntryCap=%d, want 2000（2026-10-14 用户裁定设大值）", AutobanListEntryCap)
	}
}

// Given 名单为空、候选新封数超过上限。
// When merge 容量收敛。
// Then 按容量截断新封（高计数优先保留）——不得因「无可挤的存量自动条目」
// 把整批新封全丢弃；丢弃数入 DroppedNew（可观测）。
func TestAutobanMerge_trimsNewBansWhenCapExceeded(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 200
	t.Cleanup(func() { AutobanListEntryCap = oldCap })

	candidates := make([]AutobanSuggestion, 0, 201)
	for i := 1; i <= 201; i++ {
		candidates = append(candidates, AutobanSuggestion{IP: fmt.Sprintf("198.51.100.%d", i), Count: 1000 - i})
	}
	out, err := autobanMergeEntries(AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: false}, candidates)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 200 {
		t.Fatalf("201 个新封只留 200（截断而非整批丢弃），得到 %d 条", len(entries))
	}
	if out.Total != 200 || out.DroppedNew != 1 || out.Evicted != 0 {
		t.Fatalf("merge 计数失真：total=%d dropped=%d evicted=%d, want 200/1/0", out.Total, out.DroppedNew, out.Evicted)
	}
	if len(out.Banned) != 200 {
		t.Fatalf("banned=%d, want 200（保留的新封）", len(out.Banned))
	}
	// 高计数优先保留：计数最高的 198.51.100.1 必须在场
	if _, exists := entryValues(entries)["198.51.100.1"]; !exists {
		t.Fatal("容量截断必须保留高计数候选（198.51.100.1 缺失）")
	}
	if _, exists := entryValues(entries)["198.51.100.201"]; exists {
		t.Fatal("超限的最低计数候选应被丢弃（198.51.100.201 应缺席）")
	}
}

// ---- 超限可观测：任务日志 WARN 行 + 审计「容量收敛」行（系统操作者） ----

// Given 名单已满自动条目、候选触发挤出。
// When 正式模式跑一轮 RunAutobanCycle。
// Then tasks/autoban.log 落 WARN 级「容量收敛：挤出 N、丢弃 M」行；审计落
// action=容量收敛、username=system 的操作记录。
func TestAutobanRunCycle_capacityConvergenceObservable(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 2
	t.Cleanup(func() { AutobanListEntryCap = oldCap })
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "198.51.100.3", Remark: autobanEntryRemark, ExpiresAt: "2026-10-14 12:00:00"}, // 晚到期
		{Value: "198.51.100.4", Remark: autobanEntryRemark, ExpiresAt: "2026-10-14 11:00:00"}, // 最早到期→被挤
	})
	autobanObserveEvent("203.0.113.10", "blocked", "942100")

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	log := readTaskLog(t, AutobanTaskID)
	if !strings.Contains(log, "[WARN]") || !strings.Contains(log, "容量收敛：挤出 1、丢弃 0") {
		t.Fatalf("任务日志应有 WARN 级容量收敛行（挤出 1、丢弃 0）:\n%s", log)
	}
	if !strings.Contains(log, "挤出 IP 198.51.100.4") {
		t.Fatalf("WARN 行应点名被挤出条目身份（198.51.100.4）:\n%s", log)
	}
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='容量收敛' AND resource='IP 地址列表' AND username='system'`).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("容量收敛审计行=%d, want 1（系统操作者）", n)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='容量收敛'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "挤出 1") || !strings.Contains(detail, "丢弃 0") {
		t.Fatalf("容量收敛审计详情失真: %q", detail)
	}
}

// Given 名单被手动条目填满（手动条目不参与挤出），容量已满。
// When 正式模式下一批 IP 达到阈值。
// Then 「新封 0、丢弃 N」必须落 WARN + 容量收敛审计——名单内容未变化
// （Changed=false）不得成为静默理由；管理员必须能区分「未达标」与「满容量
// 丢弃」（否则攻击流量未被封禁且无告警）。
func TestAutobanRunCycle_capacityDropOnManualOnlyListIsVisible(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 3
	t.Cleanup(func() { AutobanListEntryCap = oldCap })
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "198.51.100.1", Remark: "事件处置"},
		{Value: "198.51.100.2", Remark: "事件处置"},
		{Value: "198.51.100.3", Remark: "事件处置"},
	})
	autobanObserveEvent("203.0.113.60", "blocked", "942100")

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}

	log := readTaskLog(t, AutobanTaskID)
	if !strings.Contains(log, "[WARN]") || !strings.Contains(log, "容量收敛：挤出 0、丢弃 1") {
		t.Fatalf("满容量丢弃新封必须落 WARN 级容量收敛行:\n%s", log)
	}
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='容量收敛' AND username='system'`).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("容量收敛审计行=%d, want 1（系统操作者）", n)
	}
	if got := len(presetEntries(t)); got != 3 {
		t.Fatalf("名单=%d 条, want 3（手动条目不得被挤、新封被丢弃）", got)
	}
}

// ---- 计数分级日志：热路径零日志 / 每轮摘要活跃数 / 过期汇总一行 ----

// autobanLogNow 软读任务日志（尚未写任何行=空串——「零日志」断言用）。
func autobanLogNow(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(taskengine.TaskLogPath(AutobanTaskID))
	if err != nil {
		return ""
	}
	return string(data)
}

func TestAutobanCounter_tieredLogging(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 3, 5, "1h", "all", true)

	// 未达标 IP 零日志（2 次 < 阈值 3）
	autobanObserveEvent("203.0.113.8", "blocked", "942100")
	autobanObserveEvent("203.0.113.8", "blocked", "942100")
	if s := autobanLogNow(t); s != "" {
		t.Fatalf("未达标 IP 不得留任何日志行:\n%s", s)
	}

	// 摄取热路径只更新计数，不写任何任务日志（达标也不写）——分级日志只由
	// Run 的每轮汇总行承担。
	for range 4 {
		autobanObserveEvent("203.0.113.7", "blocked", "942100")
	}
	if s := autobanLogNow(t); s != "" {
		t.Fatalf("热路径喂入不得写任务日志:\n%s", s)
	}

	// 每轮摘要行含「活跃 M 个 IP」（M=当前窗口内达过阈值的 IP 数）
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	if s := autobanLogNow(t); !strings.Contains(s, "活跃 1 个 IP") {
		t.Fatalf("摘要行应含「活跃 1 个 IP」:\n%s", s)
	}
	afterRun := autobanLogNow(t)

	// Feed 路径窗口过期只重置计数，不写日志；新窗口内的达标同样不写。
	f.Advance(6 * time.Minute)
	autobanObserveEvent("203.0.113.7", "blocked", "942100")
	if s := autobanLogNow(t); s != afterRun {
		t.Fatalf("feed 路径不得追加日志行（含窗口过期/新窗口达标）:\n%s", s)
	}
	autobanObserveEvent("203.0.113.7", "blocked", "942100")
	autobanObserveEvent("203.0.113.7", "blocked", "942100")
	if s := autobanLogNow(t); s != afterRun {
		t.Fatalf("热路径达标不得追加日志行:\n%s", s)
	}
	// 逐轮汇总的过期清零行由 Run 的修剪路径产生（每轮一行，不逐 IP 刷屏）。
	f.Advance(6 * time.Minute)
	autobanCandidates(3, 5*time.Minute)
	if got := strings.Count(autobanLogNow(t), "计数窗口过期，清零"); got != 1 {
		t.Fatalf("Run 修剪路径汇总清零日志=%d 行, want 1（同链保留）:\n%s", got, autobanLogNow(t))
	}
	if !strings.Contains(autobanLogNow(t), "203.0.113.7") {
		t.Fatalf("汇总清零日志应保留 IP 样本:\n%s", autobanLogNow(t))
	}
}

// Given 同一轮有多个曾达阈值的过期 IP 与一个未达阈值过期 IP。
// When 修剪计数桶。
// Then 只写一条按轮汇总日志，样本有界且候选评估不丢失。
func TestAutobanCandidates_aggregateExpiryLog(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	for i := 1; i <= 6; i++ {
		AutobanSeedCounterForTest(fmt.Sprintf("203.0.113.%d", i), 1, 1)
	}
	AutobanSeedCounterForTest("203.0.113.99", 0, 1)
	f.Advance(6 * time.Minute)

	candidates := autobanCandidates(1, 5*time.Minute)

	if len(candidates) != 6 {
		t.Fatalf("过期达标候选=%d, want 6（汇总日志不得改变评估）", len(candidates))
	}
	log := autobanLogNow(t)
	if got := strings.Count(log, "计数窗口过期，清零"); got != 1 {
		t.Fatalf("过期清零日志=%d 行, want 1（按轮汇总）:\n%s", got, log)
	}
	if !strings.Contains(log, "6 个 IP 计数窗口过期，清零") || !strings.Contains(log, "另有 1 个") {
		t.Fatalf("汇总行应包含总数与截断余量:\n%s", log)
	}
	if strings.Contains(log, "203.0.113.99") {
		t.Fatalf("未达阈值 IP 不得进入过期汇总:\n%s", log)
	}
	for i := 1; i <= 6; i++ {
		if strings.Count(log, fmt.Sprintf("203.0.113.%d", i)) > 1 {
			t.Fatalf("IP %d 仍被逐条写日志:\n%s", i, log)
		}
	}
}

func TestAutobanRequestReloadLocked_missingReloaderLeavesWarn(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	oldFn := autobanReloader
	autobanReloader = nil
	t.Cleanup(func() { autobanReloader = oldFn })

	if got := autobanRequestReloadLocked("测试装配缺失"); got != autobanReloadNone {
		t.Fatalf("reload state=%v, want none", got)
	}
	log := readTaskLog(t, AutobanTaskID)
	if !strings.Contains(log, "[WARN]") || !strings.Contains(log, "重载回调未注册") {
		t.Fatalf("缺失重载回调必须留 WARN 任务日志:\n%s", log)
	}
}

// merge 读改写+重载与名单写路径同一 CaddyOpLock 临界区 ----

// Given 正式模式、候选达标；CaddyOpLock 被并发「名单写路径」临界区预持
// （handlers AddIPToList/UpdateIPList 同型：持 CaddyOpLock → 读条目 → 追加 →
// 回写 → 释放）。
// When RunAutobanCycle 并发执行。
// Then 写路径先提交追加、释放后本轮完成——最终名单同时含写路径追加值与
// 本轮新封值（不丢更新）；以终态和收敛次数为判据，不用静默等待窗冒充互斥证明。
func TestAutobanRunCycle_mergeSerializesWithListWriterUnderCaddyOpLock(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	seedAutobanListReferencedByPolicy(t)
	reloads := 0
	oldFn := autobanReloader
	autobanReloader = func() error { reloads++; return nil }
	t.Cleanup(func() { autobanReloader = oldFn })
	autobanObserveEvent("203.0.113.1", "blocked", "942100")

	CaddyOpLock.Lock()
	cycleDone := make(chan error, 1)
	go func() { cycleDone <- RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}) }()

	// 写路径完成自己的追加后释放互斥锁。
	entries := append(presetEntries(t), models.IPListEntry{Value: "198.51.100.50", Remark: AutobanManualUnbanRemark, CreatedAt: "2026-10-14 10:00:00"})
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE id=?`, string(raw), presetListID(t)); err != nil {
		t.Fatal(err)
	}
	CaddyOpLock.Unlock()

	// 释放后 autoban 轮完成：最终名单=写路径追加+本轮新封（不丢更新）
	select {
	case err := <-cycleDone:
		if err != nil {
			t.Fatalf("cycle: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("锁释放后 autoban 轮未完成（疑死锁）")
	}
	got := entryValues(presetEntries(t))
	if _, ok := got["198.51.100.50"]; !ok {
		t.Fatal("并发名单写路径的追加在 merge 后必须保留（丢更新）")
	}
	if _, ok := got["203.0.113.1"]; !ok {
		t.Fatal("本轮新封 IP 必须落名单")
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1（merge 变化后同临界区重载）", reloads)
	}
}

// 批入口一次读配置，scope+window 下传单事件路径 ----

// Given 库配置窗口=1 分钟。
// When autobanObserveEventScoped 显式接收下传的 scope/window。
// Then 窗口内累计、越过下传窗口重置（若回退内层逐事件读库或写死兜底，
// 2 分钟处仍是同窗口累计，断言即失败）；窗口无效（<=0）跳过计数、无写死
// 5 分钟兜底。
func TestAutobanObserveBatch_scopeAndWindowPassedDown(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 100, 1, "1h", "all", true)
	oneMin := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 1, Duration: "1h", Scope: "all", DryRun: true}

	autobanObserveEventScoped(oneMin, "203.0.113.1", "blocked", "942100")
	autobanObserveEventScoped(oneMin, "203.0.113.1", "blocked", "942100")
	autobanMu.Lock()
	w := autobanWindows["203.0.113.1"]
	autobanMu.Unlock()
	if w == nil || w.Count != 2 {
		t.Fatalf("窗口内计数=%+v, want 2", w)
	}

	f.Advance(2 * time.Minute)
	autobanObserveEventScoped(oneMin, "203.0.113.1", "blocked", "942100")
	autobanMu.Lock()
	w = autobanWindows["203.0.113.1"]
	autobanMu.Unlock()
	if w == nil || w.Count != 1 {
		t.Fatalf("越过下传窗口后应重置计数（不得落 5 分钟写死兜底）, 得到 %+v", w)
	}

	autobanObserveEventScoped(AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 0, Duration: "1h", Scope: "all", DryRun: true}, "203.0.113.2", "blocked", "942100")
	autobanMu.Lock()
	_, invalidWindowFed := autobanWindows["203.0.113.2"]
	autobanMu.Unlock()
	if invalidWindowFed {
		t.Fatal("窗口无效时不得计数（无写死兜底）")
	}
}

// 禁用路径收尾——到期清理一次+暂存重载强制收敛 ----

// Given 名单含已到期自动条目/未到期自动条目/手动条目，且存在节流暂存的重载
// （禁用后无循环 flush 点——核心）。
// When AutobanDisableFlush()（PUT 禁用路径在 StopLoop 前调用）。
// Then 已到期自动条目立即清除+落「自动解封」审计；暂存重载绕过节流强制执行；
// 未到期/手动条目保留；暂存标记清除。
func TestAutobanDisableFlush_expiresOnceAndForceFlushes(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "198.51.100.1", Remark: autobanEntryRemark, CreatedAt: "2026-10-13 10:00:00", ExpiresAt: "2026-10-14 09:00:00"}, // 已到期
		{Value: "198.51.100.2", Remark: autobanEntryRemark, CreatedAt: "2026-10-14 09:30:00", ExpiresAt: "2026-10-14 11:00:00"}, // 未到期
		{Value: "198.51.100.3", Remark: "事件处置", CreatedAt: "2026-10-13 10:00:00"},                                               // 手动
	})
	reloads := 0
	oldFn := autobanReloader
	autobanReloader = func() error { reloads++; return nil }
	t.Cleanup(func() { autobanReloader = oldFn })
	CaddyOpLock.Lock()
	autobanRequestReloadLocked("禁用前变化") // 首问立即重载（reloads=1，节流起点）
	autobanRequestReloadLocked("禁用前变化") // 次问节流窗口内→暂存
	CaddyOpLock.Unlock()
	autobanMu.Lock()
	pending := autobanReloadPending
	autobanMu.Unlock()
	if !pending {
		t.Fatal("前置：暂存必须置位")
	}

	AutobanDisableFlush()

	got := entryValues(presetEntries(t))
	if _, exists := got["198.51.100.1"]; exists {
		t.Fatal("已到期自动条目必须在禁用收尾时清除（到期解封收尾）")
	}
	if _, exists := got["198.51.100.2"]; !exists {
		t.Fatal("未到期条目必须保留")
	}
	if _, exists := got["198.51.100.3"]; !exists {
		t.Fatal("手动条目必须保留")
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2（到期清理变化重载 1 + 暂存强制收敛 1——禁用后无 flush 点，必须立即落盘）", reloads)
	}
	autobanMu.Lock()
	pending = autobanReloadPending
	autobanMu.Unlock()
	if pending {
		t.Fatal("禁用收尾后暂存必须清除（此后无下一轮）")
	}
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='自动解封' AND username='system' AND detail LIKE '%198.51.100.1%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("到期解封审计行=%d, want 1", n)
	}
}

// 禁用收尾的容量挤出必须同步清桶（与 Run 轮同口径）：被挤出条目的计数桶
// 不清空，则重新启用且零新流量时旧计数仍 ≥ 阈值 → 立即重封刚被挤出的 IP。
func TestAutobanDisableFlush_evictedIPBucketCleared(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 1
	t.Cleanup(func() { AutobanListEntryCap = oldCap })
	setAutobanConfigRaw(t, true, 1, 5, "permanent", "all", false)

	// 带外写入致 kept 超限（candidates=nil 时仍会挤出）；早创建的先被挤。
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "198.51.100.9", Remark: autobanEntryRemark, CreatedAt: "2026-10-13 09:00:00"},
		{Value: "198.51.100.10", Remark: autobanEntryRemark, CreatedAt: "2026-10-13 10:00:00"},
	})
	autobanObserveEvent("198.51.100.9", "blocked", "942100")
	autobanMu.Lock()
	if w := autobanWindows["198.51.100.9"]; w == nil || !w.Reached {
		autobanMu.Unlock()
		t.Fatalf("前置：受害者计数必须达标，got %+v", w)
	}
	autobanMu.Unlock()

	AutobanDisableFlush()

	autobanMu.Lock()
	_, stillTracked := autobanWindows["198.51.100.9"]
	autobanMu.Unlock()
	if stillTracked {
		t.Fatal("禁用收尾挤出的条目计数桶必须清空（否则重新启用零流量立即重封）")
	}
	// 留痕：容量收敛（禁用收尾）审计行落系统操作者。
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='容量收敛' AND detail LIKE '%禁用收尾%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("容量收敛审计行=%d, want 1（禁用收尾挤出必须留痕）", n)
	}
}

// 启用→达标→禁用→隔窗→启用：禁用必须把陈旧计数证据作废（清空计数桶），
// 否则停用任意时长后重新启用会在零新流量下以旧计数立即封禁，且封禁起点
// 从「此刻」重算——共享 NAT/已重新分配的 IP 会被长期封死。
func TestSetAutobanConfig_disableClearsStaleCounters(t *testing.T) {
	clock := installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 3, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: false}
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("enable: %v", err)
	}
	for range 3 {
		autobanObserveEvent("203.0.113.77", "blocked", "942100")
	}
	if got := autobanReachedCount(); got != 1 {
		t.Fatalf("前置：达标 IP 数=%d, want 1", got)
	}

	// 禁用（生产写侧入口）。
	cfg.Enabled = false
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if got := autobanTrackedCount(); got != 0 {
		t.Fatalf("禁用后计数桶=%d, want 0（陈旧计数必须作废）", got)
	}

	// 停用期跨越统计窗口的任意倍数（此处 1 小时 = 12 个窗口）。
	clock.Advance(time.Hour)
	cfg.Enabled = true
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if got := autobanTrackedCount(); got != 0 {
		t.Fatalf("重新启用后计数桶=%d, want 0", got)
	}
	if cand := autobanCandidates(cfg.Threshold, time.Duration(cfg.WindowMinutes)*time.Minute); len(cand) != 0 {
		t.Fatalf("重新启用零新流量候选=%v, want 空（不得以陈旧计数封禁）", cand)
	}
}

func TestAutobanDisableFlush_mergeFailureIsVisible(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, false, 1, 5, "1h", "all", false)
	if _, err := db.DB.Exec(`DROP TABLE security_ip_lists`); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	AutobanDisableFlush()

	if !strings.Contains(logs.String(), "禁用收尾") || !strings.Contains(logs.String(), "失败") {
		t.Fatalf("merge failure must be logged:\n%s", logs.String())
	}
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='写入失败' AND resource='自动封禁'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("merge failure audit rows=%d, want 1", n)
	}
}

// ---- 正式 merge：候选不按建议上限截断 ----

func TestAutobanFormalMerge_beyondSuggestionCap(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 60, "1h", "all", false)
	cfg := AutobanConfig{Enabled: true, Threshold: 2, WindowMinutes: 60, Duration: "1h", Scope: "all"}

	total := autobanSuggestionCap + 1
	// 前 200 个 IP 预置为「已在名单」的手动条目：正式 merge 应把它们过滤掉，
	// 只剩第 201 个新 IP 落名单。旧实现 autobanCandidates 在 200 处截断，
	// 第 201 个候选根本不存在（按计数/IP 排序后恰为最大 IP，被截掉）。
	entries := make([]models.IPListEntry, 0, autobanSuggestionCap)
	for i := 0; i < autobanSuggestionCap; i++ {
		entries = append(entries, models.IPListEntry{Value: fmt.Sprintf("198.51.100.%d", i+1), Remark: "手动"})
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE name=?`, string(raw), AutobanPresetListName); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < total; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		if i == autobanSuggestionCap {
			ip = "203.0.113.201"
		}
		autobanObserveEventScoped(cfg, ip, "blocked", "942100")
		autobanObserveEventScoped(cfg, ip, "blocked", "942100")
	}

	cands := autobanCandidates(cfg.Threshold, time.Hour)
	if len(cands) != total {
		t.Fatalf("candidates=%d, want %d（候选评估不得按展示上限截断）", len(cands), total)
	}
	out, err := autobanMergeEntries(cfg, cands)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out.Banned) != 1 || out.Banned[0] != "203.0.113.201" {
		t.Fatalf("banned=%v, want [203.0.113.201]（第 201 个候选必须可被封禁）", out.Banned)
	}

	// 观察模式仍按展示上限截断（展示口径不变）。
	resetAutobanStateForTest()
	for i := 0; i < total; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		if i == autobanSuggestionCap {
			ip = "203.0.113.201"
		}
		autobanObserveEventScoped(cfg, ip, "blocked", "942100")
		autobanObserveEventScoped(cfg, ip, "blocked", "942100")
	}
	setAutobanConfigRaw(t, true, 2, 60, "1h", "all", true)
	// 名单里的 200 个 IP 不再影响候选（候选只看计数）。
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("dry-run cycle: %v", err)
	}
	autobanMu.Lock()
	stored := len(autobanSuggestions)
	autobanMu.Unlock()
	if stored != autobanSuggestionCap {
		t.Fatalf("dry-run suggestions stored=%d, want %d（展示口径截断）", stored, autobanSuggestionCap)
	}
}

// window(60m) > duration(10m) 时，条目到期解封不得被同一
// 计数桶在 merge 内立即重封——旧实现每轮「清到期 → 从仍跨阈值的桶重封」，
// 实际封禁被延长到约 window+duration，并产生成对的自动解封/自动封禁审计。
func TestAutobanMerge_expiredEntryNotRebannedSameRound(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 3, WindowMinutes: 60, Duration: "10m", Scope: "all", DryRun: false}
	const ip = "203.0.113.55"

	// Given 3 次真实计数达阈值 → 封禁 10 分钟
	for range 3 {
		autobanObserveEventScoped(cfg, ip, "blocked", "944100")
	}
	cands := autobanCandidates(3, time.Hour)
	if len(cands) != 1 {
		t.Fatalf("给定：候选=%v，want 1（%s 封禁前）", cands, ip)
	}
	if _, err := autobanMergeEntries(cfg, cands); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if _, ok := entryValues(presetEntries(t))[ip]; !ok {
		t.Fatal("给定：IP 未落名单")
	}

	// When 越过 10 分钟时长（计数窗口 60m 尚未过期 → 桶仍跨阈值）
	f.Advance(11 * time.Minute)
	expiredCands := autobanCandidates(3, time.Hour)
	found := false
	for _, c := range expiredCands {
		if c.IP == ip {
			found = true
		}
	}
	if !found {
		t.Fatalf("前提失效：到期后计数桶仍应跨阈值产出候选（window>duration），got=%v", expiredCands)
	}
	out, err := autobanMergeEntries(cfg, expiredCands)

	// Then 同一轮只解封，不得重封
	if err != nil {
		t.Fatalf("expiry merge: %v", err)
	}
	sawExpired := false
	for _, v := range out.Expired {
		if v == ip {
			sawExpired = true
		}
	}
	if !sawExpired {
		t.Fatalf("到期 IP 未进入 Expired：%v", out.Expired)
	}
	for _, v := range out.Banned {
		if v == ip {
			t.Fatalf("到期解封的 IP 在同一轮被计数桶重封（回归形状）：banned=%v", out.Banned)
		}
	}
	if _, ok := entryValues(presetEntries(t))[ip]; ok {
		t.Fatalf("到期后名单仍含 %s（应已解封）", ip)
	}

	// 生产路径随后清桶（RunAutobanCycle）——零新事件下下一轮不再产出候选。
	AutobanForgetIPs(out.Expired)
	if got := AutobanTrackedIPs(); got != 0 {
		t.Fatalf("到期清桶后计数键=%d，want 0", got)
	}
	if again := autobanCandidates(3, time.Hour); len(again) != 0 {
		t.Fatalf("到期清桶后零新事件不得再产候选，got=%v", again)
	}
}

// installFeedHealthTestEngine 装配只含喂入源 daemon 的引擎（StartPaused：默认
// 调度关闭 = 用户显式停止 / 自愈预算用尽后的共同终态形状）。。
func installFeedHealthTestEngine(t *testing.T) *taskengine.Engine {
	t.Helper()
	// 摄取健康位是包级全局（securityEventsIngestionHealth）：其他用例用
	// securityEventsRecordPollResult 注入过失败后会留下 Observed && !Healthy，
	// 而本组用例断言的是「调度是否停止」这一维。不先摆到确定的未观测基线，
	// 断言就会被上一个用例的顺序决定（-shuffle 换排列即假红）。
	prevHealth := SecurityEventsIngestionHealthSnapshot()
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	t.Cleanup(func() { SecurityEventsSetIngestionHealthForTest(prevHealth) })
	te := taskengine.NewEngine(taskengine.Options{StartPaused: true})
	t.Cleanup(te.Stop)
	if err := te.Register(taskengine.Descriptor{
		ID: AutobanFeedTaskID, Family: "system", Name: "安全事件采集",
		Kind: taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			<-rc.Ctx.Done()
			return nil
		},
	}); err != nil {
		t.Fatalf("register feed task: %v", err)
	}
	old := TaskEngine()
	SetTaskEngineForTest(te)
	t.Cleanup(func() { SetTaskEngineForTest(old) })
	return te
}

// 计数唯一喂入源（安全事件采集）停摆时必须判降级；
// LoopOn=false 是用户显式停止与「自愈用尽后停环」的共同终态，恢复调度即不降级。
func TestAutobanFeedHealth_reportsStoppedIngestion(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")

	// 引擎未装配：不判定（测试/装配早期，避免误报）。
	prevEngine := TaskEngine()
	t.Cleanup(func() { SetTaskEngineForTest(prevEngine) })
	SetTaskEngineForTest(nil)
	if degraded, reason := AutobanFeedHealth(); degraded {
		t.Fatalf("引擎未装配时不得报降级: reason=%q", reason)
	}

	te := installFeedHealthTestEngine(t)
	if degraded, reason := AutobanFeedHealth(); !degraded || !strings.Contains(reason, "调度已停止") {
		t.Fatalf("degraded=%v reason=%q, want 调度停止降级", degraded, reason)
	}
	te.StartLoop(AutobanFeedTaskID)
	if degraded, reason := AutobanFeedHealth(); degraded {
		t.Fatalf("调度恢复后不得报降级: reason=%q", reason)
	}
	te.StopLoop(AutobanFeedTaskID)
	if degraded, _ := AutobanFeedHealth(); !degraded {
		t.Fatal("用户停止采集任务后必须报降级（补采/轮转暂停必须可见）")
	}
}

// 喂入源停摆时 RunAutobanCycle 仍正常收尾（只做可见性），但必须留
// WARN 转换行 + 每轮摘要停摆注记；恢复后记一次恢复行且摘要不再带注记。
func TestRunAutobanCycle_surfacesFeedDegraded(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "24h", "all", true)
	te := installFeedHealthTestEngine(t)

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("喂入源停摆不得让本轮失败（可见性语义）: %v", err)
	}
	logPath := taskengine.TaskLogPath(AutobanTaskID)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read autoban task log: %v", err)
	}
	if !strings.Contains(string(data), "数据源异常") {
		t.Fatalf("停摆必须留 WARN 转换行: %q", string(data))
	}
	if !strings.Contains(string(data), "数据源停摆") {
		t.Fatalf("每轮摘要必须追加停摆注记: %q", string(data))
	}
	// 停摆持续期不重复刷屏：再做一轮，WARN 行仍只有一条。
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(logPath)
	if got := strings.Count(string(data), "数据源异常"); got != 1 {
		t.Fatalf("WARN 转换行=%d，want 1（60s 周期不得刷屏）: %q", got, string(data))
	}

	te.StartLoop(AutobanFeedTaskID)
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(logPath)
	if !strings.Contains(string(data), "数据源已恢复") {
		t.Fatalf("恢复沿必须记一次恢复行: %q", string(data))
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if last := lines[len(lines)-1]; strings.Contains(last, "数据源停摆") {
		t.Fatalf("恢复后的摘要不得再带停摆注记: %q", last)
	}
}

// 禁用收尾不清到期计数桶 ——

// 禁用收尾的到期解封必须同步清计数桶（与 Run 轮同语义）：否则窗口内
// 重新启用且零新流量时旧计数仍 ≥ 阈值，下一轮立即重封刚解封的 IP。
// 未到期条目的桶不得清（仅到期解封同步清桶）。
func TestAutobanDisableFlush_forgetsExpiredCounters(t *testing.T) {
	clock := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "198.51.100.1", Remark: autobanEntryRemark, CreatedAt: "2026-10-13 10:00:00", ExpiresAt: "2026-10-14 09:00:00"}, // 已到期
		{Value: "198.51.100.2", Remark: autobanEntryRemark, CreatedAt: "2026-10-14 09:30:00", ExpiresAt: "2026-10-14 11:00:00"}, // 未到期
	})
	oldReloader := autobanReloader
	autobanReloader = func() error { return nil }
	t.Cleanup(func() { autobanReloader = oldReloader })
	autobanMu.Lock()
	autobanWindows["198.51.100.1"] = &autobanCounter{Count: 9, WindowStart: clock.Now(), LastSeen: clock.Now()}
	autobanWindows["198.51.100.2"] = &autobanCounter{Count: 9, WindowStart: clock.Now(), LastSeen: clock.Now()}
	autobanMu.Unlock()

	AutobanDisableFlush()

	autobanMu.Lock()
	_, expiredBucket := autobanWindows["198.51.100.1"]
	_, liveBucket := autobanWindows["198.51.100.2"]
	autobanMu.Unlock()
	if expiredBucket {
		t.Fatal("禁用收尾的到期解封必须同步清计数桶（否则重新启用且零新流量时旧计数立即重封）")
	}
	if !liveBucket {
		t.Fatal("未到期条目的计数桶不得清空（仅到期解封同步清桶）")
	}
}

// 调度态正常（LoopOn=true）但摄取 tick 连续失败时，喂入源健康必须降级——
// 摄取循环对 tick 失败只记账不退出，单看调度态会让「事件停更、计数恒 0」
// 呈现为 feed_degraded=false（健康位分裂型静默失效）。
func TestAutobanFeedHealth_reportsIngestionTickFailures(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	te := installFeedHealthTestEngine(t)
	te.StartLoop(AutobanFeedTaskID)
	t.Cleanup(func() {
		te.StopLoop(AutobanFeedTaskID)
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	// 未观测到任何摄取结果（Observed=false，装配早期）不误报。
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	if degraded, reason := AutobanFeedHealth(); degraded {
		t.Fatalf("未观测前不得报降级: %q", reason)
	}
	// 摄取健康：不降级。
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})
	if degraded, reason := AutobanFeedHealth(); degraded {
		t.Fatalf("摄取健康时不得报降级: %q", reason)
	}
	// 连续失败越阈：降级且携带底层原因。
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{
		Observed: true, Healthy: false, ConsecutiveFailures: 3, LastError: "metrics db unavailable",
	})
	degraded, reason := AutobanFeedHealth()
	if !degraded || !strings.Contains(reason, "metrics db unavailable") {
		t.Fatalf("degraded=%v reason=%q, want 摄取连续失败降级并携带原因", degraded, reason)
	}
	// 恢复健康后不再降级。
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})
	if degraded, reason := AutobanFeedHealth(); degraded {
		t.Fatalf("摄取恢复健康后不得继续报降级: %q", reason)
	}
}

// ---- 审计体积与到期解封口径 ----

// 到期解封审计按条目来源分流：手动封禁条目（remark≠自动封禁）到期时不得
// 被记成「自动封禁 IP 的到期解封」——来源说错会让排障无法区分人工封禁与
// 自动封禁的到期解封。
func TestAutobanAuditExpiredUnban_splitsManualFromAuto(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")

	autobanAuditExpiredUnban([]string{"198.51.100.1", "198.51.100.2"}, []string{"198.51.100.2"})

	rows, err := db.AuditDB.Query(`SELECT detail FROM audit_log WHERE action='自动解封' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		details = append(details, d)
	}
	if len(details) != 2 {
		t.Fatalf("审计行=%d, want 2（自动条目一行、手动条目一行）: %v", len(details), details)
	}
	if !strings.Contains(details[0], "到期自动解封 1 个自动封禁 IP") || !strings.Contains(details[0], "198.51.100.1") {
		t.Fatalf("自动条目行=%q, want 只含自动封禁 IP 198.51.100.1", details[0])
	}
	if strings.Contains(details[0], "198.51.100.2") {
		t.Fatalf("自动条目行不得包含手动封禁条目: %q", details[0])
	}
	if !strings.Contains(details[1], "手动封禁条目") || !strings.Contains(details[1], "198.51.100.2") {
		t.Fatalf("手动条目行=%q, want 明示手动封禁来源", details[1])
	}
}

// 单轮逐 IP 封禁审计受上限约束：超限保留前 N 条逐 IP 行 + 一条汇总行
// （点名总数与省略数）——洪峰下单轮 2000 个 IP 达标不得写 2000 行审计。
func TestAutobanAuditBanned_capsPerRoundRows(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	oldCap := autobanAuditPerRoundCap
	autobanAuditPerRoundCap = 2
	t.Cleanup(func() { autobanAuditPerRoundCap = oldCap })

	autobanAuditBanned(AutobanConfig{Threshold: 5, WindowMinutes: 10, Duration: "1h"},
		[]string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"})

	rows, err := db.AuditDB.Query(`SELECT detail FROM audit_log WHERE action='自动封禁' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	perIP, summaries := 0, 0
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, "省略逐条记录") {
			summaries++
			if !strings.Contains(detail, "共 4 个 IP") || !strings.Contains(detail, "其余 2 个") {
				t.Fatalf("汇总行口径错误: %q（want 共 4 / 其余 2）", detail)
			}
			continue
		}
		perIP++
	}
	if perIP != 2 || summaries != 1 {
		t.Fatalf("逐 IP 行=%d 汇总行=%d, want 2/1（上限门失效或汇总缺失）", perIP, summaries)
	}
}

// 批量到期解封的审计必须按行预算分片：旧实现把整批 IP 拼进一行，超过 4KiB
// 净化上限后后半名单被截断静默丢失（与逐 IP 封禁审计的可追溯性不对称）。
func TestAutobanAuditExpiredUnban_chunksWithinDetailBudget(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	const total = 120
	ips := make([]string, 0, total)
	for i := range total {
		ips = append(ips, fmt.Sprintf("10.%d.%d.%d", i/256, i%256, i%7+1))
	}
	autobanAuditExpiredUnban(ips, nil)

	rows, err := db.AuditDB.Query(`SELECT detail FROM audit_log WHERE action='自动解封' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got int
	joined := strings.Builder{}
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		got++
		if len(detail) >= 4096 {
			t.Fatalf("审计行 %d 字节 ≥ 4KiB 净化上限（会被截断）: %s", len(detail), detail)
		}
		joined.WriteString(detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := (total + autobanUnbanAuditPerLine - 1) / autobanUnbanAuditPerLine
	if got != want {
		t.Fatalf("审计行数=%d, want %d（每行 ≤%d 个 IP）", got, want, autobanUnbanAuditPerLine)
	}
	all := joined.String()
	for _, ip := range ips {
		if !strings.Contains(all, ip) {
			t.Fatalf("审计未覆盖 IP %s（分片丢条目）", ip)
		}
	}
}

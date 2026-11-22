package notify

// v2.4.5 事件体系修正：目录条目/默认订阅、安全库终态事件、摄取降级/恢复、
// 启动事件单发、用户配置变更、登录/MFA 失败去抖、拦截聚合降噪与计数。

import (
	"strings"
	"testing"
	"time"
)

// ---- 目录：新增/改写条目（级别+默认订阅+文案） ----

func TestV245CatalogEntries(t *testing.T) {
	cases := []struct {
		id    string
		level Level
		def   bool
		title string
		body  string
	}{
		{EvtLibUpdated, LevelInfo, false, "规则库更新", "「%s」%s更新%s（%s）"},
		{EvtIngestDegraded, LevelWarn, true, "安全事件摄取降级", "安全事件摄取降级：%s"},
		{EvtIngestRecovered, LevelInfo, true, "安全事件摄取恢复", "安全事件摄取已恢复（降级原因：%s）"},
		{EvtUserUpdated, LevelWarn, true, "用户配置变更", "管理员 %s 修改了用户「%s」（%s）"},
	}
	for _, c := range cases {
		e, ok := catalogByID(c.id)
		if !ok {
			t.Errorf("事件 %s 未进目录", c.id)
			continue
		}
		if e.Level != c.level || e.DefaultSub != c.def || e.TitleFormat != c.title || e.BodyFormat != c.body {
			t.Errorf("目录 %s = {%s,%v,%q,%q}, want {%s,%v,%q,%q}",
				c.id, e.Level, e.DefaultSub, e.TitleFormat, e.BodyFormat,
				c.level, c.def, c.title, c.body)
		}
	}
	// 旧键保留且语义改为「手动发起」。
	if EvtLibUpdated != "sec.lib_updated" {
		t.Fatalf("旧键变更: %q", EvtLibUpdated)
	}
}

func TestBlockedAggregateCatalogBodyIncludesCounters(t *testing.T) {
	e, ok := catalogByID(EvtBlockedAggregate)
	if !ok {
		t.Fatal("拦截聚合事件不在目录")
	}
	for _, want := range []string{"拦截 %s 次", "挑战 %s 次", "自动封禁 %s 次", "TOP 规则"} {
		if !strings.Contains(e.BodyFormat, want) {
			t.Errorf("聚合模板缺 %q: %q", want, e.BodyFormat)
		}
	}
	if e.Level != LevelInfo || !e.DefaultSub {
		t.Fatalf("拦截聚合级别/默认订阅变更: {%s,%v}", e.Level, e.DefaultSub)
	}
}

// ---- 安全库终态事件：成功/失败各一条，字段序=1 库 2 触发 3 版本/错误 ----

func TestLibUpdateResultEvents(t *testing.T) {
	ok := libUpdateResultEvent(true, "CRS规则库", "auto", "版本 4.5.0")
	if ok.Type != EvtLibUpdated || ok.Level != LevelInfo {
		t.Fatalf("成功事件 = {%s,%q}, want {%s,info}", ok.Type, ok.Level, EvtLibUpdated)
	}
	if ok.Fields["2"] != "自动" || ok.Fields["3"] != "成功" {
		t.Fatalf("成功字段=%v", ok.Fields)
	}
	body := renderBody(mustCatalog(t, ok.Type), ok)
	if want := "「CRS规则库」自动更新成功（版本 4.5.0）"; body != want {
		t.Fatalf("成功正文=%q, want %q", body, want)
	}
	bad := libUpdateResultEvent(false, "威胁情报库", "manual", "下载失败：timeout")
	if bad.Type != EvtLibUpdated || bad.Level != LevelWarn {
		t.Fatalf("失败事件 = {%s,%q}, want {%s,warn}", bad.Type, bad.Level, EvtLibUpdated)
	}
	body = renderBody(mustCatalog(t, bad.Type), bad)
	if want := "「威胁情报库」手动更新失败（下载失败：timeout）"; body != want {
		t.Fatalf("失败正文=%q, want %q", body, want)
	}
}

func mustCatalog(t *testing.T, id string) catalogEntry {
	t.Helper()
	e, ok := catalogByID(id)
	if !ok {
		t.Fatalf("事件 %s 不在目录", id)
	}
	return e
}

// ---- 登录/MFA 失败去抖：用户|IP 10 分钟；终态原因绕过去抖 ----

func resetAuthFailureDebounceForTest(t *testing.T) time.Time {
	t.Helper()
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	oldNow := authFailureNow
	authFailureNow = func() time.Time { return now }
	authFailureMu.Lock()
	authFailureSeen = map[string]time.Time{}
	authFailureMu.Unlock()
	t.Cleanup(func() {
		authFailureNow = oldNow
		authFailureMu.Lock()
		authFailureSeen = map[string]time.Time{}
		authFailureMu.Unlock()
	})
	return now
}

func TestPublishLoginFailedDebounce(t *testing.T) {
	resetBlockedStateForTest(t)
	ensureBusStoppedForTest(t)
	base := resetAuthFailureDebounceForTest(t)
	before := DroppedCount()
	date := time.Now().In(dailyLocation()).Format("2006-01-02")
	_, failBefore, _ := readAuthCounters(date)

	PublishLoginFailed("alice", "认证失败", "203.0.113.9")
	PublishLoginFailed("alice", "认证失败", "203.0.113.9")
	if got := DroppedCount() - before; got != 1 {
		t.Fatalf("同用户同 IP 窗口内发布 %d 条, want 1", got)
	}
	PublishLoginFailed("alice", "认证失败", "203.0.113.10")
	if got := DroppedCount() - before; got != 2 {
		t.Fatalf("不同 IP 应独立去抖：累计 %d 条, want 2", got)
	}
	authFailureNow = func() time.Time { return base.Add(10*time.Minute + time.Second) }
	PublishLoginFailed("alice", "认证失败", "203.0.113.9")
	if got := DroppedCount() - before; got != 3 {
		t.Fatalf("10 分钟窗口滑出后应重新发布：累计 %d 条, want 3", got)
	}
	// 通知去抖不得让日报失败计数少记（每次尝试都累加）。
	if _, failAfter, _ := readAuthCounters(date); failAfter-failBefore != 4 {
		t.Fatalf("日报登录失败计数增量=%d, want 4（去抖只作用于通知）", failAfter-failBefore)
	}
}

func TestPublishLoginFailedTerminalReasonBypassesDebounce(t *testing.T) {
	ensureBusStoppedForTest(t)
	resetAuthFailureDebounceForTest(t)
	before := DroppedCount()

	for _, reason := range []string{"账户已锁定", "账号已禁用"} {
		PublishLoginFailed("bob", reason, "198.51.100.7")
		PublishLoginFailed("bob", reason, "198.51.100.7")
	}
	if got := DroppedCount() - before; got != 4 {
		t.Fatalf("终态原因必须绕过去抖每次发布：累计 %d 条, want 4", got)
	}
}

func TestPublishMFAVerifyFailedDebounce(t *testing.T) {
	ensureBusStoppedForTest(t)
	resetAuthFailureDebounceForTest(t)
	before := DroppedCount()

	PublishMFAVerifyFailed("carol", "MFA step-up 验证失败", "203.0.113.11")
	PublishMFAVerifyFailed("carol", "MFA step-up 验证失败", "203.0.113.11")
	if got := DroppedCount() - before; got != 1 {
		t.Fatalf("MFA 同用户同 IP 窗口内发布 %d 条, want 1", got)
	}
	// 与登录失败共用同一用户|IP 键：非终态的登录失败不得绕过 MFA 去抖。
	PublishMFAVerifyFailed("carol", "禁用 MFA 前验证失败", "203.0.113.11")
	if got := DroppedCount() - before; got != 1 {
		t.Fatalf("非终态 MFA 失败不得绕过去抖：累计 %d 条, want 1", got)
	}
	date := time.Now().In(dailyLocation()).Format("2006-01-02")
	if _, _, mfa := readAuthCounters(date); mfa < 3 {
		t.Fatalf("日报 MFA 失败计数=%d, want ≥3（去抖不减少计数）", mfa)
	}
}

// ---- 启动事件：completed 只发一次 ----

func TestPublishStartupCompletedOnce(t *testing.T) {
	ensureBusStoppedForTest(t)
	startupCompletedSent.Store(false)
	t.Cleanup(func() { startupCompletedSent.Store(false) })
	before := DroppedCount()

	PublishStartupCompleted(":8000")
	PublishStartupCompleted(":8000")
	if got := DroppedCount() - before; got != 1 {
		t.Fatalf("startup_completed 发布 %d 条, want 1（幂等）", got)
	}
}

func TestPublishStartupAbnormal(t *testing.T) {
	ensureBusStoppedForTest(t)
	before := DroppedCount()
	PublishStartupAbnormal("initialize database: disk full")
	if got := DroppedCount() - before; got != 1 {
		t.Fatalf("startup_abnormal 发布 %d 条, want 1", got)
	}
}

// ---- 拦截聚合：单次只发一条 / 阈值升级不重复级别 / 挑战与自动封禁计数 ----

func TestBlockedAggregateSingleBlockPublishesOnce(t *testing.T) {
	resetBlockedStateForTest(t)
	evs := recordBlocked("r1")
	if len(evs) != 1 || evs[0].Type != EvtBlockedAggregate {
		t.Fatalf("单次拦截发布 %d 条, want 1 条聚合", len(evs))
	}
	body := renderBody(mustCatalog(t, EvtBlockedAggregate), evs[0])
	if !strings.Contains(body, "拦截 1 次 / 挑战 0 次 / 自动封禁 0 次") {
		t.Fatalf("首条聚合正文未含三项计数: %q", body)
	}
	if evs := recordBlocked("r1"); len(evs) != 0 {
		t.Fatalf("同窗口后续拦截又发布了 %d 条", len(evs))
	}
	if ev := takeBlockedWindowEvent(); ev != nil {
		t.Fatalf("单次拦截窗口 flush 又发布了事件: %+v", ev)
	}
}

func TestBlockedAggregateThresholdEscalatesOncePerLevel(t *testing.T) {
	old := blockedThresholdsFn
	blockedThresholdsFn = func() (int, int) { return 2, 4 }
	t.Cleanup(func() { blockedThresholdsFn = old })
	resetBlockedStateForTest(t)

	e1 := recordBlocked("x")
	e2 := recordBlocked("x")
	e3 := recordBlocked("x")
	e4 := recordBlocked("x")
	e5 := recordBlocked("x")
	if len(e1) != 1 || e1[0].Level != LevelInfo {
		t.Fatalf("首发=%v, want 1 条 info", levels(e1))
	}
	if len(e2) != 1 || e2[0].Level != LevelWarn {
		t.Fatalf("达 warn 阈值=%v, want 1 条 warn", levels(e2))
	}
	if len(e3) != 0 {
		t.Fatalf("未跨新阈值又发 %v", levels(e3))
	}
	if len(e4) != 1 || e4[0].Level != LevelCritical {
		t.Fatalf("达 critical 阈值=%v, want 1 条 critical", levels(e4))
	}
	if len(e5) != 0 {
		t.Fatalf("同级别重复发 %v", levels(e5))
	}
	if ev := takeBlockedWindowEvent(); ev != nil {
		t.Fatalf("升级已发后窗口 flush 重复发: %+v", ev)
	}
}

func TestBlockedAggregateCountsChallengesAndAutobans(t *testing.T) {
	old := blockedThresholdsFn
	blockedThresholdsFn = func() (int, int) { return 2, 100 }
	t.Cleanup(func() { blockedThresholdsFn = old })
	resetBlockedStateForTest(t)

	recordBlocked("SQLi")
	RecordChallengeEvent()
	RecordChallengeEvent()
	recordAutobanInWindow()
	e := recordBlocked("SQLi")
	if len(e) != 1 {
		t.Fatalf("达 warn 阈值发布 %d 条, want 1", len(e))
	}
	body := renderBody(mustCatalog(t, EvtBlockedAggregate), e[0])
	if !strings.Contains(body, "拦截 2 次 / 挑战 2 次 / 自动封禁 1 次") {
		t.Fatalf("聚合正文计数错误: %q", body)
	}
	if !strings.Contains(body, "SQLi") {
		t.Fatalf("聚合正文缺 TOP 规则: %q", body)
	}
}

func levels(evs []Event) []Level {
	out := make([]Level, len(evs))
	for i, e := range evs {
		out[i] = e.Level
	}
	return out
}

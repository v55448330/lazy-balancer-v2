package services

// 自动封禁收敛热路径钉测（2026-10-15，历史第三批）：名单内容变化（merge
// 新封/清到期/容量挤出）后的生效路径——资格门（被启用策略引用，含受信代理
// 网段引用面同日热路径化——原「∧ 非受信代理网段引用」排除合取项已退役，
// 与手动名单写路径同一查询核心）命中 → 投影热路径（零 /load，
// @ipListFast 匹配器 ≤1s stat 热感知）；资格未命中/不可判定/刷新器未注册/
// 未证实收敛（发射面变化/运行配置不可读/渲染被拒）→ 回退既有全量重载
// （节流+暂存+失败再武装语义原样）。节流 Ruling：热路径免节流（文件重写+
// 字节比对毫秒级幂等，60s 任务周期天然限频），节流四态机制专属全量重载
// 回退路径（autobanLastReload 记账不消费）。

import (
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// autobanConvergeSpy 收敛路径间谍：refreshes=投影热路径调用数、reloads=全量
// 重载回调调用数。hot=nil 表示刷新器未注册（生产装配缺席/测试二进制形态）。
type autobanConvergeSpy struct {
	refreshes int
	reloads   int
}

func installAutobanConvergeSpy(t *testing.T, hot func() (IPListProjectionOutcome, error)) *autobanConvergeSpy {
	t.Helper()
	spy := &autobanConvergeSpy{}
	oldRef, oldRel := autobanProjectionRefresher, autobanReloader
	if hot != nil {
		autobanProjectionRefresher = func() (IPListProjectionOutcome, error) { spy.refreshes++; return hot() }
	}
	autobanReloader = func() error { spy.reloads++; return nil }
	t.Cleanup(func() { autobanProjectionRefresher, autobanReloader = oldRef, oldRel })
	return spy
}

// 资格门命中形态夹具：启用中的 deny ACL 策略引用预置名单（seedHotPathPolicy
// 与手动名单写路径热路径钉测同源——单源夹具）。
func seedAutobanListReferencedByPolicy(t *testing.T) int64 {
	t.Helper()
	return seedHotPathPolicy(t, presetListID(t))
}

func autobanReloadAuditRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE username='system' AND action IN ('重载','重载失败') AND detail LIKE '%自动封禁名单%'`).Scan(&n); err != nil {
		t.Fatalf("read reload audit: %v", err)
	}
	return n
}

// 核心钉：资格门命中 → merge 走投影热路径（零 /load）；不落「重载」系统审计
// （审计真实性——配置未重载不得宣称重载）；摘要尾注不宣称「已重载」。
func TestAutobanConverge_gateHitHotPathZeroReload(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "blocked,logged", false)
	seedAutobanListReferencedByPolicy(t)
	spy := installAutobanConvergeSpy(t, func() (IPListProjectionOutcome, error) { return ProjectionConverged, nil })

	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].Value != "203.0.113.1" {
		t.Fatalf("名单 merge 结果=%+v, want 新封 203.0.113.1", entries)
	}
	if spy.refreshes != 1 || spy.reloads != 0 {
		t.Fatalf("资格门命中必须走投影热路径（零 /load）：refreshes=%d reloads=%d", spy.refreshes, spy.reloads)
	}
	if n := autobanReloadAuditRows(t); n != 0 {
		t.Fatalf("热路径收敛不得落「重载」系统审计（审计真实性），命中 %d 条", n)
	}
	if log := autobanLogNow(t); !strings.Contains(log, "投影热路径收敛") || strings.Contains(log, "已重载") {
		t.Fatalf("任务日志尾注=%q, want 投影热路径收敛且不宣称已重载", log)
	}
}

// 资格门未命中且无启用策略/受信代理/CRS 排除引用 → 无发射面，名单落库后
// 不需要任何收敛重载；热路径刷新器与全量重载都不得调用。
func TestAutobanConverge_unreferencedSkipsReload(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "blocked,logged", false)
	spy := installAutobanConvergeSpy(t, func() (IPListProjectionOutcome, error) { return ProjectionConverged, nil })

	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	if len(presetEntries(t)) != 1 {
		t.Fatalf("未引用路径下 merge 结果必须照常落名单，得到 %+v", presetEntries(t))
	}
	if spy.refreshes != 0 || spy.reloads != 0 {
		t.Fatalf("未被引用名单无发射面，必须零收敛调用：refreshes=%d reloads=%d", spy.refreshes, spy.reloads)
	}
	if log := autobanLogNow(t); !strings.Contains(log, "未被引用") || strings.Contains(log, "已重载") {
		t.Fatalf("未引用名单的任务日志尾注=%q, want 未被引用零重载", log)
	}
}

// 刷新器未注册（异常装配/测试二进制）→ 资格门命中也回退全量重载（宁可一次
// 重载，不欠引用方渲染收敛）。
func TestAutobanConverge_refresherMissingFallsBack(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "blocked,logged", false)
	seedAutobanListReferencedByPolicy(t)
	spy := installAutobanConvergeSpy(t, nil)

	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	if spy.refreshes != 0 || spy.reloads != 1 {
		t.Fatalf("刷新器未注册必须回退全量重载：refreshes=%d reloads=%d", spy.refreshes, spy.reloads)
	}
}

// 热路径未证实收敛（发射面变化/运行配置不可读，(false,nil)）→ 回退全量重载
// ——失败回退语义保留。
func TestAutobanConverge_hotNotConfirmedFallsBack(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "blocked,logged", false)
	seedAutobanListReferencedByPolicy(t)
	spy := installAutobanConvergeSpy(t, func() (IPListProjectionOutcome, error) { return ProjectionFallback, nil })

	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	if spy.refreshes != 1 || spy.reloads != 1 {
		t.Fatalf("未证实收敛必须回退全量重载：refreshes=%d reloads=%d", spy.refreshes, spy.reloads)
	}
}

// 受信代理网段引用（trusted_proxy_range_refs）已热路径化（合并网段投影
// tp.txt，lb_file 文件源 ≤1s stat 热感知）→ 资格门只看「被启用策略引用」，
// 引用面变化经投影重写零重载收敛。
func TestAutobanConverge_trustedProxyRefHotPath(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "blocked,logged", false)
	// 只挂受信代理引用、不挂启用策略绑定：资格门的 tp 维度必须独立成立
	// （同时挂策略会让本用例在 tp 维度失效时仍然绿——无鉴别力）。
	listID := presetListID(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_range_refs=? WHERE id=1`,
		"["+strconv.FormatInt(listID, 10)+"]"); err != nil {
		t.Fatalf("seed trusted proxy refs: %v", err)
	}
	spy := installAutobanConvergeSpy(t, func() (IPListProjectionOutcome, error) { return ProjectionConverged, nil })

	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	if spy.refreshes != 1 || spy.reloads != 0 {
		t.Fatalf("受信代理网段引用名单应走投影热路径零重载：refreshes=%d reloads=%d, want 1/0", spy.refreshes, spy.reloads)
	}
}

// 节流 Ruling 钉：热路径免节流——紧随全量重载（节流窗口起点刚记账）的资格
// 命中收敛仍即时执行，不得被 60s 节流窗口压成暂存（节流对象恒为全量重载）。
func TestAutobanConverge_hotPathFreeOfThrottle(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "blocked,logged", false)
	listID := presetListID(t)
	seedHotPathPolicy(t, listID)
	spy := installAutobanConvergeSpy(t, func() (IPListProjectionOutcome, error) { return ProjectionConverged, nil })

	CaddyOpLock.Lock()
	defer CaddyOpLock.Unlock()
	if st := autobanRequestReloadLocked("垫底全量重载"); st != autobanReloadApplied {
		t.Fatalf("前置全量重载 state=%d, want applied（节流起点记账）", st)
	}
	if st := autobanConvergeLocked("热路径收敛", listID); st != autobanReloadHotApplied {
		t.Fatalf("节流窗口内的热路径收敛被压制成 %d——热路径必须免节流", st)
	}
	if spy.refreshes != 1 || spy.reloads != 1 {
		t.Fatalf("refreshes=%d reloads=%d, want 1/1", spy.refreshes, spy.reloads)
	}
	autobanMu.Lock()
	pending := autobanReloadPending
	autobanMu.Unlock()
	if pending {
		t.Fatal("热路径收敛不得置重载暂存")
	}
}

// 禁用收尾的到期清理在资格门命中时同样走热路径（零 /load）；暂存不得残留。
func TestAutobanDisableFlush_hotPathWhenEligible(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "blocked,logged", false)
	seedAutobanListReferencedByPolicy(t)
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "198.51.100.1", Remark: autobanEntryRemark, CreatedAt: "2026-10-13 10:00:00", ExpiresAt: "2026-10-14 09:00:00"}, // 已到期
		{Value: "198.51.100.2", Remark: autobanEntryRemark, CreatedAt: "2026-10-14 09:30:00", ExpiresAt: "2026-10-14 11:00:00"}, // 未到期
	})
	spy := installAutobanConvergeSpy(t, func() (IPListProjectionOutcome, error) { return ProjectionConverged, nil })

	AutobanDisableFlush()

	got := entryValues(presetEntries(t))
	if _, exists := got["198.51.100.1"]; exists {
		t.Fatal("已到期条目必须在禁用收尾清除")
	}
	if _, exists := got["198.51.100.2"]; !exists {
		t.Fatal("未到期条目必须保留")
	}
	if spy.refreshes != 1 || spy.reloads != 0 {
		t.Fatalf("禁用收尾清理变化应走热路径：refreshes=%d reloads=%d", spy.refreshes, spy.reloads)
	}
	autobanMu.Lock()
	pending := autobanReloadPending
	autobanMu.Unlock()
	if pending {
		t.Fatal("禁用收尾后暂存必须清除")
	}
}

// 摘要尾注四态：热路径收敛态不宣称「重载」。
func TestAutobanReloadNote_hotPathState(t *testing.T) {
	if got := reloadNote(false, autobanReloadHotApplied); got != "" {
		t.Fatalf("无变化尾注=%q, want 空", got)
	}
	got := reloadNote(true, autobanReloadHotApplied)
	if !strings.Contains(got, "投影热路径收敛") || !strings.Contains(got, "零重载") {
		t.Fatalf("热路径尾注=%q, want 投影热路径收敛+零重载", got)
	}
	if strings.Contains(got, "已重载") {
		t.Fatalf("热路径尾注不得宣称已重载：%q", got)
	}
}

// ---- 集成钉：真实 CaddyService + fake admin（与手动名单写路径热路径钉测
// 同源夹具：newHotPathTestAdmin/seedHotPathPolicy/mustReadProjection）----

// 装配：autoban 夹具（临时库+时钟+主节点+状态复位）→ 新临时库（迁移种子仍含
// 预置名单/配置列）→ stub 安全库 → fake admin CaddyService；预置名单预置一条
// 手动条目（非空 → deny ACL 段首轮渲染即发射，投影文件就位）；注入与 main.go
// 同形的真实收敛缝（InLock 投影刷新 + 真全量重载包装）。
func installAutobanHotPathIntegration(t *testing.T) (*CaddyService, *hotPathTestAdmin, *autobanConvergeSpy, int64) {
	t.Helper()
	stubSecurityLibsAvailable(t)
	installAutobanFixture(t, "2026-10-14 10:00:00")
	newClusterTestService(t)
	admin := newHotPathTestAdmin(t)
	s := NewCaddyService(admin.srv.URL)
	policyID := seedHotPathPolicy(t, presetListID(t))
	seedPresetEntries(t, []models.IPListEntry{{Value: "198.51.100.1", Remark: "事件处置", CreatedAt: "2026-10-14 09:00:00"}})
	if err := s.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次全量应用: %v", err)
	}
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("首次 /load 次数=%d, want 1", got)
	}
	spy := &autobanConvergeSpy{}
	oldRef, oldRel := autobanProjectionRefresher, autobanReloader
	autobanProjectionRefresher = func() (IPListProjectionOutcome, error) { spy.refreshes++; return s.RefreshIPListProjectionsInLock() }
	autobanReloader = func() error { spy.reloads++; return s.GenerateAndApplyConfigForceInLock() }
	t.Cleanup(func() { autobanProjectionRefresher, autobanReloader = oldRef, oldRel })
	return s, admin, spy, policyID
}

func autobanRunBanCycle(t *testing.T, ip string) {
	t.Helper()
	setAutobanConfigRaw(t, true, 2, 5, "1h", "blocked,logged", false)
	autobanObserveEvent(ip, "blocked", "942100")
	autobanObserveEvent(ip, "blocked", "942100")
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
}

// Given 预置名单已被启用策略引用且投影就位（首轮 /load=1）。
// When merge 新封一 IP（名单-only 变化，发射面不变）。
// Then 投影热路径收敛：零新增 /load、投影文件已含新封 IP、全量重载回调零调用。
func TestAutobanCycle_hotPathZeroLoadProjectionRewritten(t *testing.T) {
	_, admin, spy, policyID := installAutobanHotPathIntegration(t)

	autobanRunBanCycle(t, "203.0.113.77")

	if spy.refreshes != 1 || spy.reloads != 0 {
		t.Fatalf("refreshes=%d reloads=%d, want 1/0（热路径收敛，零全量重载）", spy.refreshes, spy.reloads)
	}
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("自动封禁 merge 后 /load 次数=%d, want 仍 1（零重载）", got)
	}
	content := mustReadProjection(t, policyID)
	if !strings.Contains(content, "203.0.113.77/32") || !strings.Contains(content, "198.51.100.1/32") {
		t.Fatalf("投影内容=%q, want 含新封 IP 与既有手动条目", content)
	}
}

// Given 预置名单为空且被启用策略引用（2026-10-15 始终发射收敛：首轮即恒发射
// 空 @ipListFast，空投影就位）。
// When 首次封禁使名单由空变非空（恒发射下为纯内容变化）。
// Then 投影热路径收敛：零新增 /load、投影文件已含新封 IP、全量重载零调用。
func TestAutobanCycle_emptyListFirstBanHotPath(t *testing.T) {
	stubSecurityLibsAvailable(t)
	installAutobanFixture(t, "2026-10-14 10:00:00")
	newClusterTestService(t)
	admin := newHotPathTestAdmin(t)
	s := NewCaddyService(admin.srv.URL)
	policyID := seedHotPathPolicy(t, presetListID(t)) // 名单为空 → 首轮恒发射空投影
	if err := s.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次全量应用: %v", err)
	}
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("首次 /load 次数=%d, want 1", got)
	}
	spy := &autobanConvergeSpy{}
	oldRef, oldRel := autobanProjectionRefresher, autobanReloader
	autobanProjectionRefresher = func() (IPListProjectionOutcome, error) { spy.refreshes++; return s.RefreshIPListProjectionsInLock() }
	autobanReloader = func() error { spy.reloads++; return s.GenerateAndApplyConfigForceInLock() }
	t.Cleanup(func() { autobanProjectionRefresher, autobanReloader = oldRef, oldRel })

	autobanRunBanCycle(t, "203.0.113.77")

	if spy.refreshes != 1 || spy.reloads != 0 {
		t.Fatalf("空→首封（恒发射下纯内容变化）必须热路径收敛：refreshes=%d reloads=%d, want 1/0", spy.refreshes, spy.reloads)
	}
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("/load 次数=%d, want 仍 1（零重载）", got)
	}
	if content := mustReadProjection(t, policyID); !strings.Contains(content, "203.0.113.77/32") {
		t.Fatalf("投影内容=%q, want 含新封 IP", content)
	}
}

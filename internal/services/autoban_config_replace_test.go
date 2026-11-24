package services

// 「十列自动封禁配置被替换」后的运行期收敛单源：PUT 保存（SetAutobanConfig）
// 与备份导入/还原（通用 UPDATE 提交后）共用同一动作与同一文案判定。
// 两条写入路径各自内联判断会让「响应披露的收敛」与「实际执行的收敛」分叉
// （导入面漏清桶 = 陈旧计数按新口径整批并入封禁候选）。

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/i18n"
	"lazy-balancer-v2/internal/taskengine"
)

func TestAutobanConfigReplaceEffectNote_mapsEffectsToUserText(t *testing.T) {
	// 运行值恒为归一形态（GetAutobanConfig 的 COALESCE 默认）：证据分层三字段
	// 带显式默认值，否则「计数方式由 X 改为 Y」会拿零值当旧配置。
	base := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h",
		Scope: "blocked,logged", DryRun: false,
		CountingMode: "classic", SuspicionMultiplier: 4, ConfirmFloorRatio: "0.4"}
	disabled := base
	disabled.Enabled = false
	withWindow1 := base
	withWindow1.WindowMinutes = 1
	withScopeBlocked := base
	withScopeBlocked.Scope = "blocked"
	withThreshold50 := base
	withThreshold50.Threshold = 50
	withDuration24h := base
	withDuration24h.Duration = "24h"
	withDryRun := base
	withDryRun.DryRun = true
	withEvidence := base
	withEvidence.CountingMode = "evidence"
	withMultiplier := base
	withMultiplier.SuspicionMultiplier = 8
	disabledWithThreshold50 := disabled
	disabledWithThreshold50.Threshold = 50

	cases := []struct {
		name    string
		old     AutobanConfig
		new     AutobanConfig
		want    []string
		empty   bool
		notWant []string
	}{
		{"十列相同", base, base, nil, true, nil},
		{"仅时长变化（无运行期动作）", base, withDuration24h, nil, true, nil},
		{"仅观察模式变化（无运行期动作）", base, withDryRun, nil, true, nil},
		{"窗口变更清桶", base, withWindow1, []string{"统计窗口由 5 分钟改为 1 分钟", "清空自动封禁统计计数"}, false, nil},
		{"口径变更清桶", base, withScopeBlocked, []string{"统计口径由 blocked,logged 改为 blocked", "清空自动封禁统计计数"}, false, nil},
		// 断言与文案单源：仅改证据分层参数（窗口/口径未变）时不得谎报
		// 「窗口/口径由 X 改为 X」——清桶是合并判定，不是变更事实。
		{"仅计数方式变更不谎报窗口/口径", base, withEvidence,
			[]string{"计数方式由 classic 改为 evidence", "清空自动封禁统计计数"}, false, []string{"统计窗口", "统计口径"}},
		{"仅嫌疑倍率变更不谎报窗口/口径", base, withMultiplier,
			[]string{"嫌疑累计倍率由 4 改为 8", "清空自动封禁统计计数"}, false, []string{"统计窗口", "统计口径"}},
		{"仅阈值变更重算达标", base, withThreshold50, []string{"封禁阈值", "重算统计达标标记"}, false, nil},
		{"停用执行禁用收尾", base, disabled, []string{"已停用", "禁用收尾"}, false, nil},
		{"启用联动调度", disabled, base, []string{"已启用", "调度已按新配置开启"}, false, nil},
		// 已停用状态下（old 亦禁用）任何保存/导入都没有「禁用」动作可收尾：
		// 禁用收尾只属于 enabled→disabled 的真实翻转；停用期改阈值只重算达标
		// 标记，响应不得宣称「已执行禁用收尾」（此前 !new.Enabled 判据把
		// 停用期的任意保存都当禁用处理）。
		{"已停用仅改阈值不宣称禁用收尾", disabled, disabledWithThreshold50, []string{"封禁阈值", "重算统计达标标记"}, false, []string{"禁用收尾", "已停用"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			note := AutobanConfigReplaceEffectNote(tt.old, tt.new, i18n.ZH)
			if tt.empty {
				if note != "" {
					t.Fatalf("note=%q, want 空串（无运行期收敛动作不得编造披露）", note)
				}
				return
			}
			for _, want := range tt.want {
				if !strings.Contains(note, want) {
					t.Fatalf("note=%q, want 含 %q", note, want)
				}
			}
			for _, banned := range tt.notWant {
				if strings.Contains(note, banned) {
					t.Fatalf("note=%q, want 不含 %q", note, banned)
				}
			}
		})
	}
}

// Given 计数桶非空（Count=60，阈值 100 时未达标）。
// When 仅阈值调低到 50 后收敛。
// Then 计数桶保留（窗口内证据不丢）、达标标记按新阈值重算；窗口变更则清桶。
func TestReconcileAutobanRuntimeAfterConfigReplace_thresholdOnlyKeepsBuckets(t *testing.T) {
	setupIsolatedDB(t)
	AutobanSeedCounterForTest("45.33.32.77", 60, 100)
	if got := AutobanTrackedIPs(); got != 1 {
		t.Fatalf("前置计数桶=%d, want 1", got)
	}
	if got := autobanReachedCount(); got != 0 {
		t.Fatalf("前置达标数=%d, want 0（60 < 阈值 100）", got)
	}

	old := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "blocked,logged"}
	lowered := old
	lowered.Threshold = 50
	ReconcileAutobanRuntimeAfterConfigReplace(old, lowered)

	if got := AutobanTrackedIPs(); got != 1 {
		t.Fatalf("仅阈值变更后计数桶=%d, want 1（证据保留，只重算达标标记）", got)
	}
	if got := autobanReachedCount(); got != 1 {
		t.Fatalf("调低阈值后达标数=%d, want 1（/status 与过期摘要按新阈值读）", got)
	}

	// 窗口变更：桶长语义变了 → 整表清空。
	narrowed := lowered
	narrowed.WindowMinutes = 1
	ReconcileAutobanRuntimeAfterConfigReplace(lowered, narrowed)
	if got := AutobanTrackedIPs(); got != 0 {
		t.Fatalf("窗口变更后计数桶=%d, want 0（旧计数不可与新口径混算）", got)
	}
}

// Given 另一写者（并发 PUT / 导入提交后收敛）正持配置替换锁。
// When SetAutobanConfig 尝试保存。
// Then 必须等锁释放后才执行「读旧值→写十列→收敛」——并发交错会让后写者
// 以陈旧基线判定「配置未变更」而跳过清桶（宽窗口计数桶在窄口径下残留）。
func TestSetAutobanConfig_serializesWithInFlightReplace(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "blocked", DryRun: true}
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	autobanConfigReplaceMu.Lock()
	done := make(chan error, 1)
	go func() { done <- SetAutobanConfig(cfg) }()
	select {
	case err := <-done:
		autobanConfigReplaceMu.Unlock()
		t.Fatalf("并发写者在替换锁被占用时不得完成（err=%v）：读旧值→写→收敛必须串行", err)
	case <-time.After(100 * time.Millisecond):
	}
	autobanConfigReplaceMu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("锁释放后保存必须完成: %v", err)
	}
}

// Given 配置替换收敛（导入提交后）正持锁。
// When Run 轮读取配置。
// Then 配置读必须等锁释放——否则会读到「新配置 + 旧计数桶」中间态并按新
// 窗口把旧桶整批并入封禁候选。
func TestRunAutobanCycle_configReadWaitsForReplace(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "blocked", true)
	probe := installAutobanConfigProbe(t)

	autobanConfigReplaceMu.Lock()
	done := make(chan error, 1)
	go func() { done <- RunAutobanCycle(taskengine.RunContext{Trigger: "manual"}) }()
	time.Sleep(150 * time.Millisecond)
	if got := probe.fullReads.Load(); got != 0 {
		autobanConfigReplaceMu.Unlock()
		<-done
		t.Fatalf("替换锁被占用期间 Run 不得完成配置读，实际读取 %d 次", got)
	}
	autobanConfigReplaceMu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("锁释放后 Run 必须完成: %v", err)
	}
	if got := probe.fullReads.Load(); got == 0 {
		t.Fatal("锁释放后 Run 轮必须读到配置")
	}
}

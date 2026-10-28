package services

// 「六列自动封禁配置被替换」后的运行期收敛单源：PUT 保存（SetAutobanConfig）
// 与备份导入/还原（通用 UPDATE 提交后）共用同一动作与同一文案判定。
// 两条写入路径各自内联判断会让「响应披露的收敛」与「实际执行的收敛」分叉
// （导入面漏清桶 = 陈旧计数按新口径整批并入封禁候选）。

import (
	"strings"
	"testing"
)

func TestAutobanConfigReplaceEffectNote_mapsEffectsToUserText(t *testing.T) {
	base := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: false}
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

	cases := []struct {
		name  string
		old   AutobanConfig
		new   AutobanConfig
		want  []string
		empty bool
	}{
		{"六列相同", base, base, nil, true},
		{"仅时长变化（无运行期动作）", base, withDuration24h, nil, true},
		{"仅观察模式变化（无运行期动作）", base, withDryRun, nil, true},
		{"窗口变更清桶", base, withWindow1, []string{"统计窗口/口径", "清空自动封禁统计计数"}, false},
		{"口径变更清桶", base, withScopeBlocked, []string{"统计窗口/口径", "清空自动封禁统计计数"}, false},
		{"仅阈值变更重算达标", base, withThreshold50, []string{"封禁阈值", "重算统计达标标记"}, false},
		{"停用执行禁用收尾", base, disabled, []string{"已停用", "禁用收尾"}, false},
		{"启用联动调度", disabled, base, []string{"已启用", "调度已按新配置开启"}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			note := AutobanConfigReplaceEffectNote(tt.old, tt.new)
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
		})
	}
}

// Given 计数桶非空（Count=60，阈值 100 时未达标）。
// When 仅阈值调低到 50 后收敛。
// Then 计数桶保留（窗口内证据不丢）、达标标记按新阈值重算；窗口变更则清桶。
func TestReconcileAutobanRuntimeAfterConfigReplace_thresholdOnlyKeepsBuckets(t *testing.T) {
	setupIsolatedDB(t)
	AutobanSeedCounterForTest("203.0.113.77", 60, 100)
	if got := AutobanTrackedIPs(); got != 1 {
		t.Fatalf("前置计数桶=%d, want 1", got)
	}
	if got := autobanReachedCount(); got != 0 {
		t.Fatalf("前置达标数=%d, want 0（60 < 阈值 100）", got)
	}

	old := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "all"}
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

package services

// 证据分层计数配置面：结构扩列、读写往返、校验域、缺省归一、变更收敛。
// classic 为默认（存量语义冻结）；evidence 由用户显式选择。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given 默认库。
// When 读取配置。
// Then 三新字段落默认值（classic/4/0.4）。
func TestAutobanConfig_defaultsEvidenceFields(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg, err := GetAutobanConfig()
	if err != nil {
		t.Fatalf("GetAutobanConfig: %v", err)
	}
	if cfg.CountingMode != db.DefaultAutobanCountingMode {
		t.Fatalf("CountingMode=%q, want %q", cfg.CountingMode, db.DefaultAutobanCountingMode)
	}
	if cfg.SuspicionMultiplier != db.DefaultAutobanSuspicionMultiplier {
		t.Fatalf("SuspicionMultiplier=%d, want %d", cfg.SuspicionMultiplier, db.DefaultAutobanSuspicionMultiplier)
	}
	if cfg.ConfirmFloorRatio != db.DefaultAutobanConfirmFloorRatio {
		t.Fatalf("ConfirmFloorRatio=%q, want %q", cfg.ConfirmFloorRatio, db.DefaultAutobanConfirmFloorRatio)
	}
}

// Given 空串模式（旧客户端/旧调用方未携带）。
// When 保存。
// Then 归一为 classic（保持存量等权语义），其余字段原样落库。
func TestAutobanSetConfig_normalizesEmptyCountingModeToClassic(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	if err := SetAutobanConfig(AutobanConfig{
		Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h",
		Scope: "blocked,logged", DryRun: true,
	}); err != nil {
		t.Fatalf("SetAutobanConfig: %v", err)
	}
	cfg, err := GetAutobanConfig()
	if err != nil {
		t.Fatalf("GetAutobanConfig: %v", err)
	}
	if cfg.CountingMode != "classic" {
		t.Fatalf("空串模式应归一 classic，得到 %q", cfg.CountingMode)
	}
}

// Given evidence 配置。
// When 保存后回读。
// Then 三字段逐字往返。
func TestAutobanSetConfig_roundTripsEvidenceFields(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	if err := SetAutobanConfig(AutobanConfig{
		Enabled: true, Threshold: 50, WindowMinutes: 5, Duration: "1h",
		Scope: "blocked,logged,challenge_issued,challenge_failed", DryRun: false,
		Escalation: "standard", CountingMode: "evidence",
		SuspicionMultiplier: 10, ConfirmFloorRatio: "0.6",
	}); err != nil {
		t.Fatalf("SetAutobanConfig: %v", err)
	}
	cfg, err := GetAutobanConfig()
	if err != nil {
		t.Fatalf("GetAutobanConfig: %v", err)
	}
	if cfg.CountingMode != "evidence" || cfg.SuspicionMultiplier != 10 || cfg.ConfirmFloorRatio != "0.6" {
		t.Fatalf("往返失败：mode=%q mult=%d floor=%q", cfg.CountingMode, cfg.SuspicionMultiplier, cfg.ConfirmFloorRatio)
	}
}

// 校验域：模式枚举 / 倍率 [2,20] / 打底 {0.2,0.4,0.6}；越界响亮拒绝。
func TestAutobanConfig_evidenceFieldValidation(t *testing.T) {
	base := AutobanConfig{
		Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h",
		Scope: "blocked", DryRun: true, Escalation: "off",
		CountingMode: "classic", SuspicionMultiplier: 4, ConfirmFloorRatio: "0.4",
	}
	if err := ValidateAutobanConfig(base); err != nil {
		t.Fatalf("基线配置应通过校验: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(*AutobanConfig)
	}{
		{"mode-bogus", func(c *AutobanConfig) { c.CountingMode = "bogus" }},
		{"mode-literal", func(c *AutobanConfig) { c.CountingMode = "EVIDENCE" }},
		{"mult-below", func(c *AutobanConfig) { c.SuspicionMultiplier = 1 }},
		{"mult-above", func(c *AutobanConfig) { c.SuspicionMultiplier = 21 }},
		{"floor-bogus", func(c *AutobanConfig) { c.ConfirmFloorRatio = "bogus" }},
		{"floor-free-decimal", func(c *AutobanConfig) { c.ConfirmFloorRatio = "0.5" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			if err := ValidateAutobanConfig(c); err == nil {
				t.Fatalf("%s：越界配置必须拒绝", tc.name)
			}
		})
	}
	// 枚举内边界值通过
	for _, ok := range []AutobanConfig{
		{CountingMode: "evidence", SuspicionMultiplier: 2, ConfirmFloorRatio: "0.2"},
		{CountingMode: "evidence", SuspicionMultiplier: 20, ConfirmFloorRatio: "0.6"},
	} {
		c := base
		c.CountingMode, c.SuspicionMultiplier, c.ConfirmFloorRatio = ok.CountingMode, ok.SuspicionMultiplier, ok.ConfirmFloorRatio
		if err := ValidateAutobanConfig(c); err != nil {
			t.Fatalf("边界值 (%d,%s) 应通过: %v", ok.SuspicionMultiplier, ok.ConfirmFloorRatio, err)
		}
	}
}

// Given 计数桶已有键。
// When 模式/倍率/打底任一变。
// Then 计数桶清空（语义变了旧计数不可比，与 window/scope 同口径）。
func TestAutobanSetConfig_resetsCountersOnCountingModeChange(t *testing.T) {
	for _, tc := range []struct {
		name string
		next AutobanConfig
	}{
		{"mode-classic-to-evidence", AutobanConfig{CountingMode: "evidence", SuspicionMultiplier: 4, ConfirmFloorRatio: "0.4"}},
		{"multiplier-change", AutobanConfig{CountingMode: "evidence", SuspicionMultiplier: 8, ConfirmFloorRatio: "0.4"}},
		{"floor-change", AutobanConfig{CountingMode: "evidence", SuspicionMultiplier: 4, ConfirmFloorRatio: "0.6"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installAutobanFixture(t, "2026-10-14 10:00:00")
			base := AutobanConfig{
				Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h",
				Scope: "blocked,logged", DryRun: true, Escalation: "off",
			}
			if err := SetAutobanConfig(base); err != nil {
				t.Fatalf("SetAutobanConfig base: %v", err)
			}
			autobanObserveEvent("45.33.32.7", "blocked", "942100")
			autobanMu.Lock()
			before := len(autobanWindows)
			autobanMu.Unlock()
			if before != 1 {
				t.Fatalf("前置计数桶=%d, want 1", before)
			}

			next := base
			next.CountingMode, next.SuspicionMultiplier, next.ConfirmFloorRatio =
				tc.next.CountingMode, tc.next.SuspicionMultiplier, tc.next.ConfirmFloorRatio
			if err := SetAutobanConfig(next); err != nil {
				t.Fatalf("SetAutobanConfig next: %v", err)
			}
			autobanMu.Lock()
			after := len(autobanWindows)
			autobanMu.Unlock()
			if after != 0 {
				t.Fatalf("%s：计数语义变更必须清桶，残留 %d 键", tc.name, after)
			}
		})
	}
}

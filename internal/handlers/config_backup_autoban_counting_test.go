package handlers

// 证据分层三列导入钳制/归一钉测：与保存侧「拒」、回填侧「复位」有意分歧——
// 导入是历史快照，越界钳位、缺省归一、非空非法枚举响亮拒绝（整包 400）。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestValidateV2BackupAutobanConfig_countingModeNormalization(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  any
		want string
	}{
		{"empty-normalizes-classic", "", db.DefaultAutobanCountingMode},
		{"classic", "classic", "classic"},
		{"evidence", "evidence", "evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{"autoban_counting_mode": tc.raw}
			if _, err := validateV2BackupAutobanConfig(config); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if got := config["autoban_counting_mode"]; got != tc.want {
				t.Fatalf("counting_mode=%v, want %q", got, tc.want)
			}
		})
	}
	// 键缺席/null 不注入（旧备份保留库内存量值）。
	for _, name := range []string{"absent", "null"} {
		config := map[string]any{}
		if name == "null" {
			config["autoban_counting_mode"] = nil
		}
		if _, err := validateV2BackupAutobanConfig(config); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if name == "absent" {
			if _, exists := config["autoban_counting_mode"]; exists {
				t.Fatal("键缺席不得注入")
			}
		}
	}
}

func TestValidateV2BackupAutobanConfig_countingModeInvalidRejected(t *testing.T) {
	for _, raw := range []any{"bogus", "EVIDENCE", "Classic", float64(1), true} {
		config := map[string]any{"autoban_counting_mode": raw}
		if _, err := validateV2BackupAutobanConfig(config); err == nil {
			t.Fatalf("counting_mode=%v（%T）必须拒绝", raw, raw)
		}
	}
}

func TestValidateV2BackupAutobanConfig_suspicionMultiplierClamp(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  any
		want int
	}{
		{"below-min-clamp", float64(1), services.AutobanSuspicionMultiplierMin},
		{"above-max-clamp", float64(99), services.AutobanSuspicionMultiplierMax},
		{"valid-untouched", float64(10), 10},
		{"non-integer-default", "abc", db.DefaultAutobanSuspicionMultiplier},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{"autoban_suspicion_multiplier": tc.raw}
			notes, err := validateV2BackupAutobanConfig(config)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			got, ok := backupInteger(config["autoban_suspicion_multiplier"])
			if !ok || got != tc.want {
				t.Fatalf("multiplier=%v（%T）, want %d", config["autoban_suspicion_multiplier"], config["autoban_suspicion_multiplier"], tc.want)
			}
			if tc.name != "valid-untouched" && len(notes) == 0 {
				t.Fatal("钳位/归一必须留痕")
			}
		})
	}
}

func TestValidateV2BackupAutobanConfig_confirmFloorGate(t *testing.T) {
	// 枚举内通过；空值归一默认；非空非法拒绝。
	for _, ok := range []string{"0.2", "0.4", "0.6"} {
		config := map[string]any{"autoban_confirm_floor_ratio": ok}
		if _, err := validateV2BackupAutobanConfig(config); err != nil {
			t.Fatalf("floor=%s 应通过: %v", ok, err)
		}
	}
	config := map[string]any{"autoban_confirm_floor_ratio": ""}
	if _, err := validateV2BackupAutobanConfig(config); err != nil {
		t.Fatalf("空值归一: %v", err)
	}
	if config["autoban_confirm_floor_ratio"] != db.DefaultAutobanConfirmFloorRatio {
		t.Fatalf("空值应归一 %q", db.DefaultAutobanConfirmFloorRatio)
	}
	for _, bad := range []any{"0.5", "bogus", float64(0.4)} {
		config := map[string]any{"autoban_confirm_floor_ratio": bad}
		if _, err := validateV2BackupAutobanConfig(config); err == nil {
			t.Fatalf("floor=%v（%T）必须拒绝", bad, bad)
		}
	}
}

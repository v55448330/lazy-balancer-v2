package handlers

// 旧 autoban 口径迁移（单值 scope + count_human_failed 开关 → 四维集合）：
// 开关值经 JSON 反序列化是数值 1/0（float64），裸 ch.(bool) 断言恒 false，
// 「all + 开关开」备份会丢 challenge_failed 维。读取必须走备份布尔单源
// backupBooleanEnabled（bool/数值/字符串同口径）。

import (
	"strings"
	"testing"
)

func TestValidateV2BackupAutobanConfig_legacyCountHumanNumericForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  any
		want string
	}{
		{"json-number-1", float64(1), "blocked,logged,challenge_failed"},
		{"json-number-0", float64(0), "blocked,logged"},
		{"bool-true", true, "blocked,logged,challenge_failed"},
		{"int64-1", int64(1), "blocked,logged,challenge_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{
				"autoban_scope":              "all",
				"autoban_count_human_failed": tc.raw,
			}
			if _, err := validateV2BackupAutobanConfig(config); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if got := config["autoban_scope"]; got != tc.want {
				t.Fatalf("autoban_scope=%v, want %q（数值开关不得被读成 false）", got, tc.want)
			}
			if _, exists := config["autoban_count_human_failed"]; exists {
				t.Fatal("退役开关字段迁移后必须删除")
			}
		})
	}
	// 回归：已是新集合形态原样保留（不走旧值映射）。
	config := map[string]any{"autoban_scope": "blocked,challenge_failed"}
	if _, err := validateV2BackupAutobanConfig(config); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := config["autoban_scope"]; got != "blocked,challenge_failed" {
		t.Fatalf("新集合形态必须原样保留, got %v", got)
	}
	// 边界：开关缺席 = false（不追加 challenge_failed）。
	config = map[string]any{"autoban_scope": "all"}
	notes, err := validateV2BackupAutobanConfig(config)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := config["autoban_scope"]; got != "blocked,logged" {
		t.Fatalf("开关缺席 autoban_scope=%v, want blocked,logged", got)
	}
	if len(notes) == 0 || !strings.Contains(zhWarning(notes[0]), "all") {
		t.Fatalf("迁移必须留痕, notes=%v", notes)
	}
}

// NAT 会话精修退役的旧备份兼容：携带 nat_detection/nat_fingerprint_threshold
// 键的备份导入不拒绝——两键在导入门删除（列已随启动迁移退役，通用写入面
// 按列存在性跳过；显式删除保证预览/比对面无死键），其余键照常校验。
func TestValidateV2BackupAutobanConfig_legacyNatKeysIgnored(t *testing.T) {
	for _, tc := range []struct {
		name string
		nat  any
		fp   any
	}{
		{"json-forms", true, float64(3)},
		{"out-of-range", float64(1), float64(999)},
		{"non-integer", "bogus", "bogus"},
		{"null-forms", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{
				"autoban_scope":                     "blocked,logged",
				"autoban_nat_detection":             tc.nat,
				"autoban_nat_fingerprint_threshold": tc.fp,
			}
			if _, err := validateV2BackupAutobanConfig(config); err != nil {
				t.Fatalf("携带退役 NAT 键的备份不得被拒绝: %v", err)
			}
			for _, key := range []string{"autoban_nat_detection", "autoban_nat_fingerprint_threshold"} {
				if _, exists := config[key]; exists {
					t.Fatalf("退役 NAT 键 %s 必须在导入门删除", key)
				}
			}
			if got := config["autoban_scope"]; got != "blocked,logged" {
				t.Fatalf("其余键不得受影响, autoban_scope=%v", got)
			}
		})
	}
}

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
	if len(notes) == 0 || !strings.Contains(notes[0], "all") {
		t.Fatalf("迁移必须留痕, notes=%v", notes)
	}
}

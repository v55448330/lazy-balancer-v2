package handlers

// 自动封禁 escalation 导入门钉：与保存侧（services.ValidAutobanEscalation）
// 同口径——空串/null 归一缺省 off（旧备份无此键/无值形态）、非空非法与非字符串
// 形态响亮拒绝；合法枚举原样保留。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestValidateV2BackupAutobanConfig_escalationNormalization(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  any
		want string
	}{
		{"absent-default", nil, ""}, // 键缺席由下方单独断言
		{"empty-normalizes-off", "", "off"},
		{"null-preserved", nil, ""}, // null=未携带，与 duration/scope 同口径跳过（库内 DDL 默认兜底）
		{"off", "off", "off"},
		{"standard", "standard", "standard"},
		{"aggressive", "aggressive", "aggressive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{}
			if tc.name != "absent-default" {
				config["autoban_escalation"] = tc.raw
			}
			if _, err := validateV2BackupAutobanConfig(config); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if tc.name == "absent-default" || tc.name == "null-preserved" {
				if tc.name == "absent-default" {
					if _, exists := config["autoban_escalation"]; exists {
						t.Fatal("键缺席不得注入（旧备份保留库内存量值）")
					}
				}
				return
			}
			if got := config["autoban_escalation"]; got != tc.want {
				t.Fatalf("autoban_escalation=%v, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateV2BackupAutobanConfig_escalationInvalidRejected(t *testing.T) {
	for _, raw := range []any{"bogus", "OFF", "Standard", "off,standard", float64(1), true} {
		config := map[string]any{"autoban_escalation": raw}
		if _, err := validateV2BackupAutobanConfig(config); err == nil {
			t.Fatalf("autoban_escalation=%v（%T）必须拒绝", raw, raw)
		}
	}
}

// 归一留痕：空值归一必须并入导入审计明细（与 duration/scope 同族）。
func TestValidateV2BackupAutobanConfig_escalationEmptyLeavesNote(t *testing.T) {
	config := map[string]any{"autoban_escalation": ""}
	notes, err := validateV2BackupAutobanConfig(config)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(notes) == 0 {
		t.Fatal("空值归一必须留痕")
	}
	if config["autoban_escalation"] != db.DefaultAutobanEscalation {
		t.Fatalf("归一值=%v, want %q", config["autoban_escalation"], db.DefaultAutobanEscalation)
	}
}

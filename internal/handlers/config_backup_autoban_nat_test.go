package handlers

// 自动封禁 NAT 两列导入门钉：nat_detection 布尔类型门（backupBooleanConfigKeys
// 枚举承担）；nat_fingerprint_threshold 与保存侧（services.ValidateAutobanConfig）
// 同口径——越界钳到 2-100 同边界、非整数形态归一缺省 3、合法值原样保留。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestValidateV2BackupAutobanConfig_natThresholdClamp(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  any
		want any
	}{
		{"below-min-clamped", float64(1), 2},
		{"negative-clamped", float64(-5), 2},
		{"over-max-clamped", float64(101), 100},
		{"valid-untouched", float64(5), float64(5)},
		{"boundary-min", float64(2), float64(2)},
		{"boundary-max", float64(100), float64(100)},
		{"non-integer-normalized", "bogus", db.DefaultAutobanNatFingerprintThreshold},
		{"float-fraction-normalized", float64(3.5), db.DefaultAutobanNatFingerprintThreshold},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{"autoban_nat_fingerprint_threshold": tc.raw}
			if _, err := validateV2BackupAutobanConfig(config); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if got := config["autoban_nat_fingerprint_threshold"]; got != tc.want {
				t.Fatalf("autoban_nat_fingerprint_threshold=%v（%T）, want %v（%T）", got, got, tc.want, tc.want)
			}
		})
	}
}

// 键缺席/null 不得注入（旧备份保留库内存量值，与 duration/scope 同口径）。
func TestValidateV2BackupAutobanConfig_natThresholdAbsentPreserved(t *testing.T) {
	config := map[string]any{}
	if _, err := validateV2BackupAutobanConfig(config); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, exists := config["autoban_nat_fingerprint_threshold"]; exists {
		t.Fatal("键缺席不得注入")
	}
	config = map[string]any{"autoban_nat_fingerprint_threshold": nil}
	if _, err := validateV2BackupAutobanConfig(config); err != nil {
		t.Fatalf("validate null: %v", err)
	}
	if config["autoban_nat_fingerprint_threshold"] != nil {
		t.Fatal("null=未携带，不得改写")
	}
}

// 钳制/归一必须留痕（导入审计明细）。
func TestValidateV2BackupAutobanConfig_natClampLeavesNote(t *testing.T) {
	config := map[string]any{"autoban_nat_fingerprint_threshold": float64(1)}
	notes, err := validateV2BackupAutobanConfig(config)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(notes) == 0 {
		t.Fatal("越界钳制必须留痕")
	}
}

// nat_detection 布尔键登记：非布尔形态经 v2 类型门整包拒绝（此处钉登记面）。
func TestBackupBooleanConfigKeys_carriesNatDetection(t *testing.T) {
	found := false
	for _, key := range backupBooleanConfigKeys {
		if key == "autoban_nat_detection" {
			found = true
		}
	}
	if !found {
		t.Fatal("autoban_nat_detection 必须登记为布尔键（非布尔形态整包 400）")
	}
}

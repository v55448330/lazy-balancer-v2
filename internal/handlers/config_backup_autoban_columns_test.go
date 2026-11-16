package handlers

// configBackupAutobanColumns 与 services.ReadAutobanConfigFrom 的列清单
// parity 绊线：清单是导入侧「运行期收敛是否需要比对」的输入面，读侧是
// 收敛判定的唯一事实源——两侧漂移会让导入比对到假的「无变化」。
// cc_* 阈值已迁策略级（global_config 同名列零运行期消费），不得混入；
// human_secret 单列登记（携带判定需要，但不属于十列比对）。

import (
	"reflect"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestConfigBackupAutobanColumns_matchReadAutobanConfigFrom(t *testing.T) {
	newBackupTestHandlers(t)
	// 读侧事实源：ReadAutobanConfigFrom 的 SELECT 列（经 PRAGMA 核对存在性，
	// 列序以读侧 SQL 为准——此处按读侧语义序断言集合与顺序）。
	want := []string{
		"autoban_enabled", "autoban_threshold", "autoban_window_minutes",
		"autoban_duration", "autoban_scope", "autoban_dry_run", "autoban_escalation",
		"autoban_counting_mode", "autoban_suspicion_multiplier", "autoban_confirm_floor_ratio",
	}
	if !reflect.DeepEqual(configBackupAutobanColumns, want) {
		t.Fatalf("configBackupAutobanColumns=%v, want 与 ReadAutobanConfigFrom 同集同序 %v", configBackupAutobanColumns, want)
	}
	for _, column := range configBackupAutobanColumns {
		var exists int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name=?`, column).Scan(&exists); err != nil {
			t.Fatalf("pragma lookup %s: %v", column, err)
		}
		if exists == 0 {
			t.Fatalf("清单含不存在的列 %s（死条目）", column)
		}
	}
	// cc_* 死条目不得回流：CC 阈值在策略级，全局列零运行期消费。
	for _, column := range []string{"cc_rps_limit", "cc_rps_window", "cc_4xx_ratio", "cc_session_ua_threshold", "cc_detect_enabled", "cc_session_anomaly"} {
		for _, carried := range configBackupAutobanColumns {
			if carried == column {
				t.Fatalf("cc_* 列 %s 不得入自动封禁收敛清单（阈值已迁策略级）", column)
			}
		}
	}
}

// human_secret 携带判定：单列登记必须被 configCarriesAutobanRuntimeColumns
// 消费（提交后缓存失效收敛的触发前提），且不属于十列清单本体。
func TestConfigCarriesAutobanRuntimeColumns_humanSecretTriggersConvergence(t *testing.T) {
	if !configCarriesAutobanRuntimeColumns(map[string]any{configBackupHumanSecretColumn: "x"}) {
		t.Fatal("携带 human_secret 必须触发提交后收敛判定")
	}
	for _, carried := range configBackupAutobanColumns {
		if carried == configBackupHumanSecretColumn {
			t.Fatal("human_secret 不属于自动封禁十列（ReadAutobanConfigFrom 不读取）")
		}
	}
	// 十列任一携带同样触发；无关键不触发。
	if !configCarriesAutobanRuntimeColumns(map[string]any{"autoban_threshold": 5}) {
		t.Fatal("携带十列之一必须触发收敛判定")
	}
	if configCarriesAutobanRuntimeColumns(map[string]any{"log_level": "info"}) {
		t.Fatal("无关配置键不得触发收敛判定")
	}
	if configCarriesAutobanRuntimeColumns(map[string]any{}) {
		t.Fatal("空配置不得触发收敛判定")
	}
}

package services

// 证据分层缺省归一与 db 治理常量对账钉：OrDefault 的缺省输出必须与
// db.DefaultAutoban*（DDL DEFAULT/启动回填/读侧 COALESCE 的同一单源）恒等，
// 禁止 services 私抄字面量副本——两处漂移会让「缺省归一」与「建库默认」分叉。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given 缺省形态（倍率 0=旧客户端未携带 / 打底空串）。
// When OrDefault 归一。
// Then 输出≡db 治理常量（单源绑定）。
func TestAutobanCountingDefaults_matchDBGovernance(t *testing.T) {
	if got := AutobanSuspicionMultiplierOrDefault(0); got != db.DefaultAutobanSuspicionMultiplier {
		t.Fatalf("倍率缺省归一=%d, want db.DefaultAutobanSuspicionMultiplier=%d", got, db.DefaultAutobanSuspicionMultiplier)
	}
	if got := AutobanConfirmFloorRatioOrDefault(""); got != db.DefaultAutobanConfirmFloorRatio {
		t.Fatalf("打底缺省归一=%q, want db.DefaultAutobanConfirmFloorRatio=%q", got, db.DefaultAutobanConfirmFloorRatio)
	}
}

// Given 显式合法值（非缺省形态）。
// When OrDefault 归一。
// Then 原样透传（归一只补缺省，不改写显式配置）。
func TestAutobanCountingDefaults_explicitValuesPassThrough(t *testing.T) {
	if got := AutobanSuspicionMultiplierOrDefault(8); got != 8 {
		t.Fatalf("显式倍率=%d, want 8", got)
	}
	if got := AutobanConfirmFloorRatioOrDefault("0.6"); got != "0.6" {
		t.Fatalf("显式打底=%q, want 0.6", got)
	}
}

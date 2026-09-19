package services

// 第 44 轮 G1 组修复钉住测试:SEC44-1 存量归一(security_policies 中
// block_status_code=429 行启动归一为 403)。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// SEC44-1(第 44 轮):存量 block_status_code=429 行随启动归一为 403——429
// 保留给限流(overviewmetrics.go:83-90 限流卡片按 code=429 计数),WAF 拦截
// 页 429 会混入限流指标口径。写侧白名单已剔除 429(handlers 侧),存量行经
// legacySecurityEnumBackfills 既有模式归一(security_block_pages 无
// status_code 列,429 仅可能存于 security_policies,见 db.go:492-502 与
// db.go:1234-1236 注释)。
func TestSEC441_normalizeBackfillsBlockStatus429To403(t *testing.T) {
	// Given 主节点(fresh 库 is_master 默认 TRUE),一条 429 遗留行 + 一条合法 404 行
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(
		"INSERT INTO security_policies (name, mode, ip_acl_mode, geoip_mode, block_status_code) VALUES ('legacy-429','blocking','deny','deny',429), ('valid-404','blocking','deny','deny',404)"); err != nil {
		t.Fatalf("seed policies: %v", err)
	}

	// When 启动归一
	NormalizeLegacySecurityPolicyEnums(context.Background())

	// Then 429 行归一为 403(与默认拦截状态码同口径),合法行原值保留
	var legacy, valid int
	if err := db.DB.QueryRow("SELECT block_status_code FROM security_policies WHERE name='legacy-429'").Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow("SELECT block_status_code FROM security_policies WHERE name='valid-404'").Scan(&valid); err != nil {
		t.Fatal(err)
	}
	if legacy != 403 {
		t.Fatalf("block_status_code=429 must normalize to 403, got %d", legacy)
	}
	if valid != 404 {
		t.Fatalf("valid row must be preserved, got %d", valid)
	}
}

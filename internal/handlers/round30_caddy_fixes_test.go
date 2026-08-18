package handlers

import (
	"context"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Round 30 F-4: 启动校验必须一次报出全部坏规则——首错即 return 会让多条坏规则
// 需要重启多次才能逐一暴露；聚合错误每条含规则名 + caddy_id。
func TestValidateEnabledStoredRuleConfigs_reports_all_bad_rules(t *testing.T) {
	// Given
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_http_redirect) VALUES
		('lb_bad_a','坏规则甲','http','a.example.test',80,1,1,1),
		('lb_bad_b','坏规则乙','http','b.example.test',80,1,1,1)`); err != nil {
		t.Fatalf("seed bad rules: %v", err)
	}

	// When
	err := validateEnabledStoredRuleConfigs(context.Background())

	// Then: 两条坏规则在同一次校验中全部报出
	if err == nil {
		t.Fatal("validateEnabledStoredRuleConfigs 接受了两条 80 端口 TLS 跳转自环规则")
	}
	message := err.Error()
	for _, want := range []string{"坏规则甲", "lb_bad_a", "坏规则乙", "lb_bad_b"} {
		if !strings.Contains(message, want) {
			t.Fatalf("错误信息必须包含 %q，实际: %s", want, message)
		}
	}
}

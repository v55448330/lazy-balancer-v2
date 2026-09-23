package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 缺库降级（2026-09-24 用户裁定）：CRS 规则库或 IP2Region 库缺失时，
// 所有安全规则（预检/ACL/限流/WAF/GeoIP/信任直通包裹）整体不渲染——
// coraza Include 缺失文件会让 caddy validate 拒绝整份配置（负载均衡也被
// 拖死），降级为安全段缺席 + 告警，由用户补库后恢复。
// stubSecurityLibsAvailable 把 CRS 目录/IP2Region 库桩到临时可用形态——缺库降级
// （2026-09-24）后，凡断言安全链渲染的测试必须先桩可用，否则安全段整体缺席。
func stubSecurityLibsAvailable(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	crsDir := filepath.Join(tmp, "crs")
	// 空 rules 目录即可视为可用（真实故障形态=目录缺失）；不写探针文件——
	// 949 抬码等发射门以文件存在为条件，测试口径须与历史无库环境一致。
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	xdb := filepath.Join(tmp, "ip2region.xdb")
	if err := os.WriteFile(xdb, []byte("xdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldCRS, oldXdb := crsDirectivesDir, ip2regionLivePath
	crsDirectivesDir, ip2regionLivePath = crsDir, xdb
	t.Cleanup(func() { crsDirectivesDir, ip2regionLivePath = oldCRS, oldXdb })
}

func TestGenerateCaddyConfig_missingSecurityLibs_disablesSecurityChain(t *testing.T) {
	_, database := newClusterTestService(t)
	// Given：http 规则 + stage1 ACL 策略（deny 内联条目）+ 绑定
	if _, err := database.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enabled)
		VALUES ('lb-libs','libs','http','libs.example.com',80,'weighted_round_robin','',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb-libs','127.0.0.1',8080,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	res, err := database.Exec(`INSERT INTO security_policies (name,mode,enabled,policy_type,ip_acl_enabled,ip_acl_mode,ip_acl_list)
		VALUES ('libs-acl','blocking',1,'stage1',1,'deny','["10.99.0.1/32"]')`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb-libs', ?)`, policyID); err != nil {
		t.Fatal(err)
	}

	// 可用形态桩（共享 helper）：CRS 目录含基础设施探针文件 + ip2region 库非空
	stubSecurityLibsAvailable(t)
	tmp := t.TempDir()
	crsDir := crsDirectivesDir
	xdb := ip2regionLivePath

	renderHasWAF := func() bool {
		cfg := GenerateCaddyConfig()
		if msg, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
			t.Fatalf("generate: %s", msg)
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Contains(string(raw), `"handler":"waf"`)
	}

	// 库齐全 → 安全链渲染（预检 coraza 存在）
	crsDirectivesDir, ip2regionLivePath = crsDir, xdb
	if !renderHasWAF() {
		t.Fatal("库齐全时安全链应渲染（coraza 缺席）")
	}
	// CRS 缺失 → 安全链整体不渲染
	crsDirectivesDir = filepath.Join(tmp, "crs-missing")
	if renderHasWAF() {
		t.Fatal("CRS 缺失时安全链不应渲染")
	}
	// CRS 恢复 + IP2Region 缺失 → 同样不渲染
	crsDirectivesDir = crsDir
	ip2regionLivePath = filepath.Join(tmp, "missing.xdb")
	if renderHasWAF() {
		t.Fatal("IP2Region 缺失时安全链不应渲染")
	}
}

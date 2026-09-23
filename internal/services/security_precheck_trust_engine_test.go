package services

// 第 47 轮 F-47-15：预检层「信任名单 DetectionOnly 全局豁免」此前只有字符串顺序钉
// （geoip_caddy_test.go:189-194）与编译钉（enginegate）——「只记录不拦」是运行级
// 语义（phase:1 的 ctl:ruleEngine=DetectionOnly 必须对同相位的后续 GeoIP deny 链
// 生效），字符串/编译测试看不出来。本测试用真实 coraza 事务（R-10：引擎行为实证）
// 钉住三条：①信任 IP 经 id:12 后海外 GeoIP deny 不拦（放行）；②非信任海外 IP 被
// deny 中断；③非信任境内 IP 不命中（形状回归）。

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"lazy-balancer-v2/internal/models"
)

func newPrecheckBehaviorWAF(t *testing.T, directives string) coraza.WAF {
	t.Helper()
	var kept []string
	for _, line := range strings.Split(directives, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SecAuditLog ") {
			continue // 审计日志路径在开发/CI 不存在（非被测对象）
		}
		if strings.HasPrefix(trimmed, "SecAuditEngine ") {
			kept = append(kept, "SecAuditEngine Off") // 同上：本测试只关心中断与否
			continue
		}
		kept = append(kept, line)
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join(kept, "\n")))
	if err != nil {
		t.Fatalf("coraza 拒绝预检指令:\n%v\n--- directives ---\n%s", err, strings.Join(kept, "\n"))
	}
	return waf
}

func TestEngineBehavior_PrecheckTrustDetectionOnlyExemptsGeoIPDeny(t *testing.T) {
	// Given：阶段 0 保留检测信任策略（trust_detection=1，id:12 DetectionOnly）
	// + 海外地域拦截策略（deny 模式，id:800000+policyID 预检链），同一规则绑定。
	stage0 := &models.SecurityPolicy{
		ID: 1, Name: "stage0-retained", Mode: "off",
		PolicyType:         models.PolicyTypeStage0,
		TrustDetection:     true,
		IPWhitelistEnabled: true,
		IPWhitelist:        json.RawMessage(`["203.0.113.9"]`),
	}
	geoip := &models.SecurityPolicy{
		ID: 2, Name: "geoip-overseas", Mode: "blocking",
		PolicyType:     models.PolicyTypeStage1,
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["海外"]`),
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{stage0, geoip}, 403))
	if !strings.Contains(directives, "id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly") {
		t.Fatalf("预检未发射阶段 0 保留检测 id:12:\n%s", directives)
	}
	if !strings.Contains(directives, "id:800002,") {
		t.Fatalf("预检未发射 GeoIP 链（800000+policyID）:\n%s", directives)
	}
	waf := newPrecheckBehaviorWAF(t, directives)

	run := func(clientIP, geoLoc string) *types.Interruption {
		tx := waf.NewTransaction()
		defer func() { _ = tx.Close() }()
		tx.ProcessConnection(clientIP, 12345, "127.0.0.1", 443)
		tx.ProcessURI("/", "GET", "HTTP/1.1")
		tx.AddRequestHeader("X-GeoIP-Loc", geoLoc)
		return tx.ProcessRequestHeaders()
	}

	// ① 信任 IP（命中 id:12）→ 同相位后续 GeoIP deny 只记录不拦（无中断）。
	if it := run("203.0.113.9", "海外"); it != nil {
		t.Fatalf("信任 IP 必须被 id:12 DetectionOnly 豁免（只记录不拦），却发生中断 status=%d rule=%d",
			it.Status, it.RuleID)
	}
	// ② 非信任海外 IP → GeoIP deny 中断（默认 403）。
	it := run("198.51.100.7", "海外")
	if it == nil {
		t.Fatal("非信任海外 IP 必须被 GeoIP deny 中断")
	}
	if it.Status != 403 {
		t.Fatalf("denyStatus=403 时中断码须为 403，got %d", it.Status)
	}
	// ③ 非信任境内 IP → 不命中（形状回归）。
	if it := run("198.51.100.8", "中国"); it != nil {
		t.Fatalf("境内 IP 不应命中海外拦截，却中断 status=%d", it.Status)
	}
}

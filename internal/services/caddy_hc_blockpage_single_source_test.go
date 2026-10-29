package services

// 渲染层结构单源守卫：
//   - 健康检查四门校验与被动块（HTTP/TCP 两份近似实现合并为
//     healthCheckCore/passiveHealthCheck 后，只允许存在一份文案与字段发射点）；
//   - 拦截页「首个内容非空页策略」的选择（403 兜底与 429 限流兜底共用
//     firstPolicyWithBlockPage 后，只允许存在一份选择实现）。
//
// 两侧各写一份时，报错文案、字段名与「空内容页不遮蔽后续有效页」的取舍会
// 静默分叉（HTTP 侧允许空内容页遮蔽即整段拦截页消失）。

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func readCaddySource(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("caddy.go")
	if err != nil {
		t.Fatalf("读取 caddy.go: %v", err)
	}
	return string(src)
}

// 健康检查校验文案与被动块字段在 caddy.go 只允许出现一次：HTTP
// （generateHTTPRouteObjects）与 TCP（buildTCPServer/buildTCPProxyRoute）渲染
// 必须共用 healthCheckCore/passiveHealthCheck。
func TestHealthCheckRenderSingleSource(t *testing.T) {
	src := readCaddySource(t)
	for _, literal := range []string{
		"健康检查间隔无效",
		"健康检查失败阈值无效",
		"健康检查恢复阈值无效",
		"健康检查超时无效",
		`"fail_duration"`,
		`"max_fails"`,
	} {
		if got := strings.Count(src, literal); got != 1 {
			t.Fatalf("%q 在 caddy.go 出现 %d 次, want 1（HTTP/TCP 健康检查渲染必须共用单源，两侧各写一份会静默分叉）", literal, got)
		}
	}
	for _, fn := range []string{"func healthCheckCore(", "func passiveHealthCheck("} {
		if got := strings.Count(src, fn); got != 1 {
			t.Fatalf("%q 在 caddy.go 出现 %d 次, want 1", fn, got)
		}
	}
}

// HTTP 与 TCP 健康检查渲染的等价面钉测：同一份库值必须发射相同的被动块
// 数值与主动探测间隔/超时；只有协议专属键（HTTP 的 passes/fails 与
// unhealthy_status，TCP 的 rise/fall 与 port）允许分叉。
func TestHealthCheckRenderParity_HTTPAndTCP(t *testing.T) {
	stubSecurityLibsAvailable(t)
	rule := truthRule("lb-hc-parity")
	rule.EnableActiveHealthCheck = true
	rule.HealthCheckHost = "probe.parity.test"

	_, mainRoute, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generateHTTPRouteObjects: %v", err)
	}
	httpProxy := findHandlerInChain(t, mainRoute, "reverse_proxy")
	httpHC, _ := httpProxy["health_checks"].(map[string]interface{})
	if httpHC == nil {
		t.Fatalf("HTTP 侧无 health_checks: %v", httpProxy)
	}

	tcpRule := rule
	tcpRule.Protocol = "tcp"
	server, err := buildTCPServer(tcpRule)
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	route := server["routes"].([]interface{})[0].(map[string]interface{})
	tcpProxy := route["handle"].([]interface{})[0].(map[string]interface{})
	tcpHC, _ := tcpProxy["health_checks"].(map[string]interface{})
	if tcpHC == nil {
		t.Fatalf("TCP 侧无 health_checks: %v", tcpProxy)
	}

	httpPassive, _ := httpHC["passive"].(map[string]interface{})
	tcpPassive, _ := tcpHC["passive"].(map[string]interface{})
	for _, key := range []string{"fail_duration", "max_fails"} {
		if fmt.Sprint(httpPassive[key]) != fmt.Sprint(tcpPassive[key]) {
			t.Fatalf("被动块 %s HTTP=%v TCP=%v（同一库值必须同口径）", key, httpPassive[key], tcpPassive[key])
		}
	}
	// HTTP 被动失败还按状态码类码计入（5=500-599 整段）；L4 无状态码面。
	if fmt.Sprint(httpPassive["unhealthy_status"]) != "[5]" {
		t.Fatalf("HTTP unhealthy_status=%v, want [5]", httpPassive["unhealthy_status"])
	}
	if _, ok := tcpPassive["unhealthy_status"]; ok {
		t.Fatalf("TCP 被动块不得发射状态码键: %v", tcpPassive)
	}

	httpActive, _ := httpHC["active"].(map[string]interface{})
	tcpActive, _ := tcpHC["active"].(map[string]interface{})
	if httpActive == nil || tcpActive == nil {
		t.Fatalf("主动块缺失: http=%v tcp=%v", httpActive, tcpActive)
	}
	for _, key := range []string{"interval", "timeout"} {
		if fmt.Sprint(httpActive[key]) != fmt.Sprint(tcpActive[key]) {
			t.Fatalf("主动块 %s HTTP=%v TCP=%v（同一库值必须同口径）", key, httpActive[key], tcpActive[key])
		}
	}
	if httpActive["passes"] != 4 || httpActive["fails"] != 5 {
		t.Fatalf("HTTP passes/fails=%v/%v, want 4/5", httpActive["passes"], httpActive["fails"])
	}
	if tcpActive["rise"] != 4 || tcpActive["fall"] != 5 {
		t.Fatalf("TCP rise/fall=%v/%v, want 4/5", tcpActive["rise"], tcpActive["fall"])
	}
}

// 403 与 429 兜底路由对「首个内容非空页策略」的选择只允许一份实现。
func TestBlockPageSelectionSingleSource(t *testing.T) {
	src := readCaddySource(t)
	if got := strings.Count(src, "func firstPolicyWithBlockPage("); got != 1 {
		t.Fatalf("firstPolicyWithBlockPage 定义数=%d, want 1（403/429 兜底必须共用同一选择实现）", got)
	}
	// 除 helper 内的 `pages[policy.BlockPageID]` 取值外，不得再有内联的
	// 「首个内容非空页策略」扫描（曾是两处逐字重复的循环）。
	if got := strings.Count(src, "if c := securityCtx.blockPageByID[policy.BlockPageID]; c != \"\""); got != 0 {
		t.Fatalf("内联拦截页扫描残留 %d 处, want 0（必须走 firstPolicyWithBlockPage）", got)
	}
	if got := strings.Count(src, "if content := pages[policy.BlockPageID]; content != \"\""); got != 1 {
		t.Fatalf("firstPolicyWithBlockPage 内页取值 %d 处, want 1", got)
	}
}

// 空内容页（页面行已删除）不得遮蔽后续仍有效页的策略——403 兜底与 429
// 限流兜底同口径。
func TestBlockPageSelectionSkipsEmptyPagePolicy(t *testing.T) {
	ctx := &securityPolicyContext{
		policyByRule: map[string][]*models.SecurityPolicy{
			"lb_skip": {
				{ID: 1, BlockPageID: 10, BlockStatusCode: 451, RateLimitEnabled: true},
				{ID: 2, BlockPageID: 20, BlockStatusCode: 418},
			},
		},
		blockPageByID:     map[int]string{20: "later-page"},
		blockPageTypeByID: map[int]string{},
	}
	assertPage := func(t *testing.T, route map[string]interface{}, wantStatus interface{}) {
		t.Helper()
		if route == nil {
			t.Fatal("兜底路由未生成")
		}
		handle := route["handle"].([]interface{})[0].(map[string]interface{})
		if handle["body"] != "later-page" {
			t.Fatalf("body=%v, want later-page（空内容页不得遮蔽后续有效页）", handle["body"])
		}
		if fmt.Sprint(handle["status_code"]) != fmt.Sprint(wantStatus) {
			t.Fatalf("status_code=%v, want %v", handle["status_code"], wantStatus)
		}
	}
	assertPage(t, buildBlockPageErrorRoute("lb_skip", []string{"skip.test"}, ctx), 418)
	assertPage(t, buildRateLimitErrorRoute("lb_skip", []string{"skip.test"}, ctx), 429)
}

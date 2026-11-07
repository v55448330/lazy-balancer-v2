// X-LB-Protocol 双面钉测：HTTP 入口链路与 X-LB-Rule-ID 同型——
//  1. 链首 headers handler 与 X-LB-Rule-ID 同点 set（值为引擎实际协议）：
//     摄取侧以该头字面 tcp 把事件改判为 L4，链首 set 保证改判信号只能来自
//     引擎，客户端伪造的 X-LB-Protocol: tcp 无法把 HTTP 事务改判成 tcp；
//  2. reverse_proxy 无条件剥离：引擎内部控制头不直达上游，无策略规则的
//     规则（链首 handler 不在场）下客户端伪造同名头也不得上泄。
package services

import "testing"

func TestProtocolHeaderChainHeadSetOverridesAndStripped(t *testing.T) {
	stubSecurityLibsAvailable(t) // 缺库降级：安全链（含链首 headers）缺席前先桩可用
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_proto_hdr", "proto.example.test", 8080)
	mpGenBindPolicy(t, database, "lb_proto_hdr", "proto-p1", mpGenPolicySpec{mode: "detection", enabled: true})
	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_proto_hdr", "proto.example.test"))

	handlers, _ := mainRoute["handle"].([]interface{})
	if len(handlers) < 2 {
		t.Fatalf("main chain too short: %#v", handlers)
	}
	names := handlerNames(t, mainRoute)
	if names[0] != "headers" {
		t.Fatalf("chain head=%q, want headers (X-LB-Rule-ID/X-LB-Protocol inject) in %v", names[0], names)
	}
	// 链首 set 同时携带归因头与协议头，值均为引擎派生（set 覆盖客户端伪造值）。
	inject := mustMap(t, handlers[0], "ingress inject handler")
	setHeaders := mustMap(t, inject["request"], "inject request")["set"].(map[string]interface{})
	assertEqual(t, setHeaders["X-LB-Rule-ID"], []string{"lb_proto_hdr"})
	assertEqual(t, setHeaders["X-LB-Protocol"], []string{"http"})

	// reverse_proxy 的 headers.request.delete 清单无条件剥离 X-LB-Protocol。
	var proxy map[string]interface{}
	for _, raw := range handlers {
		if m, ok := raw.(map[string]interface{}); ok && m["handler"] == "reverse_proxy" {
			proxy = m
			break
		}
	}
	if proxy == nil {
		t.Fatalf("reverse_proxy handler missing from main chain %v", names)
	}
	request := mustMap(t, mustMap(t, proxy["headers"], "proxy headers")["request"], "proxy headers request")
	del, ok := request["delete"].([]string)
	if !ok || len(del) == 0 {
		t.Fatalf("headers.request.delete must be a non-empty []string, got %#v", request["delete"])
	}
	for _, header := range del {
		if header == "X-LB-Protocol" {
			return
		}
	}
	t.Fatalf("X-LB-Protocol 不在反向代理 delete 清单（伪造头会直达上游）: %v", del)
}

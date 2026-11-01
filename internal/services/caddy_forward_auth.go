package services

// 认证网关（forward_auth）渲染：Caddy 官方 forward_auth 指令的 JSON 展开形态
// （caddy v2.11.7 adapt 逐块实证）。规则链首插入网关子请求处理器：全部请求
// 先经网关校验——2xx 把网关响应头逐个拷进原请求后继续本规则处理链（未认证
// 请求到此为止，不进指标/安全链）；非 2xx 无匹配 handle_response 条目，
// 网关响应（通常跳登录页的 302/401）原样回拷客户端。认证子请求是独立
// reverse_proxy 实例，不经过本规则的 WAF/审计/限流处理链。

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ValidateForwardAuthGatewayAddress 解析认证网关 upstream（http(s)://host:port）
// 为 Caddy dial 地址；端口缺省按 scheme 补全（80/443）。保存门（handlers）与
// 渲染层共用同一白名单——保存门 400 与渲染显性失败对同一畸形值同结论
// （零兜底，与值型列「库值唯一真相」同族）。
func ValidateForwardAuthGatewayAddress(upstream string) (string, bool, error) {
	trimmed := strings.TrimSpace(upstream)
	if trimmed == "" {
		return "", false, fmt.Errorf("认证网关地址缺失")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", false, fmt.Errorf("认证网关地址 %q 无法解析: %v", trimmed, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false, fmt.Errorf("认证网关地址 %q 必须以 http:// 或 https:// 开头", trimmed)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", false, fmt.Errorf("认证网关地址 %q 缺少主机名", trimmed)
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port), parsed.Scheme == "https", nil
}

// CanonicalForwardAuthCopyHeaders 身份头清单的规范名单源：逐条
// http.CanonicalHeaderKey（Go 标准库——各连字符段首字母大写；非法 token 字节
// 原样返回，畸形仍由保存门/渲染门拒绝，归一不洗白）。与 Caddy 官方
// forward_auth adapt 对 to/占位符名的处理一致（v2.11.7
// forwardauth/caddyfile.go 逐字规范化）——Caddy 运行期响应头占位符注册键恒为
// 规范形（Go http.Header），非规范名拼出的占位符 vars 查表恒 miss → 条件 set
// 永不执行（认证照常放行、身份头静默失注入、无报错）。写侧落库前归一
// （handlers.normalizeForwardAuthValues），渲染侧消费前再归一（防御带外/
// 旧数据）；重复检测随规范化后进行（同一头的两种大小写写法判重复）。
func CanonicalForwardAuthCopyHeaders(list string) string {
	if list == "" {
		return ""
	}
	parts := strings.Split(list, ",")
	for i, part := range parts {
		parts[i] = http.CanonicalHeaderKey(part)
	}
	return strings.Join(parts, ",")
}

// buildForwardAuthHandler 构造链首认证网关子请求处理器。字段齐备性由保存门
// 与启动迁移强制，本函数对缺失/畸形显性报错（错误经 generationFailure 使
// 配置生成失败、旧配置保留）。
func buildForwardAuthHandler(rule SingleRuleConfig) (map[string]interface{}, error) {
	dial, gatewayHTTPS, err := ValidateForwardAuthGatewayAddress(rule.ForwardAuthUpstream)
	if err != nil {
		return nil, fmt.Errorf("规则 %s 认证网关配置无效: %w", rule.CaddyID, err)
	}
	uri := rule.ForwardAuthURI
	if uri == "" || !strings.HasPrefix(uri, "/") || strings.ContainsAny(uri, "\r\n") {
		return nil, fmt.Errorf("规则 %s 认证路径无效（须以 / 开头且不含换行）: %q", rule.CaddyID, uri)
	}
	copyHeaders := splitAndTrim(CanonicalForwardAuthCopyHeaders(rule.ForwardAuthCopyHeaders))
	if len(copyHeaders) == 0 {
		return nil, fmt.Errorf("规则 %s 认证网关身份头清单为空", rule.CaddyID)
	}
	for _, header := range copyHeaders {
		if header != strings.TrimSpace(header) || strings.ContainsAny(header, " \t\r\n:") {
			return nil, fmt.Errorf("规则 %s 认证网关身份头 %q 含非法字符", rule.CaddyID, header)
		}
	}

	handler := map[string]interface{}{
		"handler": "reverse_proxy",
		"rewrite": map[string]interface{}{
			// 恒 GET：网关子请求不携带/不消费原始请求体。
			"method": "GET",
			"uri":    uri,
		},
		// 原始方法与 URI 在改写前捕获回传网关（网关按原始资源判定）；
		// 其余 X-Forwarded-* 由 reverse_proxy 自带。
		"headers": map[string]interface{}{
			"request": map[string]interface{}{
				"set": map[string]interface{}{
					"X-Forwarded-Method": []string{"{http.request.method}"},
					"X-Forwarded-Uri":    []string{"{http.request.uri}"},
				},
			},
		},
		"upstreams": []interface{}{map[string]interface{}{"dial": dial}},
	}
	if gatewayHTTPS {
		// https 网关：项目标准 insecure_skip_verify（与上游 https 渲染同口径）。
		handler["transport"] = map[string]interface{}{
			"protocol": "http",
			"tls":      map[string]interface{}{"insecure_skip_verify": true},
		}
	}

	// 2xx 条目：逐头拷贝网关响应头进原请求（与 caddy adapt 展开形态逐块一致
	// ——delete 清掉客户端伪造的同名头，条件 set 保证网关未回传的头不注入
	// 空值）。非 2xx 无匹配条目：网关响应原样回拷客户端（Caddy 缺省行为）。
	copyRoutes := make([]interface{}, 0, 1+2*len(copyHeaders))
	copyRoutes = append(copyRoutes, map[string]interface{}{
		"handle": []interface{}{map[string]interface{}{"handler": "vars"}},
	})
	for _, header := range copyHeaders {
		placeholder := "{http.reverse_proxy.header." + header + "}"
		copyRoutes = append(copyRoutes, map[string]interface{}{
			"handle": []interface{}{map[string]interface{}{
				"handler": "headers",
				"request": map[string]interface{}{"delete": []string{header}},
			}},
		})
		copyRoutes = append(copyRoutes, map[string]interface{}{
			"match": []interface{}{map[string]interface{}{
				"not": []interface{}{map[string]interface{}{
					"vars": map[string]interface{}{placeholder: []string{""}},
				}},
			}},
			"handle": []interface{}{map[string]interface{}{
				"handler": "headers",
				"request": map[string]interface{}{
					"set": map[string]interface{}{header: []string{placeholder}},
				},
			}},
		})
	}
	handler["handle_response"] = []interface{}{map[string]interface{}{
		"match":  map[string]interface{}{"status_code": []int{2}},
		"routes": copyRoutes,
	}}
	return handler, nil
}

// Package apikey 是 API Key 凭据传输形态的单一事实源：REST 认证中间件与 MCP
// 转发侧必须用同一规则从请求头取 Key。两侧各写一份时，认证侧一旦放宽（新增
// 方案名/兼容小写），转发侧仍按旧前缀判定，表现为「Key 有效但 MCP 工具回
// 缺少 API 密钥」——错误文案指向错误方向，排障成本高。
package apikey

import (
	"net/http"
	"strings"

	"lazy-balancer-v2/internal/accesslog"
)

// apiKeyFromAuthorization 是 Authorization 头中 API Key 形态的唯一解析规则。
// Bearer auth-scheme 按 RFC 7235 §2.1 大小写不敏感；凭据自身的 lb_sk_ 前缀
// 仍精确匹配，避免把 JWT 误归类为 API Key。
//
// 方案与凭据两侧的空白一律剥掉：手工客户端常写成 "Bearer   <key>" 或带尾随
// 空白，按首个空格切分会让凭据带着残留空白去比对哈希，结果是「密钥无效」——
// 错误指向密钥本身，排障方向被误导。Fields 同时拒绝无分隔（"Bearer<key>" 只有
// 一个字段）与空凭据两种形态。
func apiKeyFromAuthorization(value string) (string, bool) {
	fields := strings.Fields(value)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", false
	}
	token := fields[1]
	if !strings.HasPrefix(token, "lb_sk_") {
		return "", false
	}
	return token, true
}

// IsAPIKeyAuthorization 判定 Authorization 头是否为 API Key 形态。
func IsAPIKeyAuthorization(value string) bool {
	_, ok := apiKeyFromAuthorization(value)
	return ok
}

// FromHeader 按约定顺序提取 API Key：X-API-Key 头（头名单源
// accesslog.APIKeyHeaderName）优先；否则 Authorization 头必须是大小写无关的
// Bearer 方案加 lb_sk_ 凭据，并去掉方案前缀。
// 返回空串表示请求未携带 API Key（JWT 或匿名请求）。
func FromHeader(header http.Header) string {
	if key := header.Get(accesslog.APIKeyHeaderName); key != "" {
		return key
	}
	key, _ := apiKeyFromAuthorization(header.Get("Authorization"))
	return key
}

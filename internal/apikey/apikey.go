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

// BearerToken 从 Authorization 头提取 Bearer 凭据（传输侧提取与认证侧解析
// 共用的单一规则）。RFC 7235 §2.1：auth-scheme 大小写不敏感——"bearer x" /
// "BEARER x" 与 "Bearer x" 等价；Fields 同时拒绝裸 token、空令牌与额外字段
// （无分隔/空凭据/三字段一律返回空串）。方案与凭据两侧的空白一律剥掉：手工
// 客户端常写成 "Bearer   <key>" 或带尾随空白，按首个空格切分会让凭据带着
// 残留空白去比对哈希，结果是「密钥无效」——错误指向密钥本身，排障方向被误导。
func BearerToken(value string) string {
	fields := strings.Fields(value)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return ""
	}
	return fields[1]
}

// apiKeyFromAuthorization 是 Authorization 头中 API Key 形态的唯一解析规则：
// 方案段解析复用 BearerToken，凭据自身的 lb_sk_ 前缀仍精确匹配，避免把 JWT
// 误归类为 API Key。
func apiKeyFromAuthorization(value string) (string, bool) {
	token := BearerToken(value)
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

// FromHeader 按约定顺序提取 API Key：专用 API Key 头（头名单源
// accesslog.APIKeyHeaderName）优先；否则 Authorization 头必须是大小写无关的
// Bearer 方案加 lb_sk_ 凭据，并去掉方案前缀。
// 返回空串表示请求未携带 API Key（JWT 或匿名请求）。
func FromHeader(header http.Header) string {
	if key := strings.TrimSpace(header.Get(accesslog.APIKeyHeaderName)); key != "" {
		return key
	}
	key, _ := apiKeyFromAuthorization(header.Get("Authorization"))
	return key
}

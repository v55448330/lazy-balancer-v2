package services

import "regexp"

// Caddy admin 端点原文的唯一剥离点。
//
// /load、/config、/config/、/adapt 的传输失败错误恒是 *url.Error 形态：
//
//	Post "http://<adminURL>/load": dial tcp <admin>:<port>: connect: ...
//
// 自定义 caddy_admin_url 时，把原文写进全员可见面等于把内部控制面地址与端口
// 披露给任意登录用户（含只读 API Key）：caddy_apply_error 横幅、后台重载失败
// 横幅、操作审计 detail 三处必须经本函数。服务端日志（运维可见）保留原文。

// caddyAdminEndpointInError 匹配请求地址（*url.Error 的
// `<Verb> "http://host:port/path": ...` 形态）。
var caddyAdminEndpointInError = regexp.MustCompile(`(Post|Get|Put|Delete|Head|Patch) "(https?://[^"]*)"`)

// caddyAdminDialInError 匹配同一错误文本里紧随其后的拨号/解析地址形态
// （`dial tcp 10.0.0.1:2019: connect: ...`、`dial tcp [::1]:2019: ...`），
// 否则只替换引号内 URL 仍会把 admin 地址与端口留在可见面里。
var caddyAdminDialInError = regexp.MustCompile(`(dial tcp |lookup )([^:\s"]+:\d+|\[[^\]]+\]:\d+)`)

// caddyAdminLookupInError 覆盖解析失败形态：`dial tcp: lookup <host>: no such
// host`——请求地址/拨号形态都带端口，此处只剩裸主机名（自定义 admin 域名时
// 同样是端点披露）。
var caddyAdminLookupInError = regexp.MustCompile(`(lookup )([^\s:"]+)(:)`)

// RedactCaddyAdminEndpoint 把文本里的 Caddy admin 地址替换为占位短语；无地址
// 文本原样返回（幂等——已剥离的文本再次调用不再变化）。
func RedactCaddyAdminEndpoint(text string) string {
	redacted := caddyAdminEndpointInError.ReplaceAllString(text, `${1} "<Caddy admin 端点>"`)
	redacted = caddyAdminDialInError.ReplaceAllString(redacted, `${1}<Caddy admin 端点>`)
	return caddyAdminLookupInError.ReplaceAllString(redacted, `${1}<Caddy admin 端点>${3}`)
}

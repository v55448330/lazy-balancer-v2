// Package accesslog 持有访问日志字段路径的规范形态。
//
// 为什么单独成包：Caddy filter encoder 的删除键是**精确字符串**查表
// （modules/logging/filterencoder.go 的 filtered/AddArray 直接
// fe.Fields[fe.keyPrefix+key]），不做大小写折叠；而请求头在日志里输出的键
// 取自 http.Header 的原键，即经 net/textproto 规范化后的 MIME 形态
// （"X-API-Key" -> "X-Api-Key"）。手写字面量拼写就恒不命中，脱敏静默空转。
// 该路径的消费方跨 db（启动迁移）、services（渲染 encoder）、handlers（写侧
// 归一）三层，且 db 不能反向依赖 services/handlers——故下沉为叶子包，任何
// 一层都从同一处派生，禁止再写字面量。
package accesslog

import (
	"net/textproto"
	"strings"
)

// APIKeyHeaderName 是面板机器接口凭证头名（面板对外契约，大小写不敏感）。
const APIKeyHeaderName = "X-API-Key"

// headerPathPrefix 是访问日志里请求头的字段路径前缀。
const headerPathPrefix = "request>headers>"

// APIKeyHeaderPath 返回引擎 filter encoder 实际命中的字段路径——头名按
// textproto.CanonicalMIMEHeaderKey 规范化（与 http.Header 的键完全一致）。
func APIKeyHeaderPath() string {
	return headerPathPrefix + textproto.CanonicalMIMEHeaderKey(APIKeyHeaderName)
}

// APIKeyHeaderPaths 返回需要发射 delete 的全部路径：规范形态在前，字面量
// 旧形态在后（旧模板/手写格式/非 Go 代理改写后的拼写）。filter 是精确查表，
// 不命中的键没有任何副作用，多发射一条即容忍引擎/代理差异。
func APIKeyHeaderPaths() []string {
	canonical := APIKeyHeaderPath()
	literal := headerPathPrefix + APIKeyHeaderName
	if literal == canonical {
		return []string{canonical}
	}
	return []string{canonical, literal}
}

// IsAPIKeyPath 判断一条 DSL/迁移路径是否表示同一个脱敏事实（大小写不敏感：
// "X-API-Key"/"X-Api-Key"/"x-api-key" 是同一个 HTTP 头）。写侧归一与启动
// 迁移用它识别并移除既有行，避免同一事实在落库值里出现两行。
func IsAPIKeyPath(path string) bool {
	trimmed := strings.TrimSpace(path)
	if len(trimmed) < len(headerPathPrefix) || !strings.EqualFold(trimmed[:len(headerPathPrefix)], headerPathPrefix) {
		return false
	}
	return strings.EqualFold(trimmed[len(headerPathPrefix):], APIKeyHeaderName)
}

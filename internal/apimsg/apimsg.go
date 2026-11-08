// Package apimsg — handler 侧 API 消息双语取用薄层。
// 用法(codemod 生成):models.APIResponse{Code: x, Message: apimsg.T(c, "k_x"), MessageKey: "k_x"}
package apimsg

import (
	"lazy-balancer-v2/internal/i18n"
)

// T 按请求语言取词条文案。
func T(c i18n.Ctx, key string) string { return i18n.T(i18n.FromCtx(c), key) }

// ErrMsg 服务层错误串按请求语言翻译(模板匹配,未命中原样)。
func ErrMsg(c i18n.Ctx, err error) string {
	if err == nil {
		return ""
	}
	return i18n.TrErr(err.Error(), i18n.FromCtx(c))
}

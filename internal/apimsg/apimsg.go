// Package apimsg — handler 侧 API 消息双语取用薄层。
// 用法(codemod 生成):models.APIResponse{Code: x, Message: apimsg.T(c, "k_x"), MessageKey: "k_x"}
package apimsg

import (
	"fmt"
	"strings"
)

import (
	"lazy-balancer-v2/internal/i18n"
)

// T 按请求语言取词条文案。
func T(c i18n.Ctx, key string) string { return i18n.T(i18n.FromCtx(c), key) }

// Tf 模板插值:词条含 %s 占位(与 i18n 错误模板同约定),按序填充。
// audit136-A5:参数放宽 any(int 常量等直传,内部 fmt.Sprint 字符串化)——
// 迁移管线把 fmt.Sprintf("%d", intConst) 调用点转 Tf 时参数类型混合。
func Tf(c i18n.Ctx, key string, args ...any) string {
	tpl := i18n.T(i18n.FromCtx(c), key)
	if len(args) == 0 {
		return tpl
	}
	// 简单顺序填充(词条为受控 codemod 产物,不引入 fmt 动词语义——%d 视同 %s)
	for _, a := range args {
		tpl = replaceFirst(tpl, "%s", fmt.Sprint(a))
		tpl = replaceFirst(tpl, "%d", fmt.Sprint(a))
	}
	return tpl
}

func replaceFirst(s, old, new string) string {
	i := strings.Index(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

// ErrMsg 服务层错误串按请求语言翻译(模板匹配,未命中原样)。
func ErrMsg(c i18n.Ctx, err error) string {
	if err == nil {
		return ""
	}
	return i18n.TrErr(err.Error(), i18n.FromCtx(c))
}

package apimsg

import (
	"fmt"

	"lazy-balancer-v2/internal/i18n"
	"lazy-balancer-v2/internal/models"
)

// Envelope 构造带键的响应信封：业务码 code、按请求语言渲染的 message、稳定键
// message_key 与模板参数 message_params。前端据键 + 参数用自己的词条按界面语言
// 渲染，渲染不出时回落 message。
//
// 带键响应一律经此构造，不在调用点手填三个字段：手写要把键抄两遍（已有 73 处漏抄，
// 前端无从渲染），补模板参数时若把实参再抄一份，实参里的函数调用（apimsg.ErrMsg、
// 脱敏、时间计算）会被执行两次。这里实参只求值一次。
func Envelope(c i18n.Ctx, code int, key string, args ...any) models.APIResponse {
	response := models.APIResponse{Code: code, Message: Tf(c, key, args...), MessageKey: key}
	if len(args) > 0 {
		response.MessageParams = paramTexts(args)
	}
	return response
}

// paramTexts 把模板实参转成回传给前端的文本，与 Tf 填进 message 的逐字相同（Tf 对
// 每个实参做 fmt.Sprint）。参数一律是字符串：前端只做字符串填槽，不存在数字、
// 时间等在两种语言间格式化不一致的角落。
func paramTexts(args []any) []string {
	texts := make([]string, len(args))
	for i, arg := range args {
		texts[i] = fmt.Sprint(arg)
	}
	return texts
}

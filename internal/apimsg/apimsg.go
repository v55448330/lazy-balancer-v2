// Package apimsg — handler 侧 API 消息双语取用薄层。
// 用法:models.APIResponse{Code: x, Message: apimsg.T(c, "rule.versionConflict"), MessageKey: "rule.versionConflict"}
// 键是语义键(域名.驼峰名),在 internal/i18n 的目录登记 zh/en;未登记的键会被原样返回。
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

// Tf 模板插值:词条含占位符(与 i18n 错误模板同约定),按序填充。
// 参数放宽 any(int 常量等直传,内部 fmt.Sprint 字符串化)。
// 槽队列化:旧实现每 arg 先 %s 后 %d 双 replaceFirst——混用
// 模板(%s...%d)一参双填错乱("%s 过长(最多 %d 字符)"→"最多 issuer 字符"),
// %q/%v 永不填充泄漏字面占位。现依序消费:%s/%d/%v/%q 各占一槽,每 arg
// 恰好消费一个槽;%q 槽输出带引号(诊断形态)。%% 是转义的百分号字面量
// (与 i18n.splitTplPlaceholders 同口径):渲染为单个 % 且不消费参数槽,
// %%s 不得被当成占位符。
func Tf(c i18n.Ctx, key string, args ...any) string {
	tpl := i18n.T(i18n.FromCtx(c), key)
	if len(args) == 0 {
		return tpl
	}
	var out strings.Builder
	argIdx := 0
	for i := 0; i < len(tpl); {
		if i+2 <= len(tpl) && tpl[i:i+2] == "%%" {
			out.WriteByte('%')
			i += 2
			continue
		}
		if i+2 <= len(tpl) && (tpl[i:i+2] == "%s" || tpl[i:i+2] == "%d" || tpl[i:i+2] == "%v" || tpl[i:i+2] == "%q") {
			if argIdx < len(args) {
				v := fmt.Sprint(args[argIdx])
				if tpl[i:i+2] == "%q" {
					v = `"` + v + `"`
				}
				out.WriteString(v)
				argIdx++
			} else {
				out.WriteString(tpl[i : i+2])
			}
			i += 2
			continue
		}
		out.WriteByte(tpl[i])
		i++
	}
	return out.String()
}

// ErrMsg 服务层错误串按请求语言翻译(模板匹配,未命中原样)。
func ErrMsg(c i18n.Ctx, err error) string {
	if err == nil {
		return ""
	}
	return i18n.TrErr(err.Error(), i18n.FromCtx(c))
}

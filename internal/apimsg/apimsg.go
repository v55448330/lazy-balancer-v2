// Package apimsg — handler 侧 API 消息取用薄层。
// 用法: models.APIResponse{Code: x, Message: apimsg.T("rule.versionConflict"), MessageKey: "rule.versionConflict"}
// 键是语义键(域名.驼峰名),在 internal/i18n 的目录登记中文母本;未登记的键会被原样返回。
//
// 后端只下发「稳定键 + 中文母本 + 结构化参数」，不按 Accept-Language 渲染：英文等
// 展示文案由前端按 message_key 用自己的词条渲染（2026-11-25 项目所有者裁定，
// web/docs/I18N.md 第 0 节）。
package apimsg

import (
	"fmt"
	"strings"
)

import (
	"lazy-balancer-v2/internal/i18n"
)

// T 取词条中文母本。
func T(key string) string { return i18n.T(key) }

// Tf 模板插值:词条含占位符(与 i18n 错误模板同约定),按序填充。
// 参数放宽 any(int 常量等直传,内部 fmt.Sprint 字符串化)。
// 槽队列化:旧实现每 arg 先 %s 后 %d 双 replaceFirst——混用
// 模板(%s...%d)一参双填错乱("%s 过长(最多 %d 字符)"→"最多 issuer 字符"),
// %q/%v 永不填充泄漏字面占位。现依序消费:%s/%d/%v/%q 各占一槽,每 arg
// 恰好消费一个槽;%q 槽输出带引号(诊断形态)。%% 是转义的百分号字面量
// (与 i18n.splitTplPlaceholders 同口径):渲染为单个 % 且不消费参数槽,
// %%s 不得被当成占位符。
func Tf(key string, args ...any) string {
	tpl := i18n.T(key)
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

// ErrMsg 服务层错误串原样返回（中文母本兜底）。
//
// 后端不翻译错误文案：英文界面需要译文的错误由 handler 用「键 + 参数」重建
// （apimsg.Envelope 的 message_params 携带的是服务层原文的中间件/数据细节，
// 属数据层而非界面文案）。
func ErrMsg(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

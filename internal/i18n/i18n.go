// Package i18n 提供后端 API 消息的中文母本目录。
//
// 设计原则（2026-11-25 项目所有者裁定，web/docs/I18N.md 第 0 节）：
//   - 后端只下发稳定键（域名.驼峰名）与结构化参数；展示文案全部由前端按界面语言
//     用自己的词条渲染（前端英文唯一源：web/src/locales/apiMessages.en.json）。
//   - 后端目录只保留「键 → 中文母本」：message 的兜底原文、审计明细与日志口径。
//     后端不存在英文译文，也不按 Accept-Language 返回不同内容。
//   - 键描述「是哪条消息」，不含措辞——改文案键不变，前端可按键取文案。
package i18n

import (
	"fmt"
	"regexp"
	"sync"
)

var (
	mu      sync.RWMutex
	catalog = map[string]string{} // 键 -> 中文母本
)

// messageKeyPattern 消息键的形态:小写域名 + 一个点 + 小写字母开头的驼峰名(至少两位),
// 如 rule.versionConflict。键描述"是哪条消息",不含措辞——改文案键不变,前端可按键取文案。
var messageKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9]*\.[a-z][A-Za-z0-9]+$`)

// IsMessageKey 报告 s 是否为消息键的形态。
func IsMessageKey(s string) bool {
	return messageKeyPattern.MatchString(s)
}

// Register 登记词条（键 + 中文母本）。仅由 catalog 生成文件与测试调用。
//
// 没有英文参数：后端不登记译文（英文归前端词条）。这条签名本身就是守卫——想在
// 后端塞英文译文会直接编译失败，而不是生成一份与前端分叉的影子目录。
func Register(key, zh string) {
	mu.Lock()
	defer mu.Unlock()
	catalog[key] = zh
}

// T 查词条中文母本;未登记的键原样返回（fail-visible，便于定位漏登记）。
// 后端不存在按语言选择的分支：响应文案恒为中文母本，前端按 message_key 渲染。
func T(key string) string {
	mu.RLock()
	text, ok := catalog[key]
	mu.RUnlock()
	if !ok {
		return key
	}
	return text
}

// Text 按词条模板渲染中文母本，并返回逐个槽位格式化后的参数。
//
// 两路输出必须同源：中文母本用 fmt 动词渲染，参数落库为字符串（审计明细
// detail_params）后由前端按同一模板重装——两边各自格式化会出现「母本 %d 渲染成
// 数字、参数 %s 存成文本」这类不一致。未登记的键按 T 的口径原样返回、参数照常
// 格式化（fail-visible，便于定位漏登记）。
func Text(key string, args ...any) (string, []string) {
	template := T(key)
	params := make([]string, len(args))
	for index, arg := range args {
		params[index] = fmt.Sprint(arg)
	}
	if len(args) == 0 {
		return template, params
	}
	return fmt.Sprintf(template, args...), params
}

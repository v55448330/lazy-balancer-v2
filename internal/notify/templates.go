package notify

import (
	"fmt"
	"strings"
)

// renderTitle/renderBody 按目录模板渲染。参数以 evt.Fields 按序填充
// （fmt.Args 语义）；模板与发布方 Fields 由埋点保证一致（catalog 即契约）。

func renderTitle(e catalogEntry, evt Event) string {
	args := fieldsArgs(evt)
	if len(args) == 0 {
		return e.TitleFormat
	}
	return fmt.Sprintf(e.TitleFormat, trimArgs(e.TitleFormat, args)...)
}

func renderBody(e catalogEntry, evt Event) string {
	args := fieldsArgs(evt)
	body := e.BodyFormat
	if len(args) > 0 {
		body = fmt.Sprintf(e.BodyFormat, trimArgs(e.BodyFormat, args)...)
	}
	// 节点信息不再追加正文后缀（2026-11-22 第五轮裁定）：结构化详情区
	// （QQ 模板 {{node}} 行/邮件卡片节点行/微信默认模板节点行）已呈现，
	// 双份重复且长标签在 pre-wrap 下换行产生怪异双括号。
	return body
}

// trimArgs 截断参数至模板动词数——测试样例统一供 6 参而各事件模板动词数
// 不同（含 0 动词标题），超配会产出 %!(EXTRA …)；0 动词不传参。
func trimArgs(format string, args []any) []any {
	n := strings.Count(format, "%s") + strings.Count(format, "%d") + strings.Count(format, "%v")
	if n == 0 {
		return nil
	}
	if n >= len(args) {
		return args
	}
	return args[:n]
}

// eventDisplayTitle 事件可读标题（目录 TitleFormat 去除动词占位，供消息元信息
// 展示，避免裸事件键如 apikey.expiry_warning 出现在用户消息中）。
func eventDisplayTitle(typ string) string {
	e, ok := catalogByID(typ)
	if !ok {
		return typ
	}
	t := strings.NewReplacer("%s", "", "%d", "", "%v", "").Replace(e.TitleFormat)
	t = strings.TrimSpace(strings.NewReplacer("（）", "", "()", "").Replace(t))
	if t == "" {
		return typ
	}
	return t
}

func fieldsArgs(evt Event) []any {
	args := make([]any, 0, len(evt.Fields))
	// Fields 以 "1","2",… 为键序（发布方模板参数序约定，契约见 catalog.go
	// 头注）：按序连续取键，首个缺号截断——多填键忽略，缺序参数位丢失由
	// 埋点侧以目录为参数序事实源避免。
	for i := 1; ; i++ {
		v, ok := evt.Fields[fmt.Sprintf("%d", i)]
		if !ok {
			break
		}
		args = append(args, v)
	}
	return args
}

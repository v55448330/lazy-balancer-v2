package notify

import (
	"fmt"
	"time"
)

// renderTitle/renderBody 按目录模板渲染。参数以 evt.Fields 按序填充
// （fmt.Args 语义）；模板与发布方 Fields 由埋点保证一致（catalog 即契约）。

func renderTitle(e catalogEntry, evt Event) string {
	args := fieldsArgs(evt)
	if len(args) == 0 {
		return e.TitleFormat
	}
	return fmt.Sprintf(e.TitleFormat, args...)
}

func renderBody(e catalogEntry, evt Event) string {
	args := fieldsArgs(evt)
	body := e.BodyFormat
	if len(args) > 0 {
		body = fmt.Sprintf(e.BodyFormat, args...)
	}
	if evt.Node != "" {
		body += "（节点 " + evt.Node + "）"
	}
	return body
}

func fieldsArgs(evt Event) []any {
	args := make([]any, 0, len(evt.Fields))
	// Fields 以 "1","2",… 为键序（发布方模板参数序约定）。
	for i := 1; ; i++ {
		v, ok := evt.Fields[fmt.Sprintf("%d", i)]
		if !ok {
			break
		}
		args = append(args, v)
	}
	if len(args) == 0 && evt.Time != (time.Time{}) {
		// 无 Fields 的事件（如登录成功）把时间作为尾参兜底，保证模板 %s 不缺参。
	}
	return args
}

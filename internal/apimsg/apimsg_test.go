package apimsg_test

import (
	"testing"

	"lazy-balancer-v2/internal/apimsg"
	i18n "lazy-balancer-v2/internal/i18n"
)

type tfCtx map[string]any

func (c tfCtx) Done() <-chan struct{} { return nil }
func (c tfCtx) Get(key any) (any, bool) {
	v, ok := c[key.(string)]
	return v, ok
}

func zhCtx() tfCtx { return tfCtx{i18n.CtxLangKey: i18n.ZH} }

// audit137-P2-1:Tf 槽队列化——混用模板一参双填回归钉+多槽依序消费钉。
func TestTfSlotQueue(t *testing.T) {
	c := zhCtx()
	// 混用模板(%s+%d)两参依序——旧实现一参双填
	if got := apimsg.Tf(c, "k_69d65efd", "issuer", 64); got != "issuer 过长（最多 64 字符）" {
		t.Fatalf("混用模板: %q", got)
	}
	// %q 槽带引号诊断形态
	if got := apimsg.Tf(c, "k_a9176a1a", "bogus", "a、b"); got != `未知日志类型 "bogus"，可选值：a、b` {
		t.Fatalf("%%q 槽: %q", got)
	}
	// %v 槽规一为 %s 语义+参数多于槽时多余忽略
	if got := apimsg.Tf(c, "k_410be8bf", 7, "detail"); got != "自定义规则 7 的条件解析失败: detail" {
		t.Fatalf("%%v 槽: %q", got)
	}
	// 参数少于槽:占位保留
	if got := apimsg.Tf(c, "k_69d65efd"); got != "%s 过长（最多 %d 字符）" {
		t.Fatalf("缺参回退: %q", got)
	}
}

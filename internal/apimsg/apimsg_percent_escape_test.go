package apimsg_test

import (
	"testing"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/i18n"
)

// Tf 的 %% 转义必须与 i18n.splitTplPlaceholders 同口径：%% 渲染为单个 %
// 字面量且不消费参数槽，%%s 不得被当成占位符。
func TestTf_percentEscapeMatchesTemplateConvention(t *testing.T) {
	i18n.Register("t.percent.escape", "进度 %s%%，%%s 是字面量", "progress %s%%, %%s is literal")
	c := tfCtx{i18n.CtxLangKey: i18n.ZH}
	if got := apimsg.Tf(c, "t.percent.escape", 50); got != "进度 50%，%s 是字面量" {
		t.Fatalf("zh Tf=%q", got)
	}
	en := tfCtx{i18n.CtxLangKey: i18n.EN}
	if got := apimsg.Tf(en, "t.percent.escape", 50); got != "progress 50%, %s is literal" {
		t.Fatalf("en Tf=%q", got)
	}
	// 零参直返形态：模板原样保留（%% 不展开，与既有零参契约一致）。
	if got := apimsg.Tf(c, "t.percent.escape"); got != "进度 %s%%，%%s 是字面量" {
		t.Fatalf("零参 Tf=%q", got)
	}
}

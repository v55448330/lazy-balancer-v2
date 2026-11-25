package apimsg_test

import (
	"testing"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/i18n"
)

// Tf 的 %% 转义必须与模板槽位口径一致：%% 渲染为单个 % 字面量且不消费参数槽，
// %%s 不得被当成占位符。
func TestTf_percentEscapeMatchesTemplateConvention(t *testing.T) {
	i18n.Register("t.percent.escape", "进度 %s%%，%%s 是字面量")
	if got := apimsg.Tf("t.percent.escape", 50); got != "进度 50%，%s 是字面量" {
		t.Fatalf("zh Tf=%q", got)
	}
	// 零参直返形态：模板原样保留（%% 不展开，与既有零参契约一致）。
	if got := apimsg.Tf("t.percent.escape"); got != "进度 %s%%，%%s 是字面量" {
		t.Fatalf("零参 Tf=%q", got)
	}
}

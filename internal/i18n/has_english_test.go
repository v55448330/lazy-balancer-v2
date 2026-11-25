package i18n

// 「中文兜底」与「独立英文译文」的区分（2026-11-25 项目所有者裁定：后端 message
// 保留中文原文作兜底、不再翻译；英文译文归前端词条）。
//
// 转移键化的新消息在后端目录只登记中文兜底（英文留空），T(EN) 按既有回落规则返回
// 中文。那些“英文不得含汉字/英文动词必须对齐”的守卫因此必须能区分「没有英文译文」
// 与「英文译文有问题」——否则中文兜底会被误判成未翻译缺陷。

import "testing"

func TestHasEnglish_reportsDedicatedTranslationsOnly(t *testing.T) {
	// 目标：有独立英文译文 → true；只有中文兜底 → false；未登记 → false。
	const withEn, zhOnly, missing = "test.hasEnglish.withEn", "test.hasEnglish.zhOnly", "test.hasEnglish.missing"
	Register(withEn, "有英文", "Has English")
	Register(zhOnly, "只有中文", "")
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		delete(catalog, withEn)
		delete(catalog, zhOnly)
	})

	if !HasEnglish(withEn) {
		t.Errorf("%s 有独立英文译文，HasEnglish 应为 true", withEn)
	}
	if HasEnglish(zhOnly) {
		t.Errorf("%s 只有中文兜底，HasEnglish 应为 false", zhOnly)
	}
	if HasEnglish(missing) {
		t.Errorf("%s 未登记，HasEnglish 应为 false", missing)
	}
	// 回归：中文兜底的键在英文界面按既有规则回落中文（T 的行为不变）。
	if got := T(EN, zhOnly); got != "只有中文" {
		t.Errorf("中文兜底的键在 EN 下应回落中文，got %q", got)
	}
	if got := T(ZH, zhOnly); got != "只有中文" {
		t.Errorf("中文母本，got %q", got)
	}
}

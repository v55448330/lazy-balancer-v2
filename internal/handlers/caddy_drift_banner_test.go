package handlers

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/services"
)

// 漂移横幅检测时间从正文拆出——正文只留
// 漂移内容（供横幅主文案），检测时间经独立字段供 meta 次行展示。

func TestFormatDriftBanner_excludesDetectTime(t *testing.T) {
	// Given 缺失+多余两形态与检测时间
	// When
	banner := services.FormatDriftRoutes([]string{"测试规则（lb_a）"}, []string{"幽灵（lb_b）"})

	// Then 正文不含检测时间（拆到 config_drift_since），内容两段保留。
	// 时间字面量的归属由下方 TestDriftBannerAndSinceFields_splitCleanly 用
	// driftSinceText(drift) == since 钉住；此处输入本身不含时间，若再断言
	// 「正文不含某个时间字面量」只是恒真噪声。
	if strings.Contains(banner, "检测于") {
		t.Fatalf("banner=%q, want 不含检测时间", banner)
	}
	if !strings.Contains(banner, "缺失规则路由: 测试规则（lb_a）") || !strings.Contains(banner, "多余规则路由: 幽灵（lb_b）") {
		t.Fatalf("banner=%q, want 缺失/多余两段俱在", banner)
	}
}

// 状态接口两字段（config_drift / config_drift_since）的契约：正文只含
// 漂移内容，首次检测时间单独下发；一致时两者皆空（前端据此隐藏横幅）。
func TestDriftBannerAndSinceFields_splitCleanly(t *testing.T) {
	const since = "2026-10-23 09:41:07"
	drift := services.ConfigDriftStatus{
		Consistent: false,
		Missing:    []string{"测试规则（lb_a）"},
		Extra:      []string{"幽灵（lb_b）"},
		Since:      since,
		CheckedAt:  "2026-10-23 09:45:00",
	}

	banner := driftBannerText(drift)
	if strings.Contains(banner, since) {
		t.Fatalf("banner=%q, want 不含 Since（时间走 config_drift_since）", banner)
	}
	if !strings.Contains(banner, "测试规则（lb_a）") || !strings.Contains(banner, "幽灵（lb_b）") {
		t.Fatalf("banner=%q, want 缺失/多余两段俱在", banner)
	}
	if got := driftSinceText(drift); got != since {
		t.Fatalf("driftSinceText=%q, want %q", got, since)
	}

	consistent := services.ConfigDriftStatus{Consistent: true, Since: since}
	if got := driftBannerText(consistent); got != "" {
		t.Fatalf("一致时正文必须为空, got %q", got)
	}
	if got := driftSinceText(consistent); got != "" {
		t.Fatalf("一致时 Since 必须为空, got %q", got)
	}
}

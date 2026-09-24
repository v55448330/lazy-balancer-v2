package handlers

import (
	"strings"
	"testing"
)

// F49-P5-1（第 49 轮审计 + 用户反馈）：漂移横幅检测时间从正文拆出——正文只留
// 漂移内容（供横幅主文案），检测时间经独立字段供 meta 次行展示。

func TestFormatDriftBanner_excludesDetectTime(t *testing.T) {
	// Given 缺失+多余两形态与检测时间
	// When
	banner := formatDriftBanner([]string{"测试规则（lb_a）"}, []string{"幽灵（lb_b）"})

	// Then 正文不含检测时间（拆到 config_drift_since），内容两段保留
	if strings.Contains(banner, "检测于") || strings.Contains(banner, "23:19:04") {
		t.Fatalf("banner=%q, want 不含检测时间", banner)
	}
	if !strings.Contains(banner, "缺失规则路由: 测试规则（lb_a）") || !strings.Contains(banner, "多余规则路由: 幽灵（lb_b）") {
		t.Fatalf("banner=%q, want 缺失/多余两段俱在", banner)
	}
}

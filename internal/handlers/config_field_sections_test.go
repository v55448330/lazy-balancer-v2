package handlers

// U8-P4-1（Round 62 审计）：ConfigFieldSections 必须覆盖 config_changes.go
// planConfigChanges 全部 add() 字段，否则字段级审计归因落「全局配置」
// （github_token 曾漏——R72 同批字段，SYS-2 同族漏点）。
// U08-F04（第 78 轮）：原用例维护一份手抄字段清单——实现新增 add() 字段时
// 清单同步漏改即假绿（threat_screen_mode/security_events_retention_days/
// security_events_row_cap 三字段即此形态漏检）。改为直接扫描源码提取
// `add("field"` 首参，与 ConfigFieldSections 双向比对（源码为唯一清单）。

import (
	"os"
	"regexp"
	"testing"

	"lazy-balancer-v2/internal/services"
)

// configChangeAddFieldRe 匹配 planConfigChanges 的 add("field", ...) 调用；
// 闭包定义行 `add := func(field, ...)` 不含 `add("`，不会误命中。
var configChangeAddFieldRe = regexp.MustCompile(`add\("([^"]+)",`)

// configChangeFieldTokensFromSource 从源码提取 planConfigChanges 全部 add()
// 首参（令牌），顺序与实现一致。
func configChangeFieldTokensFromSource(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("config_changes.go")
	if err != nil {
		t.Fatalf("read config_changes.go: %v", err)
	}
	matches := configChangeAddFieldRe.FindAllStringSubmatch(string(data), -1)
	fields := make([]string, 0, len(matches))
	for _, m := range matches {
		fields = append(fields, m[1])
	}
	return fields
}

func TestConfigFieldSections_matchConfigChangeSource(t *testing.T) {
	fields := configChangeFieldTokensFromSource(t)
	if len(fields) < 40 {
		t.Fatalf("源码提取 add() 字段=%d 个（期望 ≥40）——提取器失配或计划函数结构变更", len(fields))
	}
	seen := make(map[string]bool, len(fields))
	for _, field := range fields {
		if seen[field] {
			continue // 同字段多次 add() 合法
		}
		seen[field] = true
		section, ok := services.ConfigFieldSections[field]
		if !ok {
			t.Errorf("ConfigFieldSections missing add() field %q: audit attribution falls back to 全局配置", field)
			continue
		}
		if section == "" {
			t.Errorf("ConfigFieldSections[%q] has empty section", field)
		}
	}
	// 反向：映射不得含 add() 未使用的孤儿条目（字段改名/删除后的残留漂移）。
	for field := range services.ConfigFieldSections {
		if !seen[field] {
			t.Errorf("ConfigFieldSections 含 add() 未使用的字段 %q——映射残留/字段已改名", field)
		}
	}
}

func TestConfigFieldSections_recentDriftKeysPinned(t *testing.T) {
	// 近两轮漂移键显式钉死（U8-P4-1 + SYS-2 + U08-F04），防止镜像清单漏列时
	// 静默通过。
	pinned := map[string]string{
		"github_token":                   "基础设置",
		"mfa_write_guard":                "基础设置",
		"mfa_lockout_enabled":            "基础设置",
		"threat_screen_mode":             "基础设置",
		"security_events_retention_days": "基础设置",
		"security_events_row_cap":        "基础设置",
	}
	for field, want := range pinned {
		if got := services.ConfigFieldSections[field]; got != want {
			t.Fatalf("ConfigFieldSections[%q]=%q, want %q", field, got, want)
		}
	}
}

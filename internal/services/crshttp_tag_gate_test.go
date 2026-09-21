package services

import (
	"strings"
	"testing"
)

// 第 47 轮 F-47-4：GitHub release tag 的两条获取路径（API 的 tag_name / HTML
// 跳转的 /releases/tag/<tag>）此前均无字符集与长度校验——HTML 回退路径虽被正则
// `([^"'/]+)` 间接限制，API 路径可携带控制字符/换行（写入版本行、日志与审计，
// 并参与 raw.githubusercontent URL 拼接）。统一在两条解析漏斗处校验白名单。
func TestReleaseTagValidation_charsetAndLength(t *testing.T) {
	valid := []string{"v4.29.0", "v4.29.0-0-0", "v3.17.0", "v2.3.1", "release-2026_09", "v1.0.0+meta"}
	for _, tag := range valid {
		if err := validateReleaseTag(tag); err != nil {
			t.Fatalf("validateReleaseTag(%q) = %v, want nil（合法形状被拒）", tag, err)
		}
	}
	invalid := []struct {
		name string
		tag  string
	}{
		{"换行（日志/审计行伪造面）", "v4.29.0\ninjected"},
		{"空格", "v4 29 0"},
		{"引号", `v4.29.0"x`},
		{"路径穿越", "../../etc/passwd"},
		{"斜杠", "v4/29"},
		{"超长（>64）", "v" + strings.Repeat("9", 80)},
		{"空", ""},
		{"前导点", ".hidden"},
		{"百分号编码未解码残留", "v4.29.0%0a"},
	}
	for _, tc := range invalid {
		if err := validateReleaseTag(tc.tag); err == nil {
			t.Fatalf("validateReleaseTag(%q)（%s）= nil, want error", tc.tag, tc.name)
		}
	}
}

// 两条解析漏斗均接入校验（API JSON 路径与 HTML 跳转路径）。
func TestGitHubTagParsers_rejectUnsafeTags(t *testing.T) {
	if _, err := parseGitHubLatestTag([]byte(`{"tag_name":"v4.29.0\nevil"}`)); err == nil {
		t.Fatal("parseGitHubLatestTag 未拒含换行的 tag_name")
	}
	if _, err := parseGitHubLatestTag([]byte(`{"tag_name":"v4.29.0"}`)); err != nil {
		t.Fatalf("parseGitHubLatestTag 拒了合法 tag: %v", err)
	}
	if _, err := parseGitHubTagFromLocation("https://github.com/x/y/releases/tag/v4.29.0%0a"); err == nil {
		t.Fatal("parseGitHubTagFromLocation 未拒非法 tag 形状")
	}
	if got, err := parseGitHubTagFromLocation("https://github.com/x/y/releases/tag/v4.29.0"); err != nil || got != "v4.29.0" {
		t.Fatalf("parseGitHubTagFromLocation 合法形状: got=%q err=%v", got, err)
	}
}

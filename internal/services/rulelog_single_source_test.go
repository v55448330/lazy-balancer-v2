package services

// 规则日志文件族识别单源守卫：删除侧（ruleLogComponentOf）与统计侧
// （handlers.classifyRotationCopyName）必须共用同一份 timberjack 副本解析
// （SplitTimberjackRotationCopy / StripRotationCollisionSuffix）。
//
// 两侧各持一份解析时，统计侧认领的 `-<时间戳>-<尺寸>-<reason>.log` 形态在
// 删除侧落成一个幻影规则 ID（`lb_abc-20261018-101500-64-size`），删除与孤儿
// 清理只能靠孤儿兜底延迟收敛；两套「时间戳尾」语法就此静默分叉。

import (
	"os"
	"strings"
	"testing"
)

func readServiceRepoFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s: %v", path, err)
	}
	return string(data)
}

func TestRuleLogFileNameFamilyParsedOnce(t *testing.T) {
	rulelogSrc := readServiceRepoFile(t, "rulelog.go")
	for _, want := range []string{"func SplitTimberjackRotationCopy(", "func StripRotationCollisionSuffix("} {
		if got := strings.Count(rulelogSrc, want); got != 1 {
			t.Fatalf("%q 在 services/rulelog.go 出现 %d 次, want 1（文件族解析必须单源）", want, got)
		}
	}
	// 统计侧不得自带一套「时间戳尾/reason/碰撞后缀」解析。
	logstatsSrc := readServiceRepoFile(t, "../handlers/logstats.go")
	for _, banned := range []string{
		"func isRotationTimestampTail(",
		"func stripRotationCollisionSuffix(",
		"timberjackRotationReasonSuffix =",
	} {
		if strings.Contains(logstatsSrc, banned) {
			t.Fatalf("handlers/logstats.go 仍自带文件族解析 %q——必须复用 services 单源（两套解析曾让归属判定分叉）", banned)
		}
	}
	if !strings.Contains(logstatsSrc, "services.SplitTimberjackRotationCopy(") {
		t.Fatalf("handlers/logstats.go 未复用 services.SplitTimberjackRotationCopy")
	}
}

// 删除面单点：RemoveRuleLogFiles 只是 removeRuleLogRotations 的薄封装。
// 曾同时存在「.1..5 显式循环」与随后整目录扫描两条删除面——目录可读时前者
// 纯冗余 syscall，还把「错误条数=6」写成了对外契约。
func TestRemoveRuleLogFilesSingleRemovalSurface(t *testing.T) {
	src := readServiceRepoFile(t, "rulelog.go")
	body, ok := goFuncBody(src, "func RemoveRuleLogFiles(")
	if !ok {
		t.Fatal("rulelog.go 中找不到 RemoveRuleLogFiles 函数体")
	}
	for _, banned := range []string{"os.Remove(", "for "} {
		if strings.Contains(body, banned) {
			t.Fatalf("RemoveRuleLogFiles 内仍有独立删除面 %q——枚举+删除必须单点在 removeRuleLogRotations", banned)
		}
	}
	if !strings.Contains(body, "removeRuleLogRotations(") {
		t.Fatal("RemoveRuleLogFiles 未委托 removeRuleLogRotations")
	}
}

// goFuncBody 返回顶层函数（签名前缀 match）的函数体源码（含花括号）。
func goFuncBody(src, signature string) (string, bool) {
	start := strings.Index(src, signature)
	if start < 0 {
		return "", false
	}
	open := strings.IndexByte(src[start:], '{')
	if open < 0 {
		return "", false
	}
	open += start
	for i := open; i < len(src); i++ {
		if src[i] == '\n' && i+1 < len(src) && src[i+1] == '}' {
			return src[open : i+2], true
		}
	}
	return "", false
}

// 删除侧的归属反解必须与统计侧同口径：紧凑时间戳 + 尺寸段的副本名同属
// 该规则（此前落到 CutSuffix(".log") 分支成幻影规则 ID）。
func TestRuleLogComponentOf_acceptsEveryTimestampTailShape(t *testing.T) {
	cases := []struct {
		name      string
		component string
	}{
		{"lb_abc-2026-01-02T03-04-05.123-size.log", "lb_abc"},
		{"lb_abc-20261018-101500-64-size.log", "lb_abc"},
		{"lb_abc-20261018-101500-64-size.log.gz", "lb_abc"},
		{"lb_abc-123-20261018-101500-size.log", "lb_abc-123"},
		{"lb_abc-2026-01-02T03-04-05-time_2.log.zst", "lb_abc"},
	}
	for _, tc := range cases {
		got, ok := ruleLogComponentOf(tc.name)
		if !ok || got != tc.component {
			t.Fatalf("ruleLogComponentOf(%q)=(%q,%v), want (%q,true)", tc.name, got, ok, tc.component)
		}
	}
}

package handlers_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// audit136-A5：handlers 响应面「中文直写 Message」机械断言。
//
// 背景：i18n 统一标准（Message: apimsg.T/Tf(c, "k_x") + MessageKey）确立后，
// 历史迁移曾声明「响应面 0 残留」，实际漏网 49 处（扫描口径未覆盖
// fmt.Sprintf 插值形态）——en 用户在报错时收到中文文案。本守卫把
// 「直写=0」做成机械断言（扫描覆盖字面量与 fmt.Sprintf 两种形态），
// 漏网活不过 CI，杜绝第三轮盲区。
//
// 豁免：行内含 `audit136-A5 豁免` 注释（内部记录字段无请求上下文/i18n
// 不适用，或结构化弹框解析消费面）——豁免必须逐行注释理由。
func TestHandlersResponseMessagesAreI18nKeys(t *testing.T) {
	zhRe := regexp.MustCompile(`[\p{Han}]`)
	// Message: "中文…" 或 Message: fmt.Sprintf("中文…"
	direct := regexp.MustCompile(`Message:\s*(?:fmt\.Sprintf\()?\s*"[^"]*[\p{Han}][^"]*"`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("枚举 handlers 目录: %v", err)
	}
	offenders := []string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("读取 %s: %v", f, err)
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			if !zhRe.MatchString(line) {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue // 注释行（含「调用点」等中文说明不属响应面）
			}
			if strings.Contains(line, "MessageKey") {
				continue // 已迁移行（Message 与 MessageKey 同行）
			}
			// 豁免窗口:语句行及其前 3 行(注释块)任一含登记标记即豁免
			exempt := strings.Contains(line, "audit136-A5 豁免")
			for w := 1; w <= 3 && !exempt && i-w >= 0; w++ {
				if strings.Contains(lines[i-w], "audit136-A5 豁免") {
					exempt = true
				}
			}
			if exempt {
				continue
			}
			if strings.Contains(line, "serverErrMsg(") || strings.Contains(line, "caddyLifecycleApplyFailureMessage(") || strings.Contains(line, "importPartialSuccessMessage(") {
				continue // 500 内部错误面(139 处调用点):双语归 Tier 2 残余,已登记豁免
			}
			if direct.MatchString(line) {
				offenders = append(offenders, f+":"+strings.TrimSpace(line))
			} else if idx := strings.Index(line, "Message:"); idx >= 0 && zhRe.MatchString(line[idx:]) && !strings.Contains(line[idx:], "apimsg.") && !strings.Contains(line[idx:], "ErrMsg") && !strings.Contains(line[idx:], "serverErrMsg(") {
				offenders = append(offenders, f+":"+strings.TrimSpace(line))
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("handlers 响应面存在 %d 处中文直写 Message（未走 apimsg.T/Tf + MessageKey）——请迁移到 i18n 键或逐行登记豁免:\n%s",
			len(offenders), strings.Join(offenders, "\n"))
	}
}

func fmtLine(line string) string {
	l := strings.TrimSpace(line)
	if len(l) > 60 {
		l = l[:60]
	}
	return l
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

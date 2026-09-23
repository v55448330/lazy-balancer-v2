package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 渲染期单行护栏（v2.3.x）：coraza seclang 用 bufio.Scanner（64KiB 行上限）
// 且不检查 scanner.Err()——单行超限时该行与其后全部指令静默丢弃且 NewWAF
// 返回 nil（5000 条名单实证全失效无报错）。渲染层必须在 48KiB 处 fail-loud。
// 名单类长行已由 @ipListFast 文件投影消除；护栏兜底其余来源（如自定义规则
// 巨型 pattern）。
//
// oversizedIPList 生成散布整个 IPv4 空间的条目（混合步长防兄弟归并——
// 聚合是正确行为，测试须在聚合后的产物上断言）。
func oversizedIPList(n int) []string {
	entries := make([]string, 0, n)
	for i := range n {
		entries = append(entries, fmt.Sprintf("%d.%d.%d.%d", 1+(i%220), (i*53)%256, (i*97)%256, (i*13)%250+1))
	}
	return entries
}

func jsonRawIPList(entries []string) json.RawMessage {
	raw, err := json.Marshal(entries)
	if err != nil {
		panic(err)
	}
	return raw
}

// mustDirectives 是单行护栏签名（string, error）后测试侧的通用解包——
// 形状断言测试不接受护栏错误，出错即 panic 失败（而非把空串喂给后续断言
// 假绿）。Go 禁止混合多值实参（f(t, g()) 非法），故不带 t、以 panic 报告。
func mustDirectives(directives string, err error) string {
	if err != nil {
		panic(fmt.Sprintf("directives guard: %v", err))
	}
	return directives
}

func TestDirectiveLineLength_assertHelper(t *testing.T) {
	// Given：一行超 48KiB 的合成产物
	oversized := "SecRule REMOTE_ADDR \"@streq " + strings.Repeat("a", 49*1024) + "\" \"id:1,phase:1,deny\"\nSecMarker END\n"

	// When/Then
	if err := assertDirectiveLines(oversized); err == nil || !strings.Contains(err.Error(), "48KiB") {
		t.Fatalf("err=%v, want 含「48KiB」的护栏错误", err)
	}
	if err := assertDirectiveLines("SecRule REMOTE_ADDR \"@streq x\" \"id:1,phase:1,deny\"\n"); err != nil {
		t.Fatalf("短行不得触发护栏: %v", err)
	}
}

func TestDirectiveLineLength_engineGuardViaGiantCustomPattern(t *testing.T) {
	// Given：自定义规则携带 50KB pattern（渲染单行超 48KiB）
	policy := &models.SecurityPolicy{
		Mode:        "custom_only",
		CustomRules: json.RawMessage(`[{"id":1,"name":"r","enabled":true,"action":"block","conditions":[{"target":"uri","operator":"contains","pattern":"` + strings.Repeat("a", 50*1024) + `"}]}]`),
	}

	// When
	directives, err := BuildCorazaDirectives(policy, nil, "", false, 0)

	// Then
	if err == nil || !strings.Contains(err.Error(), "48KiB") {
		t.Fatalf("err=%v, want 含「48KiB」的护栏错误", err)
	}
	if directives != "" {
		t.Fatalf("护栏触发时不得返回可用产物（got %d bytes）", len(directives))
	}
}

func TestDirectiveLineLength_normalListsPass(t *testing.T) {
	// Given：大名单（回归形状——名单走文件投影，护栏不误伤）
	policy := &models.SecurityPolicy{
		Mode:        "blocking",
		IPBlacklist: jsonRawIPList(oversizedIPList(5000)),
	}

	// When
	directives, err := BuildCorazaDirectives(policy, nil, "", false, 0)

	// Then：产物含 @ipListFast 文件引用且名单文件内容完整
	if err != nil {
		t.Fatalf("5000 条名单不得触发护栏: %v", err)
	}
	if !strings.Contains(directives, "@ipListFast ") {
		t.Fatalf("大名单必须走文件投影:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "p0-bl"); strings.Count(got, "\n") < 4000 {
		t.Fatalf("名单文件条目数不足（聚合后仍应数千条）: %d", strings.Count(got, "\n"))
	}
}

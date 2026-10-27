package handlers

// 读路径取消传播的单一断言面：请求 context 必须一路传到查询。同端点里
// 「计数/明细/富化」已有取消钉测，而时区单行读与自动备份设置读曾用无 ctx 的
// QueryRow/Query——客户端断开后查询仍跑完，「断开即中止」变成需要逐点人工
// 核对的不变量。这里按函数体扫描（源码，而不是逐查询行为桩）把两个读函数里
// 的 ctx-less 访问钉成确定性失败。

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestAuditLogAndAutoBackupSettingsReadsConsumeRequestContext(t *testing.T) {
	ctxlessRead := regexp.MustCompile(`db\.DB\.(Query|QueryRow)\(`)
	tests := []struct {
		file string
		fn   string
	}{
		{file: "auditlog.go", fn: "func (h *Handlers) GetAuditLogs(c *gin.Context) {"},
		{file: "autobackup.go", fn: "func (h *Handlers) AutoBackupSettings(c *gin.Context) {"},
	}
	sawFunction := 0
	for _, test := range tests {
		source, err := os.ReadFile(test.file)
		if err != nil {
			t.Fatalf("read %s: %v", test.file, err)
		}
		body, ok := handlerFunctionBody(string(source), test.fn)
		if !ok {
			t.Fatalf("%s 中未找到 %q（函数改名/内联会让本守卫失效）", test.file, test.fn)
		}
		sawFunction++
		if hit := ctxlessRead.FindString(body); hit != "" {
			t.Fatalf("%s 的 %s 仍有无 ctx 的 %s（客户端断开后查询继续跑；须改用 QueryContext/QueryRowContext）",
				test.file, test.fn, hit)
		}
		if !strings.Contains(body, "QueryContext(") && !strings.Contains(body, "QueryRowContext(") {
			t.Fatalf("%s 的 %s 未出现任何 *Context 查询，扫描面可能失效", test.file, test.fn)
		}
	}
	if sawFunction != len(tests) {
		t.Fatalf("扫描函数数=%d, want %d", sawFunction, len(tests))
	}
}

// handlerFunctionBody 截取目标函数体（到下一个顶层 func 声明为止）。
func handlerFunctionBody(source, signature string) (string, bool) {
	start := strings.Index(source, signature)
	if start < 0 {
		return "", false
	}
	rest := source[start+len(signature):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		return rest[:end], true
	}
	return rest, true
}

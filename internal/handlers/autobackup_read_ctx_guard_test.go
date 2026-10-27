package handlers

// 读路径取消传播的单一断言面：请求 context 必须一路传到查询。同端点里
// 「计数/明细/富化」已有取消钉测，而时区单行读与自动备份设置读曾用无 ctx 的
// QueryRow/Query——客户端断开后查询仍跑完，「断开即中止」变成需要逐点人工
// 核对的不变量。这里按函数体扫描（源码，而不是逐查询行为桩）把自动备份
// 高危操作族（行面单行读 + 删除事务）里的 ctx-less 访问钉成确定性失败——
// 此前本守卫只覆盖 GetAuditLogs/AutoBackupSettings 两个函数，而
// autoBackupRowByID/DeleteAutoBackup 仍是 ctx-less，「同族全覆盖」的承诺
// 不成立。

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestAuditLogAndAutoBackupReadsConsumeRequestContext(t *testing.T) {
	ctxless := regexp.MustCompile(`db\.DB\.(Query|QueryRow|Exec|Begin)\(`)
	tests := []struct {
		file string
		fn   string
		// markers 该函数体内必须出现的 ctx 透传形态（任一命中即可）。
		markers []string
	}{
		{
			file: "auditlog.go", fn: "func (h *Handlers) GetAuditLogs(c *gin.Context) {",
			markers: []string{"QueryContext(", "QueryRowContext("},
		},
		{
			file: "autobackup.go", fn: "func (h *Handlers) AutoBackupSettings(c *gin.Context) {",
			markers: []string{"QueryContext(", "QueryRowContext("},
		},
		{
			file: "autobackup.go", fn: "func (h *Handlers) autoBackupRowByID(c *gin.Context, verb string) (autoBackupRowView, bool) {",
			markers: []string{"QueryRowContext("},
		},
		{
			file: "autobackup.go", fn: "func (h *Handlers) DeleteAutoBackup(c *gin.Context) {",
			markers: []string{"BeginTx(c.Request.Context()"},
		},
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
		if hit := ctxless.FindString(body); hit != "" {
			t.Fatalf("%s 的 %s 仍有无 ctx 的 %s（客户端断开后查询继续跑；须改 *Context 系列）",
				test.file, test.fn, hit)
		}
		marked := false
		for _, marker := range test.markers {
			if strings.Contains(body, marker) {
				marked = true
				break
			}
		}
		if !marked {
			t.Fatalf("%s 的 %s 未出现任何 ctx 透传形态（%v），扫描面可能失效",
				test.file, test.fn, test.markers)
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

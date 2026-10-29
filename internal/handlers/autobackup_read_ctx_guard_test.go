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
		{file: "caddy.go", fn: "func (h *Handlers) GetConfig(c *gin.Context) {", markers: []string{"QueryRowContext(c.Request.Context()"}},
		{file: "caddy.go", fn: "func (h *Handlers) GetCaddyStatus(c *gin.Context) {", markers: []string{"QueryRowContext(c.Request.Context()"}},
		{file: "config_changes.go", fn: "func loadConfigSnapshot(ctx context.Context) (configSnapshot, error) {", markers: []string{"QueryRowContext(ctx"}},
		{file: "autobackup.go", fn: "func loadAutoBackupSectionsSetting(ctx context.Context) ([]string, error) {", markers: []string{"QueryRowContext(ctx"}},
		{file: "autobackup.go", fn: "func loadAutoBackupKeepSetting(ctx context.Context) (keep int, known bool) {", markers: []string{"QueryRowContext(ctx"}},
		{file: "autobackup.go", fn: "func nextAutoBackupFilename(ctx context.Context, dir, trigger string, now time.Time) (string, error) {", markers: []string{"QueryRowContext(ctx"}},
		{file: "autobackup.go", fn: "func pruneAutoBackupStatus(ctx context.Context, dir, status string, keep int) int {", markers: []string{"QueryContext(ctx", "ExecContext(ctx"}},
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

func TestNextAutoBackupSlotReadConsumesRequestContext(t *testing.T) {
	handlerSource, err := os.ReadFile("autobackup.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(handlerSource), "services.NextAutoBackupSlot(c.Request.Context(), now)") {
		t.Fatal("设置页 next_run_at 必须把请求 ctx 传入跨包排程读取")
	}
	serviceSource, err := os.ReadFile("../services/autobackup.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(serviceSource)
	if !strings.Contains(text, "func NextAutoBackupSlot(ctx context.Context, now time.Time)") {
		t.Fatal("NextAutoBackupSlot 必须提供接收请求 ctx 的入口")
	}
	if !strings.Contains(text, "db.DB.QueryRowContext(ctx,") {
		t.Fatal("自动备份设置快照必须使用 QueryRowContext，取消后不得继续无 ctx 单行读")
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

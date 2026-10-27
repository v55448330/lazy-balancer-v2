package services

// ReadRuleLogTail 反向扫描必须受 maxBackwardScan
// 约束。maxBackwardScan 常量曾声明但扫描循环从不引用，
// 无换行的损坏/二进制日志会一路回扫到文件头（每轮 64KiB 前置拷贝，
// 100MB 无换行 ≈ 数十 GB 级复制）。本文件钉两形状：
//   - 无换行大文件：返回非空部分 tail、长度受扫描上限约束、offset 不变量保持
//   - 正常多行文件：tail 语义（最后 N 行 + 起始 offset）不变

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRuleLogFile(t *testing.T, ruleID string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	origDir := ruleLogDir
	ruleLogDir = dir
	t.Cleanup(func() { ruleLogDir = origDir })
	path := filepath.Join(dir, RuleLogFileComponent(ruleID)+".log")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write rule log %s: %v", path, err)
	}
	return path
}

func TestReadRuleLogTail_noNewlineFileBounded(t *testing.T) {
	// 8MB 无换行：旧实现全量回扫（buf 达 8MB），新实现须停在 maxBackwardScan。
	size := 8 << 20
	writeRuleLogFile(t, "probe", bytes.Repeat([]byte{0x41}, size))

	content, offset, err := ReadRuleLogTail("probe", 100)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}

	if content == "" {
		t.Fatal("tail of newline-free log returned empty content, want bounded partial tail")
	}
	if int64(len(content)) > maxBackwardScan+64*1024 {
		t.Fatalf("tail length %d exceeds maxBackwardScan bound %d", len(content), maxBackwardScan+64*1024)
	}
	if offset+int64(len(content)) != int64(size) {
		t.Fatalf("offset invariant broken: offset=%d len=%d size=%d, want offset+len==size", offset, len(content), size)
	}
}

func TestReadRuleLogTail_multilineTailSemanticsUnchanged(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 3000; i++ {
		b.WriteString(fmt.Sprintf("line-%d\n", i))
	}
	writeRuleLogFile(t, "multi", []byte(b.String()))

	content, offset, err := ReadRuleLogTail("multi", 100)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if len(lines) != 100 {
		t.Fatalf("got %d lines, want last maxLines=100", len(lines))
	}
	if lines[0] != "line-2901" || lines[99] != "line-3000" {
		t.Fatalf("tail window wrong: first=%s last=%s, want line-2901..line-3000", lines[0], lines[99])
	}
	if offset+int64(len(content)) != int64(b.Len()) {
		t.Fatalf("offset invariant broken: offset=%d len=%d total=%d", offset, len(content), b.Len())
	}
}

// removeTimberjackRotations 数字边界守卫——
// 兄弟规则（caddy_id 以本 stem 为前缀，lb_abc 与 lb_abc-extra）的轮转副本
// 此前被本规则的清扫按前缀+后缀整体误删（logstats.go 同族先例
// stem 后 '-<ts>' 段首字符必须为数字）。
func TestRemoveRuleLogFiles_siblingRuleRotationsUntouched(t *testing.T) {
	dir := t.TempDir()
	origDir := ruleLogDir
	ruleLogDir = dir
	t.Cleanup(func() { ruleLogDir = origDir })

	for _, name := range []string{
		"lb_abc.log", "lb_abc-extra.log", "lb_abc-1.log",
		"lb_abc-20260910T15-04-05.123-size.log",
		"lb_abc-extra-20260910T15-04-05.123-size.log",
		"lb_abc-1-20260910T15-04-05.123-size.log",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	RemoveRuleLogFiles("lb_abc")

	if _, err := os.Stat(filepath.Join(dir, "lb_abc.log")); !os.IsNotExist(err) {
		t.Fatal("lb_abc.log 应已删除")
	}
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-20260910T15-04-05.123-size.log")); !os.IsNotExist(err) {
		t.Fatal("lb_abc 自身轮转副本应已清扫")
	}
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-extra-20260910T15-04-05.123-size.log")); err != nil {
		t.Fatalf("兄弟规则轮转副本被误删: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-extra.log")); err != nil {
		t.Fatalf("兄弟规则活文件被误删: %v", err)
	}
	// 数字开头的兄弟规则（lb_abc-1）：旧守卫只判「stem 后首字符是数字」，
	// 会把 "-1-<ts>-size.log" 误认为本规则轮转副本。
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-1-20260910T15-04-05.123-size.log")); err != nil {
		t.Fatalf("数字兄弟规则轮转副本被误删: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-1.log")); err != nil {
		t.Fatalf("数字兄弟规则活文件被误删: %v", err)
	}
}

// ReadRuleLogTail 两段式倒扫改写的窗口等价钉——
// 多块窗口/块边界跨行/cap 边界/未终结尾行/少于 maxLines 五形状的 content 与
// offset 期望按旧实现语义手算钉死（改写前后同输入同输出，逐字节等价）。
func TestReadRuleLogTail_windowEquivalenceShapes(t *testing.T) {
	t.Run("多块窗口取尾5行", func(t *testing.T) {
		var b strings.Builder
		for i := 1; i <= 30000; i++ {
			fmt.Fprintf(&b, "L%07d\n", i)
		}
		writeRuleLogFile(t, "eq-multi", []byte(b.String()))
		content, offset, err := ReadRuleLogTail("eq-multi", 5)
		if err != nil {
			t.Fatalf("read tail: %v", err)
		}
		var want strings.Builder
		for i := 29996; i <= 30000; i++ {
			fmt.Fprintf(&want, "L%07d\n", i)
		}
		if content != want.String() {
			t.Fatalf("多块尾窗内容不等价: got %q, want %q", content, want.String())
		}
		if wantOffset := int64(b.Len() - want.Len()); offset != wantOffset {
			t.Fatalf("offset=%d, want %d", offset, wantOffset)
		}
	})
	t.Run("行跨64KB块边界", func(t *testing.T) {
		data := append(append(bytes.Repeat([]byte{'A'}, 65530), '\n'), append(bytes.Repeat([]byte{'B'}, 100), '\n')...)
		writeRuleLogFile(t, "eq-boundary", data)
		content, offset, err := ReadRuleLogTail("eq-boundary", 1)
		if err != nil {
			t.Fatalf("read tail: %v", err)
		}
		if content != string(bytes.Repeat([]byte{'B'}, 100))+"\n" {
			t.Fatalf("块边界行尾窗不等价: %q", content)
		}
		if offset != 65531 {
			t.Fatalf("offset=%d, want 65531（B 行起点）", offset)
		}
		content2, offset2, err2 := ReadRuleLogTail("eq-boundary", 2)
		if err2 != nil {
			t.Fatalf("read tail: %v", err2)
		}
		if content2 != string(data) || offset2 != 0 {
			t.Fatalf("maxLines=2 应整窗: offset=%d len=%d", offset2, len(content2))
		}
	})
	t.Run("cap边界部分尾窗", func(t *testing.T) {
		size := 5 << 20
		data := make([]byte, size)
		for i := range data {
			data[i] = 'C'
		}
		data[0] = '\n'
		writeRuleLogFile(t, "eq-cap", data)
		content, offset, err := ReadRuleLogTail("eq-cap", 10)
		if err != nil {
			t.Fatalf("read tail: %v", err)
		}
		if l := int64(len(content)); l != maxBackwardScan {
			t.Fatalf("cap 部分尾窗长度=%d, want %d", l, maxBackwardScan)
		}
		if offset != int64(size)-maxBackwardScan {
			t.Fatalf("offset=%d, want %d", offset, int64(size)-maxBackwardScan)
		}
		if offset+int64(len(content)) != int64(size) {
			t.Fatal("offset 不变量破坏: offset+len != size")
		}
	})
	t.Run("未终结尾行计为一行", func(t *testing.T) {
		writeRuleLogFile(t, "eq-partial", []byte("a\nb\nc"))
		content, offset, err := ReadRuleLogTail("eq-partial", 2)
		if err != nil {
			t.Fatalf("read tail: %v", err)
		}
		if content != "b\nc" || offset != 2 {
			t.Fatalf("未终结尾行不等价: content=%q offset=%d", content, offset)
		}
	})
	t.Run("行数少于maxLines整窗返回", func(t *testing.T) {
		writeRuleLogFile(t, "eq-short", []byte("x\ny\n"))
		content, offset, err := ReadRuleLogTail("eq-short", 100)
		if err != nil {
			t.Fatalf("read tail: %v", err)
		}
		if content != "x\ny\n" || offset != 0 {
			t.Fatalf("短文件不等价: content=%q offset=%d", content, offset)
		}
	})
}

// LBS/：ReadRuleLogFrom 遇整窗无换行（>8MB 单行/二进制/
// 损坏日志）时旧式把 data 置 nil 使 next==offset 原地不动——调用方按返回
// offset 轮询会永久卡死。钉两形状：无换行大文件每个「读满的窗口」必须前进
// 一个窗口（未满窗残段仍扣留，等待写侧补全换行）；有换行文件交付完整行且
// next 指向已消费末字节的既有语义不变。
func TestReadRuleLogFrom_newlineFreeAdvancesWindow(t *testing.T) {
	const maxRead = 8 << 20
	// 3 个满窗 + 小于一窗的残段，整文件无换行（单条记录跨越读取窗口）。
	size := int64(maxRead)*3 + 777
	writeRuleLogFile(t, "advance", bytes.Repeat([]byte{0x41}, int(size)))

	offset := int64(0)
	for window := 1; window <= 3; window++ {
		lines, next, err := ReadRuleLogFrom("advance", offset)
		if err != nil {
			t.Fatalf("read from: %v", err)
		}
		if len(lines) != 0 {
			t.Fatalf("window %d: 无行边界窗口不得交付行, got %d", window, len(lines))
		}
		if next != offset+maxRead {
			t.Fatalf("window %d: next=%d, want %d（整窗无换行须前进一个窗口）", window, next, offset+maxRead)
		}
		offset = next
	}
	// 残段（未满窗且无换行）：扣留——next 停在 offset，等待写侧补全换行。
	lines, next, err := ReadRuleLogFrom("advance", offset)
	if err != nil {
		t.Fatalf("read from: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("残段不得交付行, got %d", len(lines))
	}
	if next != offset {
		t.Fatalf("未满窗未终结残段应扣留: next=%d offset=%d", next, offset)
	}
	if offset+777 != size {
		t.Fatalf("窗口推进未覆盖到残段起点: offset=%d size=%d", offset, size)
	}
}

func TestReadRuleLogFrom_newlineFileDeliversCompleteLines(t *testing.T) {
	writeRuleLogFile(t, "complete", []byte("a\nbb\nccc\npartial"))
	lines, next, err := ReadRuleLogFrom("complete", 0)
	if err != nil {
		t.Fatalf("read from: %v", err)
	}
	if len(lines) != 3 || lines[0] != "a" || lines[1] != "bb" || lines[2] != "ccc" {
		t.Fatalf("lines=%v, want [a bb ccc]（未终结尾行须扣留）", lines)
	}
	wantNext := int64(len("a\nbb\nccc\n"))
	if next != wantNext {
		t.Fatalf("next=%d, want %d（仅交付完整行）", next, wantNext)
	}
}

// 命中回扫上限的 warn 首报留痕+节流——同一规则连续命中只报一次
// （用户反复打开日志弹框不再每读一行 warn），恢复（读到未截断 tail）补一条
// info。状态机复用 logStateTransition（与排程读失败/日志轮转同口径）。
func TestReadRuleLogTail_capWarnThrottledPerRule(t *testing.T) {
	size := 8 << 20
	writeRuleLogFile(t, "capwarn", bytes.Repeat([]byte{0x41}, size))
	isolateMetricsState(t)
	buf := captureLogf(t)

	if _, _, err := ReadRuleLogTail("capwarn", 100); err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if _, _, err := ReadRuleLogTail("capwarn", 100); err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if _, _, err := ReadRuleLogTail("capwarn", 100); err != nil {
		t.Fatalf("read tail: %v", err)
	}

	if warns := strings.Count(buf.String(), "backward scan cap"); warns != 1 {
		t.Fatalf("cap warn count=%d, want 1（首报后节流）\n%s", warns, buf.String())
	}

	// 恢复形状：换成正常多行小文件后读取 → 一条恢复 info。
	writeRuleLogFile(t, "capwarn", []byte("a\nb\nc\n"))
	if _, _, err := ReadRuleLogTail("capwarn", 100); err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if !strings.Contains(buf.String(), "resumed below the backward scan cap") {
		t.Fatalf("recovery info missing\n%s", buf.String())
	}
}

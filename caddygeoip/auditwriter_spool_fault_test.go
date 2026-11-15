package caddygeoip

// auditSpool 真实故障注入钉测：
//
//  1. 封存路径死目录形态：spool 目录被带外替换为同名文件时，封存路径生成必须快速返回
//     错误——有界重试 + 非 NotExist 分支上抛，不得持锁无限空转挂死 drain。
//  2. 写失败路径诚实核算——appendLines 返回值=确定落盘行数，滞留/
//     未尝试行走审计文件兜底（spool_errors 如实计数，零真丢）；已落盘字节随
//     reset 封存进补采可达面（根服务只消费 sealed）。
//
// 故障注入全部走真实文件系统/真实 fd（关 fd、rmdir+同名文件），禁桩。
// 修复模式镜像 caddyl4sec/shipper.go 同名函数（L4 已是修复后形态）。

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// closeSpoolActiveForTest 真实故障注入：关闭 spool 当前 active 的底层文件——
// 后续 Write/Flush 返回真实错误（file already closed），不 mock bufio。
// 同包测试直达内部句柄。
func closeSpoolActiveForTest(t *testing.T, s *auditSpool) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		t.Fatal("active file missing before fault injection")
	}
	if err := s.active.Close(); err != nil {
		t.Fatalf("close active: %v", err)
	}
}

// TestAuditSpoolRotateDeadDirReturnsPromptly：封存路径死目录形态——spool 目录被带外替换
// 为同名文件后，os.Stat 封存路径返回 ENOTDIR（非 NotExist）——rotateLocked
// 必须快速返回错误交调用方既有错误处理，不得无限空转挂死 drain goroutine。
func TestAuditSpoolRotateDeadDirReturnsPromptly(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "spool")
	s, err := openAuditSpool(dir, 64<<20, 4096)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	line := []byte(`{"k":"v"}`)
	if n, err := s.appendLines([][]byte{line}); err != nil || n != 1 {
		t.Fatalf("baseline appendLines = %d, %v; want 1, nil", n, err)
	}
	// 带外把 spool 目录替换为同名文件（清空内容 → rmdir → 建同名文件）。
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read spool dir: %v", err)
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			t.Fatalf("clear %s: %v", e.Name(), err)
		}
	}
	if err := os.Remove(dir); err != nil {
		t.Fatalf("remove spool dir: %v", err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o640); err != nil {
		t.Fatalf("recreate spool dir as file: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- s.rotateLocked() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("rotateLocked must fail when spool dir was replaced by a file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rotateLocked still running after 5s: sealedPathLocked spins forever on dead dir")
	}
}

// TestAuditSpoolAppendFlushFailureHonestFallback：批末 flush 失败形态。
// 基线 2 行已落盘 active → 关闭底层 fd（真实故障）→ spill 5 行：批末 flush
// 真实失败，滞留行随 reset 丢弃。钉测：(a) appendLines 返回 0（滞留行不计入，
// spooled 不虚增）；(b) 5 行全部走审计文件兜底 + spool_errors=5（零真丢）；
// (c) 已落盘基线随 reset 封存为 sealed（补采可达面），无 active 残留；
// (d) 恢复性——下一次写入在新 active 上成功。
func TestAuditSpoolAppendFlushFailureHonestFallback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := openAuditSpool(dir, 64<<20, 4096)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	defer func() { _ = s.close() }()

	baseline := []byte(`{"k":"baseline"}`)
	if n, err := s.appendLines([][]byte{baseline, baseline}); err != nil || n != 2 {
		t.Fatalf("baseline appendLines = %d, %v; want 2, nil", n, err)
	}
	closeSpoolActiveForTest(t, s)

	batch := [][]byte{
		[]byte(`{"i":1}`), []byte(`{"i":2}`), []byte(`{"i":3}`),
		[]byte(`{"i":4}`), []byte(`{"i":5}`),
	}
	var fallback [][]byte
	ship := &auditIPCShipper{
		spool:    s,
		fallback: func(l []byte) { fallback = append(fallback, append([]byte(nil), l...)) },
	}
	ship.spill(batch, errors.New("ipc down"))

	_, _, spooled, spoolErrs := ship.counters()
	if spooled != 0 {
		t.Fatalf("spooled = %d, want 0（本批无一确定落盘，滞留行随 reset 丢弃，不得虚增）", spooled)
	}
	if len(fallback) != len(batch) {
		t.Fatalf("fallback = %d lines, want %d（滞留+未尝试行必须走审计文件兜底，零真丢）", len(fallback), len(batch))
	}
	for i := range fallback {
		if string(fallback[i]) != string(batch[i]) {
			t.Fatalf("fallback[%d] = %s, want %s", i, fallback[i], batch[i])
		}
	}
	if spoolErrs != uint64(len(batch)) {
		t.Fatalf("spool_errors = %d, want %d", spoolErrs, len(batch))
	}

	// 已落盘基线不得滞留 active：reset 必须封存（根服务只消费 sealed）。
	var actives, sealeds int
	for _, name := range spoolFiles(t, dir) {
		switch {
		case strings.HasPrefix(name, auditSpoolActivePrefix):
			actives++
		case strings.HasPrefix(name, auditSpoolSealedPrefix):
			sealeds++
		default:
			t.Fatalf("spool 文件名不符合契约: %s", name)
		}
	}
	if actives != 0 || sealeds != 1 {
		t.Fatalf("spool after reset: active=%d sealed=%d, want 0/1（已落盘字节必须进补采可达面）", actives, sealeds)
	}
	if lines := spoolLines(t, dir); len(lines) != 2 || !strings.Contains(lines[0], "baseline") {
		t.Fatalf("sealed content = %v, want 2 baseline lines", lines)
	}

	// 恢复性：下一次写入在新 active 上成功。
	if n, err := s.appendLines([][]byte{[]byte(`{"r":1}`)}); err != nil || n != 1 {
		t.Fatalf("recovery appendLines = %d, %v; want 1, nil", n, err)
	}
}

// TestAuditSpoolAppendMidBatchFailureHonestFallback：批内直接写失败
// 形态（16KiB 行 ×32KiB 缓冲：第 2 行触发缓冲落盘真实失败）。第 1 行仅交缓冲、
// 从未落盘——不得计入返回值/spooled，必须随余下行走兜底（修复前 spooled 虚增
// 1、该行真丢）。
func TestAuditSpoolAppendMidBatchFailureHonestFallback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := openAuditSpool(dir, 64<<20, 4096)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	defer func() { _ = s.close() }()

	baseline := []byte(`{"k":"baseline"}`)
	if n, err := s.appendLines([][]byte{baseline}); err != nil || n != 1 {
		t.Fatalf("baseline appendLines = %d, %v; want 1, nil", n, err)
	}
	closeSpoolActiveForTest(t, s)

	big := []byte(strings.Repeat("x", 16<<10))
	batch := [][]byte{big, big, big}
	var fallback [][]byte
	ship := &auditIPCShipper{
		spool:    s,
		fallback: func(l []byte) { fallback = append(fallback, append([]byte(nil), l...)) },
	}
	ship.spill(batch, errors.New("ipc down"))

	_, _, spooled, spoolErrs := ship.counters()
	if spooled != 0 {
		t.Fatalf("spooled = %d, want 0（第 1 行仅在缓冲中、随 reset 丢弃，不得虚增）", spooled)
	}
	if len(fallback) != len(batch) || spoolErrs != uint64(len(batch)) {
		t.Fatalf("fallback = %d lines / spool_errors = %d, want %d/%d（零真丢）",
			len(fallback), spoolErrs, len(batch), len(batch))
	}

	// 已落盘基线封存、无 active 残留（空写失败不遗留文件占预算）。
	var actives, sealeds int
	for _, name := range spoolFiles(t, dir) {
		switch {
		case strings.HasPrefix(name, auditSpoolActivePrefix):
			actives++
		case strings.HasPrefix(name, auditSpoolSealedPrefix):
			sealeds++
		default:
			t.Fatalf("spool 文件名不符合契约: %s", name)
		}
	}
	if actives != 0 || sealeds != 1 {
		t.Fatalf("spool after reset: active=%d sealed=%d, want 0/1", actives, sealeds)
	}
	if lines := spoolLines(t, dir); len(lines) != 1 || !strings.Contains(lines[0], "baseline") {
		t.Fatalf("sealed content = %v, want 1 baseline line", lines)
	}

	if n, err := s.appendLines([][]byte{[]byte(`{"r":1}`)}); err != nil || n != 1 {
		t.Fatalf("recovery appendLines = %d, %v; want 1, nil", n, err)
	}
}

// TestAuditSpoolRotateFlushFailureHonestFallback：轮转 flush 失败形态
// （镜像 L4 TestL4SpoolRotateFlushFailureHonestLoss）。单行轮转阈值：基线写完
// 即轮转（落盘+封存+重开空 active）；关闭新 active 底层 fd 后，本批第 1 行交
// 缓冲即触发轮转 → flush 真实失败 → reset。钉测：(a) 返回 0（滞留行不计入）；
// (b) 空 active（从未落盘）随 reset 移除、不留空文件；(c) 基线 sealed 保持
// 可补采；(d) 恢复性。
func TestAuditSpoolRotateFlushFailureHonestFallback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := openAuditSpool(dir, 64<<20, 4096)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	defer func() { _ = s.close() }()

	s.mu.Lock()
	s.rotateBytes = 1 // 单行阈值：每行写完即触发轮转
	s.mu.Unlock()
	line := []byte(`{"k":"v"}`)

	if n, err := s.appendLines([][]byte{line}); err != nil || n != 1 {
		t.Fatalf("baseline appendLines = %d, %v; want 1, nil", n, err)
	}
	closeSpoolActiveForTest(t, s)

	if n, err := s.appendLines([][]byte{line, line}); err == nil || n != 0 {
		t.Fatalf("appendLines = %d, %v; want 0, real rotate-flush error", n, err)
	}

	var actives, sealeds int
	for _, name := range spoolFiles(t, dir) {
		switch {
		case strings.HasPrefix(name, auditSpoolActivePrefix):
			actives++
		case strings.HasPrefix(name, auditSpoolSealedPrefix):
			sealeds++
		default:
			t.Fatalf("spool 文件名不符合契约: %s", name)
		}
	}
	// 空 active（重开后从未落盘）随 reset 移除；基线 sealed 保持。
	if actives != 0 || sealeds != 1 {
		t.Fatalf("spool after rotate failure: active=%d sealed=%d, want 0/1", actives, sealeds)
	}
	if lines := spoolLines(t, dir); len(lines) != 1 || !strings.Contains(lines[0], `"v"`) {
		t.Fatalf("sealed content = %v, want 1 baseline line", lines)
	}

	if n, err := s.appendLines([][]byte{line}); err != nil || n != 1 {
		t.Fatalf("recovery appendLines = %d, %v; want 1, nil", n, err)
	}
}

// TestAuditSpoolResetStatFailureKeepsActiveForRetry：reset 的磁盘实况探测
// （os.Stat）真实失败（目录搜索权限被剥夺 → EACCES）时，已落盘内容不得
// 随 activePath 清零变成孤儿——写侧存活期间根服务只消费 sealed，孤儿
// active 永不补采（根服务孤儿清理只管「pid 已不存在」的遗留）。钉测：
// (a) Stat 失败后 active 文件保留且 activePath 不清（待封存清单）；
// (b) 权限恢复后下一批写入前重试封存——已落盘基线进 sealed（补采可达面）；
// (c) 新批落新 active，恢复性完整。
func TestAuditSpoolResetStatFailureKeepsActiveForRetry(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root 不受目录权限位约束，EACCES 注入不可达")
	}
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := openAuditSpool(dir, 64<<20, 4096)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	defer func() { _ = s.close() }()

	baseline := []byte(`{"k":"baseline"}`)
	if n, err := s.appendLines([][]byte{baseline, baseline}); err != nil || n != 2 {
		t.Fatalf("baseline appendLines = %d, %v; want 2, nil", n, err)
	}

	// 真实故障注入：剥夺目录搜索权限 → os.Stat(activePath) EACCES。
	if err := os.Chmod(dir, 0o600); err != nil {
		t.Fatalf("chmod fault: %v", err)
	}
	restore := func() {
		if err := os.Chmod(dir, 0o750); err != nil {
			t.Fatalf("chmod restore: %v", err)
		}
	}
	defer restore()
	closeSpoolActiveForTest(t, s)

	// 批末 flush 真实失败 → resetWriterLocked → Stat 失败分支。
	if n, err := s.appendLines([][]byte{[]byte(`{"i":1}`)}); err == nil || n != 0 {
		t.Fatalf("appendLines = %d, %v; want 0, real flush error", n, err)
	}
	restore()

	// (a) 已落盘 active 不得孤儿化：文件保留 + 路径入待封存清单
	//（activePath 让位给新 active，清单承载重试职责）。
	s.mu.Lock()
	pending := append([]string(nil), s.pendingSeal...)
	s.mu.Unlock()
	if len(pending) != 1 {
		t.Fatalf("待封存清单=%v, want 1 条（Stat 失败后已落盘基线必须保留待重试，不得清零孤儿化）", pending)
	}
	if _, err := os.Stat(pending[0]); err != nil {
		t.Fatalf("active 文件必须保留待封存: %v", err)
	}

	// (b) 恢复后下一批：待封存 active 先重试封存（基线进补采可达面）。
	if n, err := s.appendLines([][]byte{[]byte(`{"r":1}`)}); err != nil || n != 1 {
		t.Fatalf("recovery appendLines = %d, %v; want 1, nil", n, err)
	}
	var actives, sealeds int
	for _, name := range spoolFiles(t, dir) {
		switch {
		case strings.HasPrefix(name, auditSpoolActivePrefix):
			actives++
		case strings.HasPrefix(name, auditSpoolSealedPrefix):
			sealeds++
		default:
			t.Fatalf("spool 文件名不符合契约: %s", name)
		}
	}
	if actives != 1 || sealeds != 1 {
		t.Fatalf("spool after retry: active=%d sealed=%d, want 1/1（基线封存+新批 active）", actives, sealeds)
	}
	lines := spoolLines(t, dir)
	var baselineSeen int
	for _, l := range lines {
		if strings.Contains(l, "baseline") {
			baselineSeen++
		}
	}
	if baselineSeen != 2 {
		t.Fatalf("sealed/active 内容 baseline 行=%d, want 2（已落盘字节零丢失）: %v", baselineSeen, lines)
	}
}

// TestAuditSpoolCloseSealsStatFailureOrphan：Stat 失败遗留的待封存 active
// 在 close 收尾必须封存（进程退出后根服务孤儿清理虽可兜底，但写侧自己
// 收尾不得把已落盘内容留在 active——close 契约=本代全部行 sealed）。
func TestAuditSpoolCloseSealsStatFailureOrphan(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root 不受目录权限位约束，EACCES 注入不可达")
	}
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := openAuditSpool(dir, 64<<20, 4096)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	baseline := []byte(`{"k":"baseline"}`)
	if n, err := s.appendLines([][]byte{baseline}); err != nil || n != 1 {
		t.Fatalf("baseline appendLines = %d, %v; want 1, nil", n, err)
	}
	if err := os.Chmod(dir, 0o600); err != nil {
		t.Fatalf("chmod fault: %v", err)
	}
	closeSpoolActiveForTest(t, s)
	if _, err := s.appendLines([][]byte{[]byte(`{"i":1}`)}); err == nil {
		t.Fatal("flush 必须真实失败")
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatalf("chmod restore: %v", err)
	}
	if err := s.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	var actives, sealeds int
	for _, name := range spoolFiles(t, dir) {
		switch {
		case strings.HasPrefix(name, auditSpoolActivePrefix):
			actives++
		case strings.HasPrefix(name, auditSpoolSealedPrefix):
			sealeds++
		}
	}
	if actives != 0 || sealeds != 1 {
		t.Fatalf("spool after close: active=%d sealed=%d, want 0/1（待封存 active 必须收尾封存）", actives, sealeds)
	}
	if lines := spoolLines(t, dir); len(lines) != 1 || !strings.Contains(lines[0], "baseline") {
		t.Fatalf("sealed content = %v, want 1 baseline line", lines)
	}
}

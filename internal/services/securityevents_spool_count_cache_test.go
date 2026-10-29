package services

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecurityEventsSpoolStatus_reusesUnchangedFileCounts(t *testing.T) {
	t.Setenv(SecurityEventsSpoolDirEnv, "")
	oldDir := securityEventsSpoolDir
	securityEventsSpoolDir = t.TempDir()
	t.Cleanup(func() { securityEventsSpoolDir = oldDir })
	resetSecurityEventsSpoolEntryCountCacheForTest()
	path := filepath.Join(securityEventsSpoolDir, "sealed-test.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetSecurityEventsSpoolEntryCountCacheForTest()
	base := securityEventsSpoolEntryReadBytesForTest.Load()
	if got := securityEventsSpoolStatusFresh(); got.Entries != 1 {
		t.Fatalf("entries=%d, want 1", got.Entries)
	}
	afterFirst := securityEventsSpoolEntryReadBytesForTest.Load()
	if afterFirst <= base {
		t.Fatal("initial fixture did not exercise file reading")
	}
	if got := securityEventsSpoolStatusFresh(); got.Entries != 1 {
		t.Fatalf("unchanged entries=%d, want 1", got.Entries)
	}
	if got := securityEventsSpoolEntryReadBytesForTest.Load(); got != afterFirst {
		t.Fatalf("unchanged file was reread: bytes %d → %d", afterFirst, got)
	}
	const appended = "{}\n"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(appended); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	beforeAppend := securityEventsSpoolEntryReadBytesForTest.Load()
	if got := securityEventsSpoolStatusFresh(); got.Entries != 2 {
		t.Fatalf("appended entries=%d, want 2", got.Entries)
	}
	if got := securityEventsSpoolEntryReadBytesForTest.Load() - beforeAppend; got != int64(len(appended)) {
		t.Fatalf("append read %d bytes, want only %d new bytes", got, len(appended))
	}
}

func TestSecurityEventsSpoolCountCache_usesActualEOFAfterConcurrentAppend(t *testing.T) {
	// Given：一次状态扫描拿到旧 FileInfo 后，写侧又追加了一条完整记录。
	resetSecurityEventsSpoolEntryCountCacheForTest()
	path := filepath.Join(t.TempDir(), "active-eof.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// When：计数器实际读到更大的 EOF，随后按最新 FileInfo 再扫描一次。
	if got, err := securityEventsSpoolCountEntriesCached(path, stale); err != nil || got != 2 {
		t.Fatalf("first count=(%d,%v), want (2,nil)", got, err)
	}
	current, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := securityEventsSpoolCountEntriesCached(path, current)

	// Then：已读区间不得因旧 Info.Size 被再次计数。
	if err != nil || got != 2 {
		t.Fatalf("second count=(%d,%v), want (2,nil) without replaying appended bytes", got, err)
	}
}

func TestSecurityEventsSpoolCountCache_partialLineReadsOnlyAppendedTail(t *testing.T) {
	// Given：active 文件以半行结尾，首轮已把该半行计为一条待补采记录。
	resetSecurityEventsSpoolEntryCountCacheForTest()
	path := filepath.Join(t.TempDir(), "active-partial.jsonl")
	const prefix = `{"transaction":`
	if err := os.WriteFile(path, []byte(prefix), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := securityEventsSpoolStatusFreshForPath(t, path); got != 1 {
		t.Fatalf("initial entries=%d, want 1", got)
	}
	beforeAppend := securityEventsSpoolEntryReadBytesForTest.Load()
	const appended = "1}\n{}\n"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(appended); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// When/Then：总数正确，且只读取新增尾部，不因 partial 状态从 0 重读。
	if got := securityEventsSpoolStatusFreshForPath(t, path); got != 2 {
		t.Fatalf("appended entries=%d, want 2", got)
	}
	if got := securityEventsSpoolEntryReadBytesForTest.Load() - beforeAppend; got != int64(len(appended)) {
		t.Fatalf("partial append read %d bytes, want only %d new bytes", got, len(appended))
	}
}

func securityEventsSpoolStatusFreshForPath(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := securityEventsSpoolCountEntriesCached(path, info)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestSecurityEventsSpoolCountCache_truncatedRewriteStartsOver(t *testing.T) {
	// Given：已有完整行缓存，随后文件被截断重写为更短的新内容。
	resetSecurityEventsSpoolEntryCountCacheForTest()
	path := filepath.Join(t.TempDir(), "sealed-rewrite.jsonl")
	if err := os.WriteFile(path, []byte("{}\n{}\n{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := securityEventsSpoolStatusFreshForPath(t, path); got != 3 {
		t.Fatalf("initial entries=%d, want 3", got)
	}

	// When/Then：较短文件不得沿用旧 EOF/计数。
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := securityEventsSpoolStatusFreshForPath(t, path); got != 1 {
		t.Fatalf("rewritten entries=%d, want 1", got)
	}
}

func TestDrainSecurityEventsSpool_activeOnlyKeepsStatusCache(t *testing.T) {
	// Given：只有 active 文件，没有可删除的 sealed 文件；状态快照已在 TTL 内。
	t.Setenv(SecurityEventsSpoolDirEnv, "")
	oldDir := securityEventsSpoolDir
	securityEventsSpoolDir = t.TempDir()
	t.Cleanup(func() { securityEventsSpoolDir = oldDir })
	ResetSecurityEventsSpoolStateForTest()
	t.Cleanup(ResetSecurityEventsSpoolStateForTest)
	path := filepath.Join(securityEventsSpoolDir, "active-writer.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = SecurityEventsSpoolSnapshot()

	// When：补采风控每轮运行但没有改变任何 spool 文件。
	if got, err := drainSecurityEventsSpool(t.Context()); got != 0 || err != nil {
		t.Fatalf("drain=(%d,%v), want (0,nil)", got, err)
	}

	// Then：active-only 空补采不得打破 10s 状态缓存并放大健康轮询 I/O。
	securityEventsSpoolState.mu.Lock()
	haveCache := securityEventsSpoolState.haveCache
	securityEventsSpoolState.mu.Unlock()
	if !haveCache {
		t.Fatal("active-only drain invalidated the unchanged spool status cache")
	}
}

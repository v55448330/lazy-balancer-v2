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

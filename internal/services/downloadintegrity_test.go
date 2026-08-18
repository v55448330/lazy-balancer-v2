package services

// allow: SIZE_OK — TOFU download-integrity regression tests (R33 F4/F5).

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestRecordDownloadIntegrity_concurrentSourcesNoLostUpdate 验证两个更新调度器
// （CRS / ip2region）同小时并发下载时，共享记录文件的 load-modify-persist 不丢
// 更新、不撕裂文件（R33 F4）。
func TestRecordDownloadIntegrity_concurrentSourcesNoLostUpdate(t *testing.T) {
	dir := t.TempDir()
	oldPath := downloadIntegrityPath
	downloadIntegrityPath = filepath.Join(dir, ".download-integrity.json")
	t.Cleanup(func() { downloadIntegrityPath = oldPath })
	artifact := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	artifactA := artifact("a.bin", "content-A")
	artifactB := artifact("b.bin", "content-B")

	// When：两个来源并发记录（各自独立下载文件，共享同一记录文件）
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src, path := "https://src/A", artifactA
			if i%2 == 1 {
				src, path = "https://src/B", artifactB
			}
			if err := recordDownloadIntegrity(src, path, "测试资源"); err != nil {
				t.Errorf("record %s: %v", src, err)
			}
		}(i)
	}
	wg.Wait()

	// Then：两条基线都在、文件可解析（无丢失更新、无撕裂）
	records, err := loadDownloadIntegrityRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records=%d, want 2 (lost update detected)", len(records))
	}
	for _, src := range []string{"https://src/A", "https://src/B"} {
		if _, ok := records[src]; !ok {
			t.Fatalf("record for %s missing", src)
		}
	}
}

// TestRecordDownloadIntegrity_quarantinesCorruptRecordsFile 验证损坏的记录文件
// 被隔离（.corrupt-* 保留现场）、基线从头重建，而非静默禁用 TOFU 检查（R33 F5）。
func TestRecordDownloadIntegrity_quarantinesCorruptRecordsFile(t *testing.T) {
	dir := t.TempDir()
	oldPath := downloadIntegrityPath
	downloadIntegrityPath = filepath.Join(dir, ".download-integrity.json")
	t.Cleanup(func() { downloadIntegrityPath = oldPath })
	// Given：损坏（半写）的记录文件
	if err := os.WriteFile(downloadIntegrityPath, []byte(`{"broken": `), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dir, "x.bin")
	if err := os.WriteFile(artifact, []byte("fresh-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When：新下载记录
	if err := recordDownloadIntegrity("https://src/x", artifact, "测试资源"); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Then：损坏文件被隔离、新基线正常落盘
	matches, err := filepath.Glob(downloadIntegrityPath + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("corrupt quarantine files=%v err=%v, want exactly 1", matches, err)
	}
	records, err := loadDownloadIntegrityRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records=%d, want 1 rebuilt baseline", len(records))
	}
	if _, ok := records["https://src/x"]; !ok {
		t.Fatalf("rebuilt baseline missing the new source")
	}
	// And：再次记录同一来源不再触发隔离（记录文件健康）
	if err := recordDownloadIntegrity("https://src/x", artifact, "测试资源"); err != nil {
		t.Fatalf("second record: %v", err)
	}
	more, err := filepath.Glob(downloadIntegrityPath + ".corrupt-*")
	if err != nil || len(more) != 1 {
		t.Fatalf("quarantine files after healthy record=%v, want still 1", more)
	}
}

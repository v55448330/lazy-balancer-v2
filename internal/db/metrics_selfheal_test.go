package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 生产事故回归（页 1 清零 → Ping NOTADB → 崩循环）：metrics 库头部损坏
// 必须隔离重建而非启动失败。
func TestInitializeMetricsDB_quarantinesCorruptFileAndRecreates(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "lazy-balancer-metrics.db")
	corrupt := append([]byte(nil), make([]byte, 8192)...) // 前 8192 字节清零形态
	if err := os.WriteFile(dbPath, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath+"-wal", []byte("stale-wal"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := InitializeMetricsDB(dir); err != nil {
		t.Fatalf("InitializeMetricsDB on corrupted file: %v", err)
	}
	defer func() { _ = MetricsDB.Close(); MetricsDB = nil }()

	matches, err := filepath.Glob(dbPath + ".corrupt.*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("quarantined file matches=%v err=%v, want exactly 1", matches, err)
	}
	got, err := os.ReadFile(matches[0])
	if err != nil || len(got) != 8192 {
		t.Fatalf("quarantined bytes len=%d err=%v, want original 8192 preserved", len(got), err)
	}
	if walMatches, _ := filepath.Glob(dbPath + "-wal.corrupt.*"); len(walMatches) != 1 {
		t.Fatalf("stale -wal not quarantined alongside: %v", walMatches)
	}
	if _, err := MetricsDB.Exec("INSERT INTO metrics_history (rule_id, timestamp) VALUES ('r1', ?)", time.Now().UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatalf("recreated metrics db not writable: %v", err)
	}
}

// 头部魔数完好但页 1 内容损坏（Ping malformed 类）由段②隔离重建；
// 空文件（待建库）与真实有效库绝不隔离。
func TestInitializeMetricsDB_quarantinesOnPingCorruptionAndPreservesHealthy(t *testing.T) {
	t.Run("magic-intact-garbage-quarantined", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "lazy-balancer-metrics.db")
		if err := os.WriteFile(dbPath, append([]byte("SQLite format 3\x00"), make([]byte, 4080)...), 0600); err != nil {
			t.Fatal(err)
		}
		if err := InitializeMetricsDB(dir); err != nil {
			t.Fatalf("InitializeMetricsDB: %v", err)
		}
		defer func() { _ = MetricsDB.Close(); MetricsDB = nil }()
		if matches, _ := filepath.Glob(dbPath + ".corrupt.*"); len(matches) != 1 {
			t.Fatalf("corrupt-content file not quarantined: %v", matches)
		}
	})

	t.Run("empty-file-preserved", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "lazy-balancer-metrics.db")
		if err := os.WriteFile(dbPath, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := InitializeMetricsDB(dir); err != nil {
			t.Fatalf("InitializeMetricsDB: %v", err)
		}
		defer func() { _ = MetricsDB.Close(); MetricsDB = nil }()
		if matches, _ := filepath.Glob(dbPath + ".corrupt.*"); len(matches) != 0 {
			t.Fatalf("empty file quarantined: %v", matches)
		}
	})

	t.Run("valid-db-reinit-not-quarantined", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "lazy-balancer-metrics.db")
		if err := InitializeMetricsDB(dir); err != nil {
			t.Fatal(err)
		}
		if _, err := MetricsDB.Exec("INSERT INTO metrics_history (rule_id, timestamp) VALUES ('r1', '2026-08-29 00:00:00')"); err != nil {
			t.Fatal(err)
		}
		if err := MetricsDB.Close(); err != nil {
			t.Fatal(err)
		}
		MetricsDB = nil
		if err := InitializeMetricsDB(dir); err != nil {
			t.Fatalf("re-init valid db: %v", err)
		}
		defer func() { _ = MetricsDB.Close(); MetricsDB = nil }()
		var count int
		if err := MetricsDB.QueryRow("SELECT COUNT(*) FROM metrics_history WHERE rule_id='r1'").Scan(&count); err != nil || count != 1 {
			t.Fatalf("data lost on re-init: count=%d err=%v", count, err)
		}
		if matches, _ := filepath.Glob(dbPath + ".corrupt.*"); len(matches) != 0 {
			t.Fatalf("valid db quarantined: %v", matches)
		}
	})
}

func TestQuarantineCorruptSQLiteFile_missingFileIsNoop(t *testing.T) {
	quarantined, err := quarantineCorruptSQLiteFile(filepath.Join(t.TempDir(), "absent.db"))
	if err != nil || quarantined != "" {
		t.Fatalf("quarantined=%q err=%v, want noop on missing file", quarantined, err)
	}
}

// 头部有效但 16 字节后为垃圾的短文件同样隔离（n<16 非空分支）。
func TestQuarantineCorruptSQLiteFile_shortGarbageFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.db")
	if err := os.WriteFile(path, []byte("junk"), 0600); err != nil {
		t.Fatal(err)
	}
	quarantined, err := quarantineCorruptSQLiteFile(path)
	if err != nil || quarantined == "" || !strings.Contains(quarantined, ".corrupt.") {
		t.Fatalf("quarantined=%q err=%v, want quarantine path", quarantined, err)
	}
	if _, err := os.Stat(quarantined); err != nil {
		t.Fatalf("quarantined file missing: %v", err)
	}
}

package db

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlite "github.com/glebarez/go-sqlite"
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

// C4-F2 回归：Ping 损坏类错误必须经 errors.As 命中驱动的类型化错误码
// （SQLITE_NOTADB=26 / SQLITE_CORRUPT=11，可穿透 fmt.Errorf 包装链），
// 字符串 Contains 仅作兜底——驱动消息措辞变化不得让损坏库错过隔离重建。
// 真驱动口径：用真实驱动打开「魔数完好但内容损坏」的库取得_ping 错误。
func TestIsCorruptionError_typedCodeAndStringFallback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "typed.db")
	if err := os.WriteFile(dbPath, append([]byte("SQLite format 3\x00"), make([]byte, 4080)...), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := openAndPingMetricsDB(dbPath)
	if err == nil {
		t.Fatal("want ping error on corrupt-content file")
	}
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		t.Fatalf("driver ping error not typed *sqlite.Error: %T %v", err, err)
	}
	if !isCorruptionError(fmt.Errorf("open: %w", err)) {
		t.Fatalf("typed corruption code %d not detected through wrapping", sqliteErr.Code()&0xff)
	}
	if !isCorruptionError(errors.New("proxy: file is not a database (26)")) {
		t.Fatal("string fallback must still detect 'not a database'")
	}
	if !isCorruptionError(errors.New("database disk image is malformed")) {
		t.Fatal("string fallback must still detect 'malformed'")
	}
	if isCorruptionError(errors.New("database is locked (5)")) {
		t.Fatal("transient lock error must not be classified as corruption")
	}
}

// C4-F3 回归：同一秒内两次隔离不得静默覆盖此前的取证文件（rename 目标
// 重名时 Unix 语义为直接替换）。
func TestQuarantineCorruptSQLiteFile_sameSecondDoubleQuarantineKeepsBoth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.db")
	first := []byte("first-corrupt-bytes")
	second := []byte("second-corrupt-bytes")
	if err := os.WriteFile(path, first, 0600); err != nil {
		t.Fatal(err)
	}
	q1, err := quarantineCorruptSQLiteFile(path)
	if err != nil || q1 == "" {
		t.Fatalf("first quarantine: q=%q err=%v", q1, err)
	}
	if err := os.WriteFile(path, second, 0600); err != nil {
		t.Fatal(err)
	}
	q2, err := quarantineCorruptSQLiteFile(path)
	if err != nil || q2 == "" {
		t.Fatalf("second quarantine: q=%q err=%v", q2, err)
	}
	if q1 == q2 {
		t.Fatalf("same-second quarantines collide: %q", q1)
	}
	for name, want := range map[string][]byte{q1: first, q2: second} {
		got, readErr := os.ReadFile(name)
		if readErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("quarantined %s content lost: got=%q err=%v", name, got, readErr)
		}
	}
}

func TestQuarantineMetricsFileUnconditional_sameSecondDoubleQuarantineKeepsBoth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "y.db")
	if err := os.WriteFile(path, []byte("garbage-one"), 0600); err != nil {
		t.Fatal(err)
	}
	q1, err := quarantineMetricsFileUnconditionally(path)
	if err != nil || q1 == "" {
		t.Fatalf("first quarantine: q=%q err=%v", q1, err)
	}
	if err := os.WriteFile(path, []byte("garbage-two-longer"), 0600); err != nil {
		t.Fatal(err)
	}
	q2, err := quarantineMetricsFileUnconditionally(path)
	if err != nil || q2 == "" {
		t.Fatalf("second quarantine: q=%q err=%v", q2, err)
	}
	if q1 == q2 {
		t.Fatalf("same-second quarantines collide: %q", q1)
	}
	if _, err := os.Stat(q1); err != nil {
		t.Fatalf("earlier forensic file overwritten: %v", err)
	}
}

// C4-F3 回归：启动 GC 按基础名（主库/-wal/-shm）仅保留最新 3 份 .corrupt.*，
// 老文件清除；其他基础名的隔离文件不受波及。
func TestGCQuarantinedMetricsFiles_keepsNewestThreePerBase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "lazy-balancer-metrics.db")
	base := time.Now().Add(-10 * time.Hour)
	for i := 0; i < 5; i++ {
		p := fmt.Sprintf("%s.corrupt.%d", dbPath, base.Add(time.Duration(i)*time.Hour).Unix())
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		mod := base.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	for _, wal := range []string{dbPath + "-wal.corrupt.1", dbPath + "-wal.corrupt.2"} {
		if err := os.WriteFile(wal, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := filepath.Join(dir, "other.db.corrupt.1")
	if err := os.WriteFile(unrelated, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	gcQuarantinedMetricsFiles(dbPath)

	mainMatches, err := filepath.Glob(dbPath + ".corrupt.*")
	if err != nil || len(mainMatches) != 3 {
		t.Fatalf("main-base quarantine files=%v err=%v, want newest 3 kept", mainMatches, err)
	}
	for _, kept := range mainMatches {
		info, statErr := os.Stat(kept)
		if statErr != nil || info.ModTime().Before(base.Add(2*time.Hour)) {
			t.Fatalf("oldest files must be GC'd first: %s", kept)
		}
	}
	if walMatches, _ := filepath.Glob(dbPath + "-wal.corrupt.*"); len(walMatches) != 2 {
		t.Fatalf("wal-base files within keep limit must stay: %v", walMatches)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated base names must not be touched: %v", err)
	}
}

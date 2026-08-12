package services

import (
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestWriteCRSUpdateLog_rotatesAtConfiguredThreshold(t *testing.T) {
	// Given: a test DB with cert_job_log_size_mb = 1 and a cold size cache
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET cert_job_log_size_mb = 1 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	certJobLogSizeCachedAt.Store(0) // force cache refresh before first read
	t.Cleanup(func() { certJobLogSizeCachedAt.Store(0) })

	oldLogDir := crsUpdateLogDir
	crsUpdateLogDir = t.TempDir()
	t.Cleanup(func() { crsUpdateLogDir = oldLogDir })

	// And: an existing log file beyond 1MB but below the old fixed 10MB
	path := CRSUpdateLogPath()
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 2*1024*1024)), 0644); err != nil {
		t.Fatal(err)
	}

	// When: a log line is written
	writeCRSUpdateLog("INFO", "test", "rotation check")

	// Then: the oversized file is rotated to .1
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected rotated file %s.1 to exist: %v", path, err)
	}
}

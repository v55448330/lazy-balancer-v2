package services

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
)

var runtimeLogSizeMB atomic.Int64

func init() {
	runtimeLogSizeMB.Store(100)
	go func() {
		refresh := func() {
			if db.DB == nil {
				return
			}
			var mb int
			if err := db.DB.QueryRow("SELECT COALESCE(runtime_log_size_mb,100) FROM global_config WHERE id=1").Scan(&mb); err == nil && mb > 0 {
				runtimeLogSizeMB.Store(int64(mb))
			}
		}
		refresh()
		for range time.Tick(30 * time.Second) {
			refresh()
		}
	}()
}

// RotatingFileWriter writes to a log file and rotates it once it exceeds the
// size limit. Rotated files are suffixed with a timestamp and are subject to
// retention cleanup (see StartRuntimeLogCleanup).
type RotatingFileWriter struct {
	path string
	mu   sync.Mutex
	file *os.File
	size int64
}

func NewRotatingFileWriter(path string) (*RotatingFileWriter, error) {
	w := &RotatingFileWriter{path: path}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RotatingFileWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	var size int64
	if info, err := f.Stat(); err == nil {
		size = info.Size()
	}
	w.file = f
	w.size = size
	return nil
}

func (w *RotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+int64(len(p)) > runtimeLogSizeMB.Load()*1024*1024 {
		if err := w.rotateLocked(); err != nil {
			log.Printf("日志轮转失败: %v", err)
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingFileWriter) rotateLocked() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	rotated := fmt.Sprintf("%s.%s", w.path, time.Now().Format("20060102-150405"))
	if err := os.Rename(w.path, rotated); err != nil {
		// Rename failed (e.g. cross-device); keep appending to the old file.
		return w.open()
	}
	return w.open()
}

func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

// StartRuntimeLogCleanup removes rotated runtime log files older than the
// configured log retention (shared with the audit log retention setting). It
// runs once immediately and then daily.
func StartRuntimeLogCleanup(logFile string) {
	cleanup := func() {
		months := 3
		if err := db.DB.QueryRow("SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1").Scan(&months); err != nil || months < 1 {
			months = 3
		}
		cutoff := time.Now().AddDate(0, -months, 0)

		dir := filepath.Dir(logFile)
		base := filepath.Base(logFile) + "."
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasPrefix(e.Name(), base) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
					log.Printf("清理过期运行日志失败 %s: %v", e.Name(), err)
				} else {
					log.Printf("已清理过期运行日志 %s", e.Name())
				}
			}
		}
	}

	cleanup()
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanup()
		}
	}()
}

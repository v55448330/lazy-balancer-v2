package services

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// CRSUpdateLogPath returns the update log file path for the log reader endpoint.
func CRSUpdateLogPath() string {
	return filepath.Join(crsUpdateLogDir, "crs-update.log")
}

func writeCRSUpdateLog(level, stage, message string) {
	path := CRSUpdateLogPath()
	if info, err := os.Stat(path); err == nil && info.Size() >= getCertJobLogSizeBytes() {
		os.Remove(fmt.Sprintf("%s.%d", path, maxRotatedFiles))
		for i := maxRotatedFiles - 1; i >= 1; i-- {
			os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
		}
		os.Rename(path, path+".1")
	}
	if err := os.MkdirAll(crsUpdateLogDir, 0755); err != nil {
		log.Printf("crs update log: failed to create dir: %v", err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("crs update log: failed to open %s: %v", path, err)
		return
	}
	defer f.Close()
	timestamp := time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05")
	fmt.Fprintf(f, "%s [%s] %s - %s\n", timestamp, level, stage, message)
}

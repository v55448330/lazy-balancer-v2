package services

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var ip2RegionUpdateLogDir = "/app/logs"

// IP2RegionUpdateLogPath returns the update log file path for the log reader endpoint.
func IP2RegionUpdateLogPath() string {
	return filepath.Join(ip2RegionUpdateLogDir, "ip2region-update.log")
}

func writeIP2RegionUpdateLog(level, stage, message string) {
	path := IP2RegionUpdateLogPath()
	if info, err := os.Stat(path); err == nil && info.Size() >= getCertJobLogSizeBytes() {
		// SLB12-P3-10 同族:复用 rotateCertJobLogFiles(C-11 错误口径)。
		if rerr := rotateCertJobLogFiles(path); rerr != nil {
			Logf("info", "ip2region update log: rotation failed (oldest generation may be lost): %v", rerr)
		}
	}
	if err := os.MkdirAll(ip2RegionUpdateLogDir, 0755); err != nil {
		Logf("info", "ip2region update log: failed to create dir: %v", err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		Logf("info", "ip2region update log: failed to open %s: %v", path, err)
		return
	}
	defer f.Close()
	timestamp := time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05")
	fmt.Fprintf(f, "%s [%s] %s - %s\n", timestamp, level, stage, message)
}

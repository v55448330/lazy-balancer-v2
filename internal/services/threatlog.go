package services

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// 威胁情报库更新日志（v2.3.2 名单化重构）：与 CRS 更新日志同形态
// （/app/logs/threat-update.log，轮转复用 cert-job 日志轮转器）——
// 规则集「更新日志弹框」的数据源。

// SetUpdateLogDirForTest 覆盖更新日志目录（CRS/威胁库共用 crsUpdateLogDir）。
// 测试专用——生产由 /app/logs 常量承担。
func SetUpdateLogDirForTest(dir string) (restore func()) {
	old := crsUpdateLogDir
	crsUpdateLogDir = dir
	return func() { crsUpdateLogDir = old }
}

// ThreatUpdateLogPath 威胁库更新日志文件路径（日志读取端点消费）。
func ThreatUpdateLogPath() string {
	return filepath.Join(crsUpdateLogDir, "threat-update.log")
}

// AppendThreatUpdateLog 写一条威胁库更新日志（更新任务与同步/导入路径共用）。
func AppendThreatUpdateLog(level, stage, message string) {
	path := ThreatUpdateLogPath()
	if info, err := os.Stat(path); err == nil && info.Size() >= getCertJobLogSizeBytes() {
		if rerr := rotateCertJobLogFiles(path); rerr != nil {
			Logf("error", "threat update log: rotation failed (oldest generation may be lost): %v", rerr)
		}
	}
	if err := os.MkdirAll(crsUpdateLogDir, 0755); err != nil {
		Logf("error", "threat update log: failed to create dir: %v", err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		Logf("error", "threat update log: failed to open %s: %v", path, err)
		return
	}
	defer f.Close()
	timestamp := time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05")
	fmt.Fprintf(f, "%s [%s] %s - %s\n", timestamp, level, stage, message)
}

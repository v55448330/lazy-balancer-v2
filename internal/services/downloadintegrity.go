package services

// 下载完整性（TOFU）：ghfast.top 代理下载无上游官方校验和可钉，首次成功下载
// 后把 size+SHA256 记录到数据卷（.download-integrity.json）；后续同一来源
// （URL 含版本 tag）下载若 size 或摘要变化，说明代理返回内容与上次不一致，
// 以 error 日志 + 审计记录告警（不阻断安装，格式校验仍由调用方执行）。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// downloadIntegrityPath 是完整性记录文件路径；定义为变量以便测试注入。
var downloadIntegrityPath = "/app/data/.download-integrity.json"

// downloadIntegrityMu 串行化记录文件的 load-modify-persist：CRS 与 ip2region
// 两个更新调度器可能同时到期下载（同小时并发），共享同一记录文件时丢失更新
// 或撕裂 tmp 文件（R33 F4）。所有读改写路径都必须在持锁下进行。
var downloadIntegrityMu sync.Mutex

type downloadIntegrityRecord struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// recordDownloadIntegrity 校验并记录一次成功下载的完整性快照：首次下载写入
// 基线；同一来源再次下载且 size/digest 与基线不符时 Logf("error") 告警并
// RecordAuditLog（可见但不阻断）。必须在下载文件的格式验证成功之后调用——
// 验证前的坏工件基线会让下次同源好下载误报（R33 F6）。
func recordDownloadIntegrity(source, destPath, resource string) error {
	info, err := os.Stat(destPath)
	if err != nil {
		return err
	}
	digest, err := sha256File(destPath)
	if err != nil {
		return err
	}
	downloadIntegrityMu.Lock()
	defer downloadIntegrityMu.Unlock()
	records, err := loadDownloadIntegrityRecords()
	if err != nil {
		return err
	}
	prev, existed := records[source]
	records[source] = downloadIntegrityRecord{Size: info.Size(), SHA256: digest}
	if err := persistDownloadIntegrityRecords(records); err != nil {
		return err
	}
	if existed && (prev.Size != info.Size() || prev.SHA256 != digest) {
		Logf("error", "download integrity mismatch for %s: size %d→%d, sha256 %s→%s（代理返回内容与上次不一致，已按当前内容安装）", source, prev.Size, info.Size(), prev.SHA256, digest)
		RecordAuditLog("system", "下载完整性告警", resource,
			FormatAuditDetail(fmt.Sprintf("来源 %s 的下载内容与上次记录不一致（size %d→%d，sha256 %s→%s）", source, prev.Size, info.Size(), prev.SHA256, digest)), "")
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func loadDownloadIntegrityRecords() (map[string]downloadIntegrityRecord, error) {
	data, err := os.ReadFile(downloadIntegrityPath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]downloadIntegrityRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var records map[string]downloadIntegrityRecord
	if err := json.Unmarshal(data, &records); err != nil {
		// 损坏记录文件会静默禁用 TOFU 完整性检查且不自愈（R33 F5）：隔离文件
		// （rename 为 .corrupt-<ts>）保留取证现场，error 日志 + 审计记录告警，
		// 并从头重建基线。调用方须持有 downloadIntegrityMu。
		quarantined := downloadIntegrityPath + ".corrupt-" + time.Now().UTC().Format("20060102-150405")
		_ = os.Rename(downloadIntegrityPath, quarantined)
		Logf("error", "download integrity: records file %s is corrupt, quarantined to %s and baselines rebuilt", downloadIntegrityPath, quarantined)
		RecordAuditLog("system", "下载完整性", "完整性记录文件损坏",
			FormatAuditDetail(fmt.Sprintf("记录文件 %s 解析失败，已隔离为 %s 并重建基线", downloadIntegrityPath, quarantined)), "")
		return map[string]downloadIntegrityRecord{}, nil
	}
	if records == nil {
		records = map[string]downloadIntegrityRecord{}
	}
	return records, nil
}

func persistDownloadIntegrityRecords(records map[string]downloadIntegrityRecord) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(downloadIntegrityPath), 0o755); err != nil {
		return err
	}
	tmp := downloadIntegrityPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, downloadIntegrityPath)
}

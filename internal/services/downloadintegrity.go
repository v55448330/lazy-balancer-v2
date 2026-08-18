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
)

// downloadIntegrityPath 是完整性记录文件路径；定义为变量以便测试注入。
var downloadIntegrityPath = "/app/data/.download-integrity.json"

type downloadIntegrityRecord struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// recordDownloadIntegrity 校验并记录一次成功下载的完整性快照：首次下载写入
// 基线；同一来源再次下载且 size/digest 与基线不符时 Logf("error") 告警并
// RecordAuditLog（可见但不阻断）。
func recordDownloadIntegrity(source, destPath, resource string) error {
	info, err := os.Stat(destPath)
	if err != nil {
		return err
	}
	digest, err := sha256File(destPath)
	if err != nil {
		return err
	}
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
		return nil, err
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

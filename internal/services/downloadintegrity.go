package services

// 下载校验（TOFU）：经 GitHub 加速代理（github_proxy_url 白名单，历史硬编码
// ghfast.top 已废弃）下载无上游官方校验和可钉，首次成功下载后把 size+SHA256
// 记录到数据卷（.download-integrity.json）；后续同一来源（URL 含版本 tag）下载
// 若 size 或摘要变化，说明代理返回内容与上次不一致，以 error 日志 + 审计记录
// 告警并返回错误阻断安装、保留旧基线（格式校验仍由调用方执行）。内容变化必须
// 经人工清理基线（删除记录文件中该来源条目）后重试，不自动重定基线。

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
// 或撕裂 tmp 文件。所有读改写路径都必须在持锁下进行。
// 锁内只做文件 load-modify-persist 与状态判定——日志/审计落库（审计库
// I/O）一律解锁后执行，照抄看门狗 pendingIO 模式：审计库被外部写锁
// 占住时（busy_timeout 30s），持锁落审计会让两族更新调度器互相阻塞。
var downloadIntegrityMu sync.Mutex

// downloadIntegrityAudit 是「锁内判定、锁外落库」的审计记录载荷。
type downloadIntegrityAudit struct {
	action   string
	resource string
	detail   AuditDetail
}

// recordDownloadIntegrityAudits 落库锁内收集的审计记录（调用方必须已解锁）。
func recordDownloadIntegrityAudits(audits []downloadIntegrityAudit) {
	for _, audit := range audits {
		RecordAuditLog("system", audit.action, audit.resource, audit.detail, "")
	}
}

type downloadIntegrityRecord struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// errDownloadIntegrityMismatch 标记「下载内容与 TOFU 基线不一致」的阻断性
// 失败，供调用方与 I/O 类失败区分：mismatch 必须中止安装，
// I/O 失败仅记日志不阻断。
var errDownloadIntegrityMismatch = errors.New("下载完整性校验失败：内容与基线不一致")

// verifyDownloadIntegrity 在下载完成后立即比对既有 TOFU 基线（无基线时跳过
// 比对，仅返回本次快照）：内容与基线不一致时 Logf("error") + 审计并返回
// errDownloadIntegrityMismatch 包装错误。不做格式判定——格式门由调用方在解包/
// 校验后再过，但基线比对必须先于任何解包，否则被劫持/损坏的工件会先展开到
// 数据卷才被否决（磁盘/CPU 放大，且发现点远离真实原因）。
// 必须在下载文件的格式验证成功之后调用（验证前的坏工件写入基线会让下次同源
// 好下载误报）——调用方只在验证通过后调用 recordDownloadIntegrityRecord。
func verifyDownloadIntegrity(source, destPath, resource string) (downloadIntegrityRecord, error) {
	info, err := os.Stat(destPath)
	if err != nil {
		return downloadIntegrityRecord{}, err
	}
	digest, err := sha256File(destPath)
	if err != nil {
		return downloadIntegrityRecord{}, err
	}
	rec := downloadIntegrityRecord{Size: info.Size(), SHA256: digest}
	downloadIntegrityMu.Lock()
	records, audits, logs, err := loadDownloadIntegrityRecords()
	if err != nil {
		downloadIntegrityMu.Unlock()
		logDownloadIntegrityMessages(logs)
		recordDownloadIntegrityAudits(audits)
		return downloadIntegrityRecord{}, err
	}
	prev, existed := records[source]
	// mismatch 阻断安装并保留旧基线——ghfast.top 类镜像
	// 代理投毒时「仅告警+自动重定基线」无拦截力；内容变化必须经人工清理基线
	//（删除记录文件中该来源条目）后重试。
	if existed && (prev.Size != info.Size() || prev.SHA256 != digest) {
		// 锁内只构造文案与错误，日志/审计在解锁后落库。
		mismatchErr := fmt.Errorf("来源 %s 下载内容与上次完整性记录不一致（size %d→%d，sha256 %s→%s），已阻断安装；如确认上游更新合法，删除 %s 中该来源条目后重试: %w",
			source, prev.Size, info.Size(), prev.SHA256, digest, downloadIntegrityPath, errDownloadIntegrityMismatch)
		audits = append(audits, downloadIntegrityAudit{
			action:   "校验阻断",
			resource: resource,
			detail:   FormatAuditDetail(AuditTextPart("audit.downloadIntegrityMismatch", source, prev.Size, info.Size(), prev.SHA256, digest)),
		})
		downloadIntegrityMu.Unlock()
		Logf("error", "download integrity mismatch for %s: size %d→%d, sha256 %s→%s（与上次记录不一致，已阻断安装并保留旧基线；如确认上游更新合法，删除 %s 中该来源条目后重试）", source, prev.Size, info.Size(), prev.SHA256, digest, downloadIntegrityPath)
		recordDownloadIntegrityAudits(audits)
		return downloadIntegrityRecord{}, mismatchErr
	}
	downloadIntegrityMu.Unlock()
	logDownloadIntegrityMessages(logs)
	recordDownloadIntegrityAudits(audits)
	return rec, nil
}

// recordDownloadIntegrityRecord 记录一次已通过校验的下载快照（首次写入基线，
// 已存在则刷新为同值）。接收 verifyDownloadIntegrity 的返回值，避免对大工件
// 二次 stat+全文件哈希。
func recordDownloadIntegrityRecord(source string, rec downloadIntegrityRecord) error {
	downloadIntegrityMu.Lock()
	records, audits, logs, err := loadDownloadIntegrityRecords()
	if err != nil {
		downloadIntegrityMu.Unlock()
		logDownloadIntegrityMessages(logs)
		recordDownloadIntegrityAudits(audits)
		return err
	}
	records[source] = rec
	err = persistDownloadIntegrityRecords(records)
	downloadIntegrityMu.Unlock()
	logDownloadIntegrityMessages(logs)
	recordDownloadIntegrityAudits(audits)
	return err
}

// recordDownloadIntegrity 校验并记录一次成功下载的完整性快照：首次下载写入
// 基线；同一来源再次下载且 size/digest 与基线不符时返回
// errDownloadIntegrityMismatch 包装错误（阻断安装、保留旧基线）。语义等价于
// verifyDownloadIntegrity + recordDownloadIntegrityRecord 两步，供无需在
// 两步之间插解包/校验的调用方使用。
func recordDownloadIntegrity(source, destPath, resource string) error {
	rec, err := verifyDownloadIntegrity(source, destPath, resource)
	if err != nil {
		return err
	}
	return recordDownloadIntegrityRecord(source, rec)
}

// logDownloadIntegrityMessages 输出锁内构造的日志文案（调用方必须已解锁）。
func logDownloadIntegrityMessages(logs []string) {
	for _, msg := range logs {
		Logf("error", "%s", msg)
	}
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

// loadDownloadIntegrityRecords 读取记录文件（调用方须持有 downloadIntegrityMu）。
// 损坏文件的隔离审计与日志文案均以返回值交给调用方在解锁后落库/输出——
// 锁内不得做日志 writer/审计库 I/O（本文件头 discipline）。
func loadDownloadIntegrityRecords() (map[string]downloadIntegrityRecord, []downloadIntegrityAudit, []string, error) {
	data, err := os.ReadFile(downloadIntegrityPath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]downloadIntegrityRecord{}, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, err
	}
	var records map[string]downloadIntegrityRecord
	if err := json.Unmarshal(data, &records); err != nil {
		// 损坏记录文件会静默禁用 TOFU 完整性检查且不自愈：隔离文件
		// （rename 为 .corrupt-<ts>）保留取证现场，error 日志 + 审计记录告警，
		// 并从头重建基线。
		quarantined := downloadIntegrityPath + ".corrupt-" + time.Now().UTC().Format("20060102-150405")
		if err := os.Rename(downloadIntegrityPath, quarantined); err != nil {
			// 隔离失败时如实记录：文件仍在原位，后续 persist（tmp+rename）会覆盖
			// 重建，但取证副本缺失。
			return map[string]downloadIntegrityRecord{}, []downloadIntegrityAudit{{
				action:   "下载校验",
				resource: "完整性记录",
				detail:   FormatAuditDetail(AuditTextPart("audit.recordFileQuarantineFailed", downloadIntegrityPath, quarantined, err)),
			}}, []string{fmt.Sprintf("download integrity: records file %s is corrupt, quarantine rename to %s failed: %v（原文件保留，直接重建基线）", downloadIntegrityPath, quarantined, err)}, nil
		}
		return map[string]downloadIntegrityRecord{}, []downloadIntegrityAudit{{
			action:   "下载校验",
			resource: "完整性记录",
			detail:   FormatAuditDetail(AuditTextPart("audit.recordFileQuarantined", downloadIntegrityPath, quarantined)),
		}}, []string{fmt.Sprintf("download integrity: records file %s is corrupt, quarantined to %s and baselines rebuilt", downloadIntegrityPath, quarantined)}, nil
	}
	if records == nil {
		records = map[string]downloadIntegrityRecord{}
	}
	return records, nil, nil, nil
}

func persistDownloadIntegrityRecords(records map[string]downloadIntegrityRecord) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(downloadIntegrityPath), 0o755); err != nil {
		return err
	}
	// tmp+rename 缺 fsync 可留下 0 字节记录（基线丢失/误重建）。
	return writeFileAtomicSynced(downloadIntegrityPath, data, 0o644)
}

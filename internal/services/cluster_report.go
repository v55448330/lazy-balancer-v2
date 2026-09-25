package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/models"
)

var clusterProcessStartedAt = time.Now()

func (s *SyncService) Report(ctx context.Context) error {
	var masterURL, token, storedSyncError string
	var appliedVersion int
	var lastSync sql.NullTime
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(master_url,''), COALESCE(cluster_token,''), COALESCE(applied_version,0), last_sync, COALESCE(last_sync_error,'') FROM global_config WHERE id=1`).Scan(&masterURL, &token, &appliedVersion, &lastSync, &storedSyncError); err != nil {
		return fmt.Errorf("读取上报状态: %w", err)
	}
	lastSyncError, syncErrorCode := decodeSyncError(storedSyncError)
	lastSyncAt := ""
	if lastSync.Valid {
		lastSyncAt = lastSync.Time.UTC().Format(time.RFC3339)
	}
	var rulesCount, expiringCount int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM lb_rules").Scan(&rulesCount); err != nil {
		return fmt.Errorf("统计规则: %w", err)
	}
	// 到期口径跟随 cert_expiry_days 配置（与规则页「即将过期」状态一致）；
	// JSON 字段名 certs_expiring_30d 为历史名，保留以兼容旧版主节点解析。
	expiryDays := 30
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(cert_expiry_days,30) FROM global_config WHERE id=1").Scan(&expiryDays); err != nil || expiryDays <= 0 {
		// 读失败/非法值回退 30 时留痕（第 57 轮 R-12 家族扫描唯一漏点，
		// 同族 certissuer/certificates/certinfo/certjobs 均已带留痕）。
		Logf("warn", "集群报告: 读取证书到期口径失败，回退 30 天")
		expiryDays = 30
	}
	// expiryDays 经 Scan 已是纯整数（非法/非数字值回退 30），strconv.Itoa 只产生
	// 数字修饰符；SQLite datetime 修饰符无法参数化，格式化必须保证纯数字。
	expiryModifier := strconv.Itoa(expiryDays)
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_jobs WHERE status='issued' AND expires_at IS NOT NULL AND datetime(expires_at)<=datetime('now','+`+expiryModifier+` days')`).Scan(&expiringCount); err != nil {
		return fmt.Errorf("统计即将到期证书: %w", err)
	}
	_, caddyErr := s.caddy.GetConfig()
	serviceStatus := "ok"
	if caddyErr != nil || lastSyncError != "" {
		serviceStatus = "degraded"
	}
	report := models.ClusterReport{
		AppliedVersion: appliedVersion,
		ServiceStatus:  serviceStatus,
		LastSyncAt:     lastSyncAt,
		LastSyncError:  lastSyncError,
		SyncErrorCode:  syncErrorCode,
		// 分区哈希取 cluster_applied_sections 的已应用记录（apply 路径
		// recordAppliedSectionHashes 维护，含漂移重放后的本地重建口径）：
		// 代表本地当前已落库内容，无需为上报重建全量快照。从未同步过的节点
		// 表为空 → nil → 主节点按「旧版本从节点」占位展示，首个同步周期后自愈。
		SectionHashes: readAppliedSectionHashes(s.db),
		Health: models.ClusterHealth{
			CaddyOK:          caddyErr == nil,
			RulesCount:       rulesCount,
			CertsExpiring30d: expiringCount,
			UptimeSec:        int64(time.Since(clusterProcessStartedAt).Seconds()),
			SyncErrorCode:    syncErrorCode,
		},
	}
	// v2.3.0(2026-09-18 用户裁定):规则库版本随上报上送——主节点集群管理
	// 节点列表状态列 hover 可见从节点 CRS/IP2Region 版本(从节点跟随主节点
	// 同步,无需登录从节点查看)。
	// CL39-B1-2(D2):上报为每同步周期的热路径,只消费两个版本串——改走轻量
	// 版本读取(两个小文件),不再经 BuildWafFileRef 的 tarGzDirSum 全树哈希
	// 与 xdb sha256(那是快照/漂移检测的口径,上报无需)。
	report.Health.CRSVersion, report.Health.IP2RegionTag = reportWafFileVersions()
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("编码节点上报: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(masterURL, "/")+"/api/v1/cluster/nodes/report", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("创建节点上报请求: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cluster-Token", token)
	resp, err := s.do(req)
	if err != nil {
		// 审计节流：主节点持续宕机时上报每个同步周期都失败，同一错误只记录
		// 一次；错误内容变化或上报恢复后再次失败时重记，避免按分钟刷审计日志。
		s.reportAuditMu.Lock()
		auditChanged := s.lastReportFailureMsg != err.Error()
		s.lastReportFailureMsg = err.Error()
		s.reportAuditMu.Unlock()
		if auditChanged {
			RecordAuditLog("system", "上报失败", "集群节点", err.Error(), "")
		}
		return fmt.Errorf("上报主节点失败: %w", err)
	}
	defer resp.Body.Close()
	// CL39-B1-1(D1):同主机 http→https 升级已被 doWithTLSUpgradeRedirect 按
	// 原方法重放,残留 3xx(跨主机重定向/302/307 等)说明主节点地址形态需
	// 人工修正——此前落进「非 4xx 即成功」被静默吞掉;给与 Pull 3xx 分支同款
	// 可行动指引,经 reportErr→recordSyncError 通道落库(last_sync_error
	// 显「状态上报失败: …」),审计节流与拒绝分支同口径。
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		message := fmt.Sprintf("主节点返回 %d 重定向(%s)——主节点启用 HTTPS 后请将主节点地址改为 https:// 并重新注册", resp.StatusCode, resp.Header.Get("Location"))
		s.reportAuditMu.Lock()
		auditChanged := s.lastReportFailureMsg != message
		s.lastReportFailureMsg = message
		s.reportAuditMu.Unlock()
		if auditChanged {
			RecordAuditLog("system", "上报失败", "集群节点", message, "")
		}
		return errors.New(message)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		// 与传输失败相同的审计节流：主节点持续拒绝上报时同一错误只记录
		// 一次；错误内容变化或上报恢复后再次失败时重记。
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		// LimitReader 按字节截断可能切断多字节 UTF-8 字符尾部；回退到合法边界，
		// 避免审计消息尾部出现乱码。
		body = truncateValidUTF8Tail(body)
		message := fmt.Sprintf("主节点拒绝状态上报: %d", resp.StatusCode)
		if detail := strings.TrimSpace(string(body)); detail != "" {
			message += " body=" + detail
		}
		s.reportAuditMu.Lock()
		auditChanged := s.lastReportFailureMsg != message
		s.lastReportFailureMsg = message
		s.reportAuditMu.Unlock()
		if auditChanged {
			RecordAuditLog("system", "上报失败", "集群节点", message, "")
		}
		return errors.New(message)
	}
	s.reportAuditMu.Lock()
	s.lastReportFailureMsg = ""
	s.reportAuditMu.Unlock()
	return nil
}

// truncateValidUTF8Tail 将字节截断尾部退回到最后一个合法 UTF-8 字符边界，
// 消除 LimitReader 按字节截断导致的多字节字符残片乱码。
func truncateValidUTF8Tail(data []byte) []byte {
	for len(data) > 0 && !utf8.Valid(data) {
		data = data[:len(data)-1]
	}
	return data
}

// reportWafFileVersions 是 BuildWafFileRef 的轻量版本读取:只读
// crsLiveDir/VERSION 与 ip2regionLivePath+".version" 两个小文件取版本串,
// 不做 tarGzDirSum 全树哈希与 xdb sha256(Report 每同步周期调用,重哈希是
// 无谓的 IO/CPU 放大)。语义边界与 BuildWafFileRef 对齐:
//   - 文件缺失 = 空串(版本串 TrimSpace 口径、tag 经 sanitizeBundleVersion
//     形状校验,与 BuildWafFileRef 完全一致);
//   - seen 语义(rules 目录与 xdb 均缺失 = 视为「无安全数据」,两版本串保持
//     空串)以 os.Stat 等价复刻——BuildWafFileRef 的 seen 由哈希成功置位,
//     哈希 IO 异常失败时其整体返回 nil(不上报版本);本 helper 在该边缘仍
//     上报已读到的版本串,展示面(hover 空态一致性)在可读文件形态下不变。
func reportWafFileVersions() (crsVersion, ip2regionTag string) {
	if _, err := os.Stat(filepath.Join(crsLiveDir, "rules")); err != nil {
		if _, xdbErr := os.Stat(ip2regionLivePath); xdbErr != nil {
			return "", ""
		}
	}
	if v, err := os.ReadFile(filepath.Join(crsLiveDir, "VERSION")); err == nil {
		crsVersion = strings.TrimSpace(string(v))
	}
	if v, err := os.ReadFile(ip2regionLivePath + ".version"); err == nil {
		ip2regionTag = sanitizeBundleVersion(strings.TrimSpace(string(v)))
	}
	return crsVersion, ip2regionTag
}

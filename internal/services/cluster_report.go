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
	"strings"
	"time"

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
		expiryDays = 30
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_jobs WHERE status='issued' AND expires_at IS NOT NULL AND datetime(expires_at)<=datetime('now','+`+fmt.Sprintf("%d", expiryDays)+` days')`).Scan(&expiringCount); err != nil {
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
		Health: models.ClusterHealth{
			CaddyOK:          caddyErr == nil,
			RulesCount:       rulesCount,
			CertsExpiring30d: expiringCount,
			UptimeSec:        int64(time.Since(clusterProcessStartedAt).Seconds()),
			SyncErrorCode:    syncErrorCode,
		},
	}
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
	if resp.StatusCode >= http.StatusBadRequest {
		// 与传输失败相同的审计节流：主节点持续拒绝上报时同一错误只记录
		// 一次；错误内容变化或上报恢复后再次失败时重记。
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
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

package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"lazy-balancer-v2/internal/models"
)

var clusterProcessStartedAt = time.Now()

func (s *SyncService) Report(ctx context.Context) error {
	var masterURL, token, lastSyncError string
	var appliedVersion int
	var lastSync sql.NullTime
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(master_url,''), COALESCE(cluster_token,''), COALESCE(applied_version,0), last_sync, COALESCE(last_sync_error,'') FROM global_config WHERE id=1`).Scan(&masterURL, &token, &appliedVersion, &lastSync, &lastSyncError); err != nil {
		return fmt.Errorf("读取上报状态: %w", err)
	}
	lastSyncAt := ""
	if lastSync.Valid {
		lastSyncAt = lastSync.Time.UTC().Format(time.RFC3339)
	}
	var rulesCount, expiringCount int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM lb_rules").Scan(&rulesCount); err != nil {
		return fmt.Errorf("统计规则: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_jobs WHERE status='issued' AND expires_at IS NOT NULL AND datetime(expires_at)<=datetime('now','+30 days')`).Scan(&expiringCount); err != nil {
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
		Health: models.ClusterHealth{
			CaddyOK:          caddyErr == nil,
			RulesCount:       rulesCount,
			CertsExpiring30d: expiringCount,
			UptimeSec:        int64(time.Since(clusterProcessStartedAt).Seconds()),
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
		RecordAuditLog("system", "上报失败", "集群节点", err.Error(), "")
		return fmt.Errorf("上报主节点失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("主节点拒绝状态上报: %d", resp.StatusCode)
	}
	return nil
}
